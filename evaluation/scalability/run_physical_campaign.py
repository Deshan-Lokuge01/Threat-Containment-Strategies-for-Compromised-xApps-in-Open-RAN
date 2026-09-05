#!/usr/bin/env python3
"""Physical concurrent-containment scalability experiment for ZT-XGuard.

This is an end-to-end test.  It launches a real ``/bin/sh`` process in each
selected xApp container; Falco observes the resulting syscall and forwards it
through Falcosidekick to the deployed evaluator.  The script never calls a
synthetic signal-ingestion endpoint.  It then observes the real responder
effects through the deployed containment-verification API and independently
checks Service reachability and the node packet-filter chain.

The fixed design is K={1,3,5}, three repetitions per K.  Targets rotate by
repetition so that low-K cells are not tied to one workload.  Every attempted
attack is retained, including failures.  Latency is measured from the client
timestamp immediately before each kubectl exec request; this conservatively
includes exec setup time as well as Falco, webhook, evaluation and response.
"""
from __future__ import annotations

import concurrent.futures
import json
import math
import statistics
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


NAMESPACE = "ricxapp"
SYSTEM_NAMESPACE = "zt-xguard"
PROBE_POD = "ztx-scalability-probe-real"
# The four real O-RAN SC xApps deployed in the testbed.  The deployed responder
# API and the pod `app=` label both use the ricxapp-prefixed name; the exec
# container name is the short suffix (e.g. ricxapp-hw-go -> hw-go).
XAPPS = [
    "ricxapp-hw-go",
    "ricxapp-hw-python",
    "ricxapp-kpimon-go",
    "ricxapp-trafficxapp",
]
LEVELS = (1, 2, 3, 4)
VALID_TRIALS_PER_K = 10
SCHEDULE_SEED = 20260808
MAX_PRECONDITION_RETRIES = 3
# Reachability is probed against the pod IP on the RMR port, which every xApp
# listens on, because the real xApp Service objects have inconsistent HTTP
# endpoints (hw-go/trafficxapp expose no HTTP endpoint).  Probing the pod IP
# directly tests the network-layer locks (NetworkPolicy + node packet filter).
RMR_PORT = "4560"
POLL_SECONDS = 0.20
TIMEOUT_SECONDS = 30.0
POST_ENFORCEMENT_SETTLE_SECONDS = 3.0
RESTORE_TIMEOUT_SECONDS = 120.0
API_PROXY = "http://127.0.0.1:18081"
POLICY_BASE = (
    API_PROXY
    + "/api/v1/namespaces/zt-xguard/services/"
      "http:zt-xguard-policy-engine:5000/proxy"
)
import os
RESULT_ROOT = Path(os.environ["ZTX_EXP3_OUT"])
JSONL = RESULT_ROOT / "concurrent_containment_trials.jsonl"
SCHEDULE_CSV = RESULT_ROOT / "trial_schedule.csv"
STATE_URL = POLICY_BASE + "/csm/state"
CANAL_POD = "canal-4ldk7"
CHAIN = "ZTX-DIRECT-QUARANTINE"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def request_json(path: str, body: dict | None = None, timeout: float = 10.0):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        POLICY_BASE + path,
        data=data,
        method="GET" if body is None else "POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def kubectl(*args: str, timeout: float = 30.0, check: bool = True):
    return subprocess.run(
        ["kubectl", *args], capture_output=True, text=True,
        timeout=timeout, check=check,
    )


def workload_snapshot(xapp: str, ready_wait_s: float = 45.0) -> dict:
    # Wait (bounded) for exactly one Ready pod: after a containment+restore the
    # target pod can be transiently 0-Ready while its renew-svid sidecar
    # recovers or the pod is recreated.
    deadline = time.monotonic() + ready_wait_s
    ready: list = []
    while True:
        result = kubectl(
            "-n", NAMESPACE, "get", "pod", "-l", f"app={xapp}",
            "-o", "json", timeout=20, check=False,
        )
        pods = json.loads(result.stdout or "{}").get("items", []) if result.stdout else []
        app_container = xapp.replace("ricxapp-", "", 1)
        ready = []
        for pod in pods:
            statuses = pod.get("status", {}).get("containerStatuses", [])
            # Require the APPLICATION container ready; the renew-svid sidecar can
            # transiently crashloop during identity withdrawal/restore churn and
            # must not block a target whose app is up, reachable and containable.
            app_ready = any(s.get("name") == app_container and s.get("ready") for s in statuses)
            if pod.get("status", {}).get("phase") == "Running" and app_ready:
                ready.append(pod)
        if len(ready) == 1 or time.monotonic() >= deadline:
            break
        time.sleep(2)
    if len(ready) != 1:
        raise RuntimeError(f"{xapp}: expected one Ready pod, found {len(ready)}")
    pod = ready[0]
    return {
        "xapp": xapp,
        "pod": pod["metadata"]["name"],
        "uid": pod["metadata"]["uid"],
        "ip": pod["status"].get("podIP"),
        # Real xApp pods run the application container plus a renew-svid
        # sidecar; the application container name is the short suffix.
        "container": xapp.replace("ricxapp-", "", 1),
    }


def reachable(ip: str) -> bool:
    if not ip:
        return False
    result = kubectl(
        "-n", NAMESPACE, "exec", PROBE_POD, "--", "nc", "-z", "-w", "2",
        ip, RMR_PORT, timeout=8, check=False,
    )
    return result.returncode == 0


def falco_metrics() -> dict:
    """Read Falco's own Prometheus gauges/counters from the live pod."""
    result = {
        "cpu_usage_ratio": None,
        "memory_rss_bytes": None,
        "outputs_queue_drops_total": None,
    }
    try:
        pod = kubectl(
            "-n", "falco", "get", "pod", "-l", "app.kubernetes.io/name=falco",
            "-o", "json", timeout=20,
        )
        items = json.loads(pod.stdout).get("items", [])
        ip = items[0]["status"]["podIP"]
        with urllib.request.urlopen(f"http://{ip}:8765/metrics", timeout=8) as response:
            text = response.read().decode()
        names = {
            "falcosecurity_falco_cpu_usage_ratio": "cpu_usage_ratio",
            "falcosecurity_falco_memory_rss_bytes": "memory_rss_bytes",
            "falcosecurity_falco_outputs_queue_num_drops_total": "outputs_queue_drops_total",
        }
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] in names:
                result[names[parts[0]]] = float(parts[1])
    except Exception as error:
        result["error"] = repr(error)
    result["sampled_utc"] = utc_now()
    return result


def verification(xapp: str) -> dict:
    return request_json(
        "/csm/containment/verify",
        {"xapp": xapp, "namespace": NAMESPACE}, timeout=10,
    )


def mechanism_flags(payload: dict) -> dict:
    pods = payload.get("pods") or []
    services = payload.get("services") or []
    labels = (pods[0].get("labels") or {}) if pods else {}
    return {
        "quarantine_label": labels.get("zt-xguard.io/quarantine") == "true",
        "identity_disabled": labels.get("zt-xguard.io/svid-enabled") == "false",
        "service_isolated": bool(services) and all(
            service.get("service_isolated") for service in services
        ),
        "endpoints_empty": bool(services) and all(
            (service.get("endpoint_summary") or {}).get("endpoint_count") == 0
            for service in services
        ),
        "contained_verified": payload.get("contained") is True,
    }


def packet_filter_rules() -> str:
    result = kubectl(
        "-n", "kube-system", "exec", CANAL_POD, "-c", "calico-node", "--",
        "iptables", "-t", "raw", "-S", CHAIN, timeout=15, check=False,
    )
    return result.stdout or ""


def attack(snapshot: dict, barrier) -> dict:
    barrier.wait()
    started_ns = time.time_ns()
    started_mono = time.perf_counter_ns()
    result = kubectl(
        "-n", NAMESPACE, "exec", snapshot["pod"], "-c", snapshot["container"],
        "--", "/bin/sh", "-c", ":", timeout=20, check=False,
    )
    return {
        "xapp": snapshot["xapp"],
        "issued_ns": started_ns,
        "issued_utc": datetime.fromtimestamp(
            started_ns / 1_000_000_000, timezone.utc
        ).isoformat(),
        "issued_mono_ns": started_mono,
        "exec_returncode": result.returncode,
        "exec_stdout": result.stdout[-500:],
        "exec_stderr": result.stderr[-500:],
    }


def restore(xapp: str) -> dict:
    started = time.perf_counter()
    try:
        response = request_json(
            "/csm/containment/restore",
            {"xapp": xapp, "namespace": NAMESPACE},
            timeout=RESTORE_TIMEOUT_SECONDS,
        )
        return {
            "xapp": xapp,
            "elapsed_s": round(time.perf_counter() - started, 3),
            "response": response,
        }
    except Exception as error:
        return {
            "xapp": xapp,
            "elapsed_s": round(time.perf_counter() - started, 3),
            "error": repr(error),
        }


def remove_trial_ip_rules(ips: list[str]) -> list[dict]:
    actions = []
    for ip in sorted(set(filter(None, ips))):
        for flag in ("-s", "-d"):
            result = kubectl(
                "-n", "kube-system", "exec", CANAL_POD, "-c", "calico-node",
                "--", "iptables", "-t", "raw", "-D", CHAIN, flag, ip,
                "-j", "DROP", timeout=15, check=False,
            )
            actions.append({
                "ip": ip, "direction_flag": flag,
                "returncode": result.returncode,
                "stderr": result.stderr[-300:],
            })
    return actions


# ---------------------------------------------------------------------------
# Experiment 3 (accelerated, round-based). Mandatory engine restart per trial
# with CONDITION-BASED readiness; 5 rounds x K{1,2,3,4} = 20 valid trials, 6th
# round only if wall-clock allows. tP from /csm/state (no app.py change).
# ---------------------------------------------------------------------------
import csv
import itertools
import random
import threading

LOCK_KEYS = ("quarantine_label", "identity_disabled", "service_isolated",
             "endpoints_empty", "contained_verified")
POST_READY_STABILIZE = 10.0
LAUNCH_SKEW_MAX_MS = 500.0
TIME_BOX_SECONDS = 75 * 60
MANDATORY_ROUNDS = 5
MAX_ROUNDS = 6
READY_POLL_DEADLINE = 200.0


def short_name(x): return x.replace("ricxapp-", "", 1)
def services_of(x): return [f"service-{x}-http", f"service-{x}-rmr"]


def clean_locks(xapp):
    kubectl("-n", NAMESPACE, "label", "pod", "-l", f"app={xapp}",
            "zt-xguard.io/quarantine-", "--overwrite", check=False)
    kubectl("-n", NAMESPACE, "label", "pod", "-l", f"app={xapp}",
            "zt-xguard.io/svid-enabled=true", "--overwrite", check=False)
    for svc in services_of(xapp):
        kubectl("-n", NAMESPACE, "patch", "svc", svc, "--type=merge", "-p",
                '{"spec":{"selector":{"zt-xguard.io/service-isolated":null}}}', check=False)


def flush_chain():
    kubectl("-n", "kube-system", "exec", CANAL_POD, "-c", "calico-node", "--",
            "iptables", "-t", "raw", "-F", CHAIN, timeout=15, check=False)


def pod_ip(xapp):
    r = kubectl("-n", NAMESPACE, "get", "pod", "-l", f"app={xapp}",
                "-o", "jsonpath={.items[0].status.podIP}", timeout=15, check=False)
    return (r.stdout or "").strip()


def all_reachable():
    """Lightweight per-xApp app-container reachability (pod IP:RMR)."""
    out = {}
    for n in XAPPS:
        ip = pod_ip(n)
        out[n] = reachable(ip) if ip else False
    return out


def pod_ready(xapp):
    try:
        r = kubectl("-n", NAMESPACE, "get", "pod", "-l", f"app={xapp}",
                    "-o", "jsonpath={.items[0].status.containerStatuses[*].ready}",
                    timeout=15, check=False)
        return r.stdout.strip() and all(t == "true" for t in r.stdout.split())
    except Exception:
        return False


def state_map():
    out = {}
    try:
        for e in (request_json("/csm/state").get("xapps") or []):
            out[str(e.get("xapp"))] = (str(e.get("state") or "").upper(), e.get("last_update"))
    except Exception:
        pass
    return out


def precondition_check():
    detail = {"reachable": {}, "contained": {}, "compromised_state": {}}
    try:
        snaps = {n: workload_snapshot(n) for n in XAPPS}
    except Exception as e:
        return False, {"snapshot_error": repr(e)}, {}
    for n in XAPPS:
        detail["reachable"][n] = reachable(snaps[n]["ip"])
    sm = state_map()
    for n in XAPPS:
        st = (sm.get(n) or sm.get(short_name(n)) or ("", None))[0]
        detail["compromised_state"][n] = st in ("COMPROMISED", "ISOLATED")
        try:
            detail["contained"][n] = bool(verification(n).get("contained"))
        except Exception as e:
            return False, {**detail, "responder_error": repr(e)}, snaps
    ok = (all(detail["reachable"].values())
          and not any(detail["contained"].values())
          and not any(detail["compromised_state"].values()))
    return ok, detail, snaps


def reset_and_ready(trial_id):
    """Mandatory restart + condition-based readiness + fixed 10 s stabilize."""
    t0 = time.time()
    def hb(msg):
        print(f"[Exp3] trial={trial_id} | RESET | {msg} | elapsed={int(time.time()-t0)}s", flush=True)
    # SIMPLIFIED RESET (ZTX-A1_CONFIG_FROZEN=PASS): the hw-go/hw-python PID-1
    # `sh -c` startup entrypoints are now exempted from ZTX-A1, so recreating a
    # pod no longer self-contains it. Falco AND Falcosidekick stay fully ENABLED
    # throughout every measured trial. Reset = restart evaluator (clear CSM
    # state) -> clean locks -> recreate only unhealthy pods -> wait baseline
    # health -> verify no COMPROMISED/ISOLATED -> fixed 10 s stabilize -> attack.
    hb("restart evaluator (clear CSM_STATE); Falco/Falcosidekick stay enabled")
    kubectl("-n", SYSTEM_NAMESPACE, "rollout", "restart",
            "deployment/zt-xguard-policy-engine", check=False)
    kubectl("-n", SYSTEM_NAMESPACE, "rollout", "status",
            "deployment/zt-xguard-policy-engine", "--timeout=180s", timeout=200, check=False)
    for n in XAPPS:
        clean_locks(n)
    flush_chain()
    hb("recreate only unhealthy pods (startup shells now exempted)")
    recreated = set()
    deadline = time.time() + READY_POLL_DEADLINE
    last_hb = 0
    ready = False
    reach = {}
    while time.time() < deadline:
        reach = all_reachable()
        if all(reach.values()):
            ready = True
            break
        for n, r in reach.items():
            if not r and n not in recreated:
                kubectl("-n", NAMESPACE, "delete", "pod", "-l", f"app={n}",
                        "--wait=false", check=False)
                recreated.add(n)
        if time.time() - last_hb >= 30:
            hb(f"waiting app-ready reach={reach}")
            last_hb = time.time()
        time.sleep(4)
    if not ready:
        return False, {"reachable": reach, "phase": "startup_wait"}
    # Verify NO COMPROMISED/ISOLATED for the fixed 10 s stabilization window.
    stable_deadline = time.time() + POST_READY_STABILIZE
    while time.time() < stable_deadline:
        sm = state_map()
        dirty = [n for n in XAPPS
                 if (sm.get(n) or sm.get(short_name(n)) or ("", None))[0] in ("COMPROMISED", "ISOLATED")]
        if dirty:
            hb(f"unexpected COMPROMISED/ISOLATED during verify: {dirty}; reset failed")
            return False, {"verify_dirty": dirty}
        time.sleep(2)
    ok, pre, _ = precondition_check()
    if not ok:
        return False, pre
    return True, pre


def full_restart_reset():
    """Wrapper used by the trial-retry path: a full reset_and_ready cycle."""
    ok, _ = reset_and_ready(0)
    return ok


def generate_rounds(num_rounds):
    rng = random.Random(SCHEDULE_SEED)
    k1 = list(XAPPS)
    pairs = list(itertools.combinations(XAPPS, 2))
    triplets = list(itertools.combinations(XAPPS, 3))
    trials = []
    tid = 0
    for rnd in range(1, num_rounds + 1):
        ks = [1, 2, 3, 4]
        rng.shuffle(ks)
        for k in ks:
            if k == 1:
                ts = [k1[(rnd - 1) % 4]]
            elif k == 2:
                ts = list(pairs[(rnd - 1) % len(pairs)])
            elif k == 3:
                ts = list(triplets[(rnd - 1) % len(triplets)])
            else:
                ts = list(XAPPS)
            tid += 1
            trials.append({"trial_id": tid, "round": rnd, "K": k,
                           "target_set": ts, "execution_order": tid, "seed": SCHEDULE_SEED})
    return trials


def write_schedule_csv(sched):
    with SCHEDULE_CSV.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["trial_id", "round", "K", "target_set", "execution_order", "seed"])
        for t in sched:
            w.writerow([t["trial_id"], t["round"], t["K"], "|".join(t["target_set"]),
                        t["execution_order"], t["seed"]])


def run_trial(trial, snapshots):
    k = trial["K"]
    targets = trial["target_set"]
    nontargets = [x for x in XAPPS if x not in targets]
    baseline = {n: reachable(snapshots[n]["ip"]) for n in XAPPS}
    falco_before = falco_metrics()
    barrier = threading.Barrier(k)
    with concurrent.futures.ThreadPoolExecutor(max_workers=k) as pool:
        futs = [pool.submit(attack, snapshots[n], barrier) for n in targets]
        attacks = {a["xapp"]: a for a in (f.result() for f in futs)}
    issued = [attacks[n]["issued_mono_ns"] for n in targets]
    launch_skew_ms = round((max(issued) - min(issued)) / 1e6, 3)
    t0_group = min(attacks[n]["issued_ns"] for n in targets)

    observed = {n: {key: None for key in LOCK_KEYS + ("direct_packet_filter",)} for n in targets}
    tP_obs = {n: None for n in targets}
    tP_srv = {n: None for n in targets}
    deadline = time.monotonic() + TIMEOUT_SECONDS
    errors = []
    while time.monotonic() < deadline:
        sm = state_map()
        now = time.time_ns()
        for n in targets:
            st, lu = (sm.get(n) or sm.get(short_name(n)) or ("", None))
            # Only a directly-observed COMPROMISED decision counts as tP.
            # ISOLATED is the post-containment state, NOT the decision timestamp,
            # so it must never be used as detection latency (kept secondary; if
            # COMPROMISED is never observed the target's tP stays None -> missing).
            if tP_obs[n] is None and st == "COMPROMISED":
                tP_obs[n] = now
                tP_srv[n] = lu
        for n in targets:
            try:
                fl = mechanism_flags(verification(n))
                now = time.time_ns()
                for key, active in fl.items():
                    if active and observed[n][key] is None:
                        observed[n][key] = now
            except Exception as e:
                errors.append({"xapp": n, "error": repr(e)})
        if all(all(observed[n][key] is not None for key in LOCK_KEYS) for n in targets):
            break
        time.sleep(POLL_SECONDS)
    while time.monotonic() < deadline:
        rules = packet_filter_rules()
        now = time.time_ns()
        for n in targets:
            ip = snapshots[n]["ip"]
            if (f"-s {ip}/32 -j DROP" in rules and f"-d {ip}/32 -j DROP" in rules
                    and observed[n]["direct_packet_filter"] is None):
                observed[n]["direct_packet_filter"] = now
        if all(observed[n]["direct_packet_filter"] is not None for n in targets):
            break
        time.sleep(POLL_SECONDS)
    post_rules = packet_filter_rules()

    def probe(n):
        c = time.time_ns()
        return n, {"unreachable": not reachable(snapshots[n]["ip"]), "checked_ns": c}
    with concurrent.futures.ThreadPoolExecutor(max_workers=k) as pool:
        aprobe = dict(pool.map(probe, targets))
    nontarget_reach = {n: reachable(snapshots[n]["ip"]) for n in nontargets}
    falco_after = falco_metrics()

    rows = []
    for n in targets:
        t0i = attacks[n]["issued_ns"]
        def rel(ts): return round((ts - t0i) / 1e6, 3) if ts is not None else None
        ip = snapshots[n]["ip"]
        direct_block = (f"-s {ip}/32 -j DROP" in post_rules and f"-d {ip}/32 -j DROP" in post_rules)
        l3 = None
        if observed[n]["service_isolated"] and observed[n]["endpoints_empty"]:
            l3 = max(observed[n]["service_isolated"], observed[n]["endpoints_empty"])
        passed = (all(observed[n][key] is not None for key in LOCK_KEYS)
                  and direct_block and aprobe[n]["unreachable"]
                  and attacks[n]["exec_returncode"] == 0)
        rows.append({
            **snapshots[n], **attacks[n],
            "tP_observed_ms": rel(tP_obs[n]), "tP_server_utc": tP_srv[n],
            "tP_missing": tP_obs[n] is None,
            "tL1_identity_ms": rel(observed[n]["identity_disabled"]),
            "tL2_policy_selection_ms": rel(observed[n]["quarantine_label"]),
            "tL3_service_ms": rel(l3),
            "tL4_nodefilter_ms": rel(observed[n]["direct_packet_filter"]),
            "tU_unreachable_ms": rel(aprobe[n]["checked_ns"]),
            "direct_packet_filter_blocked": direct_block,
            "probe_unreachable": aprobe[n]["unreachable"], "passed": passed,
            "_tP_ns": tP_obs[n], "_l1": observed[n]["identity_disabled"],
            "_l2": observed[n]["quarantine_label"], "_l3": l3,
            "_l4": observed[n]["direct_packet_filter"], "_tU": aprobe[n]["checked_ns"],
        })

    def mkspan(key):
        vals = [r[key] for r in rows if r.get(key) is not None]
        return round((max(vals) - t0_group) / 1e6, 3) if len(vals) == len(targets) else None
    all_targets = all(r["passed"] for r in rows)
    all_nontargets = all(nontarget_reach.values()) if nontargets else True
    validity = "INVALID_TRIGGER_SYNC" if launch_skew_ms > LAUNCH_SKEW_MAX_MS else "VALID"
    return {
        "schema": "zt-xguard-exp3-trial-v1", "trial_id": trial["trial_id"],
        "round": trial["round"], "k": k, "target_set": targets, "nontargets": nontargets,
        "started_utc": min(attacks[n]["issued_utc"] for n in targets),
        "launch_skew_ms": launch_skew_ms, "validity": validity,
        "baseline_reachable": baseline, "results": rows,
        "nontarget_reachable": nontarget_reach, "all_nontargets_reachable": all_nontargets,
        "T_detect_all": mkspan("_tP_ns"), "T_identity_all": mkspan("_l1"),
        "T_policy_all": mkspan("_l2"), "T_service_all": mkspan("_l3"),
        "T_nodefilter_all": mkspan("_l4"), "T_all_isolated": mkspan("_tU"),
        "all_targets_contained": all_targets,
        "trial_success": bool(all_targets and all_nontargets and validity == "VALID"),
        "poll_errors": errors, "falco_metrics_before": falco_before,
        "falco_metrics_after": falco_after, "post_packet_filter_rules": post_rules,
        "completed_utc": utc_now(),
    }


def _stat(vals):
    if not vals:
        return {"n": 0, "median": None, "iqr": None, "min": None, "max": None}
    s = sorted(vals)
    def pct(q):
        i = (len(s) - 1) * q; lo = math.floor(i); hi = math.ceil(i)
        return s[lo] if lo == hi else s[lo] + (s[hi] - s[lo]) * (i - lo)
    return {"n": len(s), "median": round(statistics.median(s), 3),
            "iqr": round(pct(0.75) - pct(0.25), 3), "min": round(min(s), 3), "max": round(max(s), 3)}


def wilson(succ, n, z=1.959963984540054):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = succ / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = (z / d) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (round(p, 4), round(max(0.0, c - h), 4), round(min(1.0, c + h), 4))


def write_outputs(trials):
    valid = [t for t in trials if t["validity"] == "VALID"]
    raw = []
    for t in trials:
        for r in t["results"]:
            raw.append({"trial_id": t["trial_id"], "round": t["round"], "K": t["k"],
                        "xapp": r["xapp"], "is_target": 1, "validity": t["validity"],
                        "t0_utc": r["issued_utc"], "tP_observed_ms": r["tP_observed_ms"],
                        "tP_server_utc": r["tP_server_utc"], "tL1_identity_ms": r["tL1_identity_ms"],
                        "tL2_policy_selection_ms": r["tL2_policy_selection_ms"],
                        "tL3_service_ms": r["tL3_service_ms"], "tL4_nodefilter_ms": r["tL4_nodefilter_ms"],
                        "tU_unreachable_ms": r["tU_unreachable_ms"],
                        "lock_all_ok": int(bool(r["passed"])),
                        "probe_unreachable": int(bool(r["probe_unreachable"])),
                        "exec_rc": r["exec_returncode"]})
    if raw:
        with (RESULT_ROOT / "concurrent_containment_raw.csv").open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(raw[0].keys())); w.writeheader(); w.writerows(raw)
    trows = []
    for t in trials:
        trows.append({"trial_id": t["trial_id"], "round": t["round"], "K": t["k"],
                      "target_set": "|".join(t["target_set"]), "launch_skew_ms": t["launch_skew_ms"],
                      "T_detect_all": t["T_detect_all"], "T_identity_all": t["T_identity_all"],
                      "T_policy_all": t["T_policy_all"], "T_service_all": t["T_service_all"],
                      "T_nodefilter_all": t["T_nodefilter_all"], "T_all_isolated": t["T_all_isolated"],
                      "all_targets_contained": int(bool(t["all_targets_contained"])),
                      "all_nontargets_reachable": int(bool(t["all_nontargets_reachable"])),
                      "validity": t["validity"], "trial_success": int(bool(t["trial_success"]))})
    if trows:
        with (RESULT_ROOT / "concurrent_containment_trials.csv").open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(trows[0].keys())); w.writeheader(); w.writerows(trows)
    summ = {"schema": "zt-xguard-exp3-summary-v1", "note": "n small; report median/IQR/min/max, no p95/p99", "levels": {}}
    for k in LEVELS:
        kt = [t for t in valid if t["k"] == k]
        n = len(kt); succ = sum(1 for t in kt if t["trial_success"])
        p, lo, hi = wilson(succ, n)
        lvl = {"valid_trials": n, "successes": succ, "success_pct": round(100 * p, 1),
               "wilson95_secondary": [lo, hi]}
        for field in ("T_detect_all", "T_identity_all", "T_policy_all", "T_service_all",
                      "T_nodefilter_all", "T_all_isolated", "launch_skew_ms"):
            lvl[field] = _stat([t[field] for t in kt if t.get(field) is not None])
        summ["levels"][str(k)] = lvl
    summ["total_valid_trials"] = len(valid)
    summ["total_successes"] = sum(1 for t in valid if t["trial_success"])
    summ["invalid_trials"] = [{"trial_id": t["trial_id"], "validity": t["validity"]} for t in trials if t["validity"] != "VALID"]
    summ["generated_utc"] = utc_now()
    (RESULT_ROOT / "concurrent_containment_summary.json").write_text(json.dumps(summ, indent=2) + "\n")
    return summ


def main():
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)
    schedule = generate_rounds(MAX_ROUNDS)
    write_schedule_csv(schedule)
    trials_out = []
    done = set()
    if JSONL.exists():
        for line in JSONL.read_text().splitlines():
            if line.strip():
                t = json.loads(line); trials_out.append(t)
                if t["validity"] == "VALID":
                    done.add(t["trial_id"])
    campaign_start = time.time()
    valid_count = len([t for t in trials_out if t["validity"] == "VALID"])
    invalid_count = len([t for t in trials_out if t["validity"] != "VALID"])
    for trial in schedule:
        if trial["trial_id"] in done:
            continue
        # 6th-round gate: only if within the time box (wall-clock only)
        if trial["round"] > MANDATORY_ROUNDS:
            elapsed = time.time() - campaign_start
            if elapsed > TIME_BOX_SECONDS - 6 * 60:
                print(f"[Exp3] time-box reached ({int(elapsed)}s); skipping round {trial['round']}", flush=True)
                break
        ok, pre = reset_and_ready(trial["trial_id"])
        if not ok:
            rec = {"schema": "zt-xguard-exp3-trial-v1", "trial_id": trial["trial_id"],
                   "round": trial["round"], "k": trial["K"], "target_set": trial["target_set"],
                   "validity": "INVALID_PRECONDITION", "precondition": pre, "trial_success": False,
                   "results": [], "launch_skew_ms": None, "T_all_isolated": None,
                   "all_nontargets_reachable": None, "all_targets_contained": None,
                   "completed_utc": utc_now()}
            with JSONL.open("a") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
            trials_out.append(rec); invalid_count += 1
            print(f"[Exp3] valid={valid_count:02d}/20 | round={trial['round']} | K={trial['K']} | "
                  f"INVALID_PRECONDITION | invalid={invalid_count}", flush=True)
            continue
        result = None
        for attempt in range(2):
            try:
                snaps = {n: workload_snapshot(n) for n in XAPPS}
                result = run_trial(trial, snaps)
                break
            except Exception as exc:
                print(f"[Exp3] trial={trial['trial_id']} attempt {attempt + 1} "
                      f"transient error: {exc!r}; full reset + retry", flush=True)
                full_restart_reset()
        if result is None:
            rec = {"schema": "zt-xguard-exp3-trial-v1", "trial_id": trial["trial_id"],
                   "round": trial["round"], "k": trial["K"], "target_set": trial["target_set"],
                   "validity": "INVALID_HARNESS_ERROR", "trial_success": False, "results": [],
                   "launch_skew_ms": None, "T_all_isolated": None,
                   "all_nontargets_reachable": None, "all_targets_contained": None,
                   "completed_utc": utc_now()}
            with JSONL.open("a") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
            trials_out.append(rec); invalid_count += 1
            print(f"[Exp3] valid={valid_count:02d}/20 | round={trial['round']} | K={trial['K']} | "
                  f"INVALID_HARNESS_ERROR | invalid={invalid_count}", flush=True)
            continue
        result["precondition"] = pre
        with JSONL.open("a") as fh:
            fh.write(json.dumps(result, sort_keys=True) + "\n")
        trials_out.append(result)
        if result["validity"] == "VALID":
            valid_count += 1
            tag = "PASS" if result["trial_success"] else "FAIL"
        else:
            invalid_count += 1
            tag = result["validity"]
        print(f"[Exp3] valid={valid_count:02d}/20 | round={trial['round']} | K={trial['K']} | "
              f"targets={'|'.join(short_name(x) for x in trial['target_set'])} | {tag} | "
              f"T_all={result['T_all_isolated']}ms skew={result['launch_skew_ms']}ms | "
              f"nontargets_ok={result['all_nontargets_reachable']} | invalid={invalid_count}", flush=True)
        elapsed = time.time() - campaign_start
        if elapsed > TIME_BOX_SECONDS:
            print(f"[Exp3] TIME-BOX {int(elapsed)}s reached; stopping after trial {trial['trial_id']}", flush=True)
            break
    summ = write_outputs(trials_out)
    print(json.dumps(summ, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
