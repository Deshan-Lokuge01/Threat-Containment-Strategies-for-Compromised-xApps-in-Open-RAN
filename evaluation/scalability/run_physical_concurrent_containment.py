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
PROBE_POD = "ztx-scalability-probe-20260807"
XAPPS = [
    "telemetry-monitor",
    "qos-optimizer",
    "traffic-analyzer",
    "resource-optimizer",
    "security-observer",
]
LEVELS = (1, 3, 5)
REPETITIONS = 3
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
RESULT_ROOT = Path("experiments/scalability/results/physical-20260807T094544Z")
JSONL = RESULT_ROOT / "final_concurrent_trials.jsonl"
SUMMARY = RESULT_ROOT / "final_concurrent_summary.json"
MANIFEST = RESULT_ROOT / "final_concurrent_manifest.json"
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


def workload_snapshot(xapp: str) -> dict:
    result = kubectl(
        "-n", NAMESPACE, "get", "pod", "-l", f"app={xapp}",
        "-o", "json", timeout=20,
    )
    pods = json.loads(result.stdout).get("items", [])
    ready = []
    for pod in pods:
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if pod.get("status", {}).get("phase") == "Running" and statuses and all(
            item.get("ready") for item in statuses
        ):
            ready.append(pod)
    if len(ready) != 1:
        raise RuntimeError(f"{xapp}: expected one Ready pod, found {len(ready)}")
    pod = ready[0]
    return {
        "xapp": xapp,
        "pod": pod["metadata"]["name"],
        "uid": pod["metadata"]["uid"],
        "ip": pod["status"].get("podIP"),
        "container": xapp,
    }


def reachable(xapp: str) -> bool:
    result = kubectl(
        "-n", NAMESPACE, "exec", PROBE_POD, "--", "nc", "-z", "-w", "2",
        xapp, "8080", timeout=8, check=False,
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


def controlled_reset(targets: list[str], old_ips: list[str]) -> dict:
    """Return the cluster to a clean state after (never during) measurement.

    Forwarding is paused so an already-emitted alert cannot race restoration.
    The evaluator is restarted only after all restore responses complete,
    clearing per-trial in-memory state before the next independent replicate.
    This is experimental reset procedure, not a production recovery claim.
    """
    steps = []
    pause = kubectl(
        "-n", "falco", "scale", "deployment/falco-falcosidekick",
        "--replicas=0", timeout=30, check=False,
    )
    steps.append({"step": "pause_forwarder", "returncode": pause.returncode})

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets)) as pool:
        restore_results = list(pool.map(restore, targets))

    cleanup = remove_trial_ip_rules(old_ips)
    restart = kubectl(
        "-n", SYSTEM_NAMESPACE, "rollout", "restart",
        "deployment/zt-xguard-policy-engine", timeout=30, check=False,
    )
    ready = kubectl(
        "-n", SYSTEM_NAMESPACE, "rollout", "status",
        "deployment/zt-xguard-policy-engine", "--timeout=180s",
        timeout=200, check=False,
    )
    steps.extend([
        {"step": "restart_evaluator", "returncode": restart.returncode},
        {"step": "evaluator_ready", "returncode": ready.returncode,
         "stderr": ready.stderr[-500:]},
    ])

    resume = kubectl(
        "-n", "falco", "scale", "deployment/falco-falcosidekick",
        "--replicas=1", timeout=30, check=False,
    )
    forwarder_ready = kubectl(
        "-n", "falco", "rollout", "status",
        "deployment/falco-falcosidekick", "--timeout=120s",
        timeout=140, check=False,
    )
    steps.extend([
        {"step": "resume_forwarder", "returncode": resume.returncode},
        {"step": "forwarder_ready", "returncode": forwarder_ready.returncode,
         "stderr": forwarder_ready.stderr[-500:]},
    ])
    return {"steps": steps, "restore": restore_results, "trial_ip_cleanup": cleanup}


def run_cell(k: int, repetition: int) -> dict:
    rotation = repetition % len(XAPPS)
    ordered = XAPPS[rotation:] + XAPPS[:rotation]
    targets = ordered[:k]
    snapshots = {name: workload_snapshot(name) for name in targets}
    baseline = {name: reachable(name) for name in targets}
    if not all(baseline.values()):
        raise RuntimeError(f"unreachable baseline in K={k} rep={repetition}: {baseline}")

    falco_before = falco_metrics()
    pre_rules = packet_filter_rules()
    barrier = __import__("threading").Barrier(k)
    with concurrent.futures.ThreadPoolExecutor(max_workers=k) as pool:
        futures = [pool.submit(attack, snapshots[name], barrier) for name in targets]
        attacks = {item["xapp"]: item for item in (f.result() for f in futures)}

    observed = {
        name: {key: None for key in (
            "quarantine_label", "identity_disabled", "service_isolated",
            "endpoints_empty", "contained_verified", "direct_packet_filter",
        )}
        for name in targets
    }
    deadline = time.monotonic() + TIMEOUT_SECONDS
    errors = []
    while time.monotonic() < deadline:
        for name in targets:
            try:
                flags = mechanism_flags(verification(name))
                now_ns = time.time_ns()
                for key, active in flags.items():
                    if active and observed[name][key] is None:
                        observed[name][key] = now_ns
            except Exception as error:
                errors.append({"time": utc_now(), "xapp": name, "error": repr(error)})
        api_keys = (
            "quarantine_label", "identity_disabled", "service_isolated",
            "endpoints_empty", "contained_verified",
        )
        if all(all(observed[name][key] is not None for key in api_keys) for name in targets):
            break
        time.sleep(POLL_SECONDS)

    # Node-level inspection uses kubectl exec and is therefore sampled in a
    # separate loop; it must not reduce the 200 ms API-state observation
    # cadence above.
    while time.monotonic() < deadline:
        rules = packet_filter_rules()
        now_ns = time.time_ns()
        for name in targets:
            ip = snapshots[name]["ip"]
            if (
                f"-s {ip}/32 -j DROP" in rules
                and f"-d {ip}/32 -j DROP" in rules
                and observed[name]["direct_packet_filter"] is None
            ):
                observed[name]["direct_packet_filter"] = now_ns
        if all(observed[name]["direct_packet_filter"] is not None for name in targets):
            break
        time.sleep(POLL_SECONDS)

    post_rules = packet_filter_rules()
    def observe_probe(name: str) -> tuple[str, dict]:
        checked_ns = time.time_ns()
        return name, {
            "unreachable": not reachable(name),
            "checked_ns": checked_ns,
        }
    with concurrent.futures.ThreadPoolExecutor(max_workers=k) as pool:
        active_probe = dict(pool.map(observe_probe, targets))
    falco_after = falco_metrics()
    rows = []
    for name in targets:
        issued_ns = attacks[name]["issued_ns"]
        latencies = {
            key + "_ms": (
                round((timestamp - issued_ns) / 1_000_000, 3)
                if timestamp is not None else None
            )
            for key, timestamp in observed[name].items()
        }
        ip = snapshots[name]["ip"]
        direct_block = (
            f"-s {ip}/32 -j DROP" in post_rules
            and f"-d {ip}/32 -j DROP" in post_rules
        )
        passed = all(value is not None for value in observed[name].values()) and (
            direct_block and active_probe[name]["unreachable"]
            and attacks[name]["exec_returncode"] == 0
        )
        rows.append({
            **snapshots[name], **attacks[name], **latencies,
            "direct_packet_filter_blocked": direct_block,
            "active_probe_unreachable": active_probe[name]["unreachable"],
            "network_unreachable_ms": round(
                (active_probe[name]["checked_ns"] - issued_ns) / 1_000_000, 3
            ),
            "passed": passed,
        })

    issued = [attacks[name]["issued_mono_ns"] for name in targets]
    # Falco/Falcosidekick delivery and responder writes are asynchronous.
    # Every lock is already observed above; this fixed quiet period prevents
    # restoration from racing a late copy of the same alert.
    time.sleep(POST_ENFORCEMENT_SETTLE_SECONDS)
    reset = controlled_reset(targets, [snapshots[name]["ip"] for name in targets])

    time.sleep(POST_ENFORCEMENT_SETTLE_SECONDS)
    restored = {}
    for name in targets:
        try:
            fresh = workload_snapshot(name)
            restored[name] = {
                "fresh_pod": fresh,
                "service_reachable": reachable(name),
                "contained": verification(name).get("contained"),
            }
        except Exception as error:
            restored[name] = {"error": repr(error)}

    return {
        "schema": "zt-xguard-physical-concurrency-v1",
        "k": k,
        "repetition": repetition + 1,
        "targets": targets,
        "started_utc": min(attacks[name]["issued_utc"] for name in targets),
        "launch_skew_ms": round((max(issued) - min(issued)) / 1_000_000, 3),
        "poll_interval_ms": int(POLL_SECONDS * 1000),
        "timeout_seconds": TIMEOUT_SECONDS,
        "baseline_reachable": baseline,
        "results": rows,
        "successes": sum(row["passed"] for row in rows),
        "all_passed": all(row["passed"] for row in rows),
        "poll_errors": errors,
        "falco_metrics_before": falco_before,
        "falco_metrics_after": falco_after,
        "pre_packet_filter_rules": pre_rules,
        "post_packet_filter_rules": post_rules,
        "experimental_reset": reset,
        "restored_validation": restored,
        "completed_utc": utc_now(),
    }


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * quantile
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def write_summary(cells: list[dict]) -> dict:
    output = {"schema": "zt-xguard-physical-concurrency-summary-v1", "levels": {}}
    for k in LEVELS:
        selected = [cell for cell in cells if cell["k"] == k]
        rows = [row for cell in selected for row in cell["results"]]
        level = {
            "cells": len(selected),
            "attempts": len(rows),
            "successes": sum(row["passed"] for row in rows),
            "success_rate": sum(row["passed"] for row in rows) / len(rows),
            "max_launch_skew_ms": max(cell["launch_skew_ms"] for cell in selected),
        }
        for field in (
            "quarantine_label_ms", "identity_disabled_ms", "service_isolated_ms",
            "endpoints_empty_ms", "contained_verified_ms",
            "direct_packet_filter_ms", "network_unreachable_ms",
        ):
            values = [row[field] for row in rows if row[field] is not None]
            level[field] = {
                "n": len(values),
                "mean": round(statistics.fmean(values), 3) if values else None,
                "median": round(statistics.median(values), 3) if values else None,
                "p95": round(percentile(values, 0.95), 3) if values else None,
                "max": round(max(values), 3) if values else None,
            }
        output["levels"][str(k)] = level
    output["total_attempts"] = sum(v["attempts"] for v in output["levels"].values())
    output["total_successes"] = sum(v["successes"] for v in output["levels"].values())
    output["generated_utc"] = utc_now()
    SUMMARY.write_text(json.dumps(output, indent=2) + "\n")
    return output


def main() -> int:
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)
    cells = []
    if JSONL.exists():
        cells = [json.loads(line) for line in JSONL.read_text().splitlines() if line.strip()]
    completed = {(cell["k"], cell["repetition"]) for cell in cells}
    MANIFEST.write_text(json.dumps({
        "design": {"levels": LEVELS, "repetitions": REPETITIONS},
        "workloads": XAPPS,
        "attack": "real /bin/sh syscall via kubectl exec; Falco path, not synthetic API",
        "latency_origin": "client timestamp immediately before kubectl exec",
        "observation": "200 ms polling plus independent TCP and iptables checks",
        "active_probe_execution": "one concurrent TCP connect attempt per target",
        "post_enforcement_settle_seconds": POST_ENFORCEMENT_SETTLE_SECONDS,
        "between_cell_reset": (
            "Falcosidekick paused; target pods restored/recreated; evaluator "
            "restarted to clear per-trial memory; forwarding resumed. Reset is "
            "strictly outside every measured interval."
        ),
        "claim_boundary": (
            "Dummy xApps exercise real Kubernetes/Falco/evaluator/responder workflows "
            "but do not claim E2 control-loop traffic equivalence."
        ),
        "created_utc": utc_now(),
    }, indent=2) + "\n")

    for k in LEVELS:
        for repetition in range(REPETITIONS):
            key = (k, repetition + 1)
            if key in completed:
                print(f"skip completed K={k} repetition={repetition + 1}", flush=True)
                continue
            print(f"run K={k} repetition={repetition + 1}", flush=True)
            cell = run_cell(k, repetition)
            with JSONL.open("a") as output:
                output.write(json.dumps(cell, sort_keys=True) + "\n")
            cells.append(cell)
            print(
                f"  successes={cell['successes']}/{k} "
                f"launch_skew_ms={cell['launch_skew_ms']}", flush=True,
            )

    summary = write_summary(cells)
    print(json.dumps(summary, indent=2), flush=True)
    return 0 if summary["total_attempts"] == summary["total_successes"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
