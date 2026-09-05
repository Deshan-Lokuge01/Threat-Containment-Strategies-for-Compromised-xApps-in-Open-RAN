#!/usr/bin/env python3
"""ZT-XGuard T2 resource-anomaly-detector N-trial evaluation harness.

Shared module used by the 6 per-scenario runner scripts (run_r1_trials.py,
run_a5_trials.py, run_a_burst_trials.py, run_a_stealth_trials.py,
run_r6_trials.py, run_a_memory_trials.py). Each scenario is its own
independently-runnable process (deliberately not one combined harness -
operator preference, so results/progress can be inspected between
scenarios) but they all share this measurement/recovery logic so the CSV
columns and semantics are identical across scenarios.

Attack intensities are copied unchanged from the existing demo scripts
under this same directory (r1_sustained_cpu_flood.sh etc.) - those are
themselves copied unchanged from the frozen calibration scripts. Durations
are ALSO kept unchanged from those demo scripts (not further compressed -
operator decision 2026-07-24: for a real publication, use the already-
vetted durations, not new invented/compressed ones).

Three-tier latency measurement, matching the real system design:
  1. detection: attack onset -> T2 model reaches its own fully-confirmed
     public_state=SUSPICIOUS (UCL exceedance + 6-of-8 + cpu_gate all true) -
     this is what ztx_state_engine.py maps to CSM decision_state=COMPROMISED.
     Real detection latency, not a policy parameter.
  2. immediate_containment: detection -> the T2 collector's own cgroup CPU
     throttle applied (ztx_t2_collector.py's _apply_throttle_if_needed) -
     this fires in the same tick as the COMPROMISED decision, no dwell.
     Real, sub-second-scale containment latency.
  3. full_isolation: detection -> real K8s-level network isolation
     (quarantine label + service isolation, same mechanisms Falco uses) -
     explicitly gated behind ztx_isolation_manager.DWELL_SECONDS (=30.0), a
     deliberate operator-approved policy (give a human 30s to intervene
     before auto-isolating a resource-anomaly-triggered compromise), NOT a
     mechanism-speed limit. Reported as "30s dwell + measured overhead" and
     clearly labeled as such - never conflated with real latency.

Time-series capture: polls the T2 collector's own live state file
(/var/lib/ztx-t2-state/latest.json, written every tick at 1Hz, world-
readable) throughout each trial, so exemplar score-trajectory plots (T2
score rising, attack window shaded, detection point marked) can be built
from real per-second data, not just start/end summary numbers.

Event markers (exact moment detection/throttle-apply/throttle-release
happen) are read from the collector's own structured JSON log via
`journalctl -u ztx-t2-collector.service` - reusing the collector's own
instrumentation directly rather than re-deriving timing from noisier
polling alone.
"""
from __future__ import annotations

import csv
import json
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

NS = "ricxapp"
XAPP = "ricxapp-kpimon-go"
CONTAINER = "kpimon-go"
STATE_FILE = Path("/var/lib/ztx-t2-state/latest.json")
RESULTS_DIR = Path.home() / "Desktop" / "FYP" / "zt-xguard" / "xApps_Attcks" / "evaluation"
SUMMARY_CSV = RESULTS_DIR / "kpimon_t2_trials.csv"
TIMESERIES_CSV = RESULTS_DIR / "kpimon_t2_timeseries.csv"

# 2026-07-25: added for a rigorously-instrumented network-isolation
# demonstration run (SVID/identity revocation + a real active TCP
# reachability probe + retry-verified direct-iptables confirmation +
# an extended post-isolation observation hold, none of which the
# original N=51 statistical harness captured). Same technique as the
# Falco harness (run_kpimon_latency_trials.py) uses -- a dedicated
# busybox pod, `nc -z` TCP connect attempts, ClusterIP not FQDN (CoreDNS
# was intermittently flaky for the Service FQDN specifically, confirmed
# live during the Falco N=400 collection).
PROBE_POD_NAME = "ztx-network-probe"
PROBE_POD_LABEL = f"app={PROBE_POD_NAME}"
KPIMON_SERVICE_NAME = "service-ricxapp-kpimon-go-http"
KPIMON_SERVICE_PORT = 8080
REACHABILITY_PROBE_TIMEOUT_SECONDS = 3.0
REACHABILITY_RECHECK_ATTEMPTS = 5
# How many times / how far apart to retry the direct-iptables mechanism
# check after isolation is first observed, before accepting a False as
# real. The original one-shot check read False in 41/41 T2 trials in the
# prior dataset despite the same mechanism firing reliably (400/400) in
# the Falco dataset -- root cause not conclusively identified (see
# figures_matlab/README.md's "Honest limitations" section), so this
# retries rather than assuming either a fixed timing constant or that
# the mechanism itself is broken.
MECH_RECHECK_ATTEMPTS = 6
MECH_RECHECK_INTERVAL_SECONDS = 2.0
# How long to keep sampling (both this harness's own journal-derived
# time series AND any externally-running network_rxtx_sampler_exec.sh)
# after isolation is confirmed, before starting restore -- long enough
# to show throughput settle at near-zero and stay there, not just the
# transition instant. Trimmed from 90s -> 45s (2026-07-25, operator
# request to cut added-per-trial time) -- still >>1 sample interval of
# genuinely-settled near-zero throughput, which is all the figure needs;
# the dwell (30s) and post-restore startup-grace wait (~180s) are
# original to the harness and are NOT trimmed, they're load-bearing
# (see git history / session notes on the dwell-race and inconsistent-
# detection-timing bugs those windows exist to prevent).
POST_ISOLATION_OBSERVE_SECONDS = 45.0

POLL_INTERVAL_SECONDS = 1.0
# Detection must appear within this long after attack onset, or the trial
# is recorded as a real miss (not a hang) - generous margin above the
# structural 60s CPU-gate window.
DETECTION_TIMEOUT_SECONDS = 180.0
# Real full-isolation dwell (30.0) + generous margin for the containment
# writes themselves and polling granularity.
FULL_ISOLATION_TIMEOUT_SECONDS = 30.0 + 60.0
# How long to wait for the collector to fully settle back to a clean
# baseline after a trial (CPU-gate's own 60s rolling window has to roll
# the attack samples back out) before starting the next trial.
SETTLE_SECONDS = 75.0
# Mirrors ztx_t2_collector.py's own STARTUP_GRACE_SECONDS (=180.0) - can't
# import it directly (separate process/venv), same pattern as that
# module's own DWELL_SECONDS_MIRROR. The collector suppresses ALL
# reporting for this long after re-resolving its container context
# (every pod recreation, i.e. every restore under the current
# RESTORE_POD_RECREATION_ENABLED=true design) - the real driver of
# post-restore recovery timing, not SETTLE_SECONDS above (which only
# covers the CPU-gate's 60s rolling window and only applies on the rarer
# path where no pod recreation actually happened).
STARTUP_GRACE_SECONDS = 180.0

SUMMARY_FIELDS = [
    "trial_id", "scenario", "trial_number",
    "t_attack_issued_utc",
    "t_detected_utc", "detection_latency_ms",
    "t_elevated_utc", "elevated_latency_ms",
    "t_throttle_applied_utc", "immediate_containment_latency_ms",
    "t_isolated_utc", "full_isolation_latency_ms", "full_isolation_note",
    # DWELL_SECONDS (=30.0) is a fixed, known constant, not something this
    # harness can observe directly server-side (isolation_dwell_seconds_
    # remaining exists only transiently in the T2 collector's own POST
    # response, never persisted to CSM_STATE/trust-state, and is truncated
    # out of the collector's own 500-char response log - confirmed by
    # direct inspection, not assumed). This algebraic decomposition
    # (measured total minus the known constant) is the honest way to
    # separate the policy-mandated wait from whatever real overhead comes
    # after it clears.
    "post_dwell_overhead_ms",
    "quarantine_marked_at_isolation", "service_isolated_at_isolation",
    "direct_network_isolated_at_isolation", "direct_network_isolated_recheck_attempts",
    "svid_disabled_at_isolation",
    "network_baseline_reachable", "t_network_unreachable_utc", "network_unreachable_latency_ms",
    "net_rx_bytes_baseline", "net_tx_bytes_baseline",
    "net_rx_bytes_at_isolated", "net_tx_bytes_at_isolated",
    "max_t2_pressure_score", "max_m1_cpu_millicores",
    "cpu_gate_hit_ever", "confirmed_6of8_ever",
    "final_public_state", "reached_compromised", "reached_isolated",
    "expected_to_detect", "correct_classification",
    "restore_verified", "throttle_released_verified",
    "outcome", "notes",
]

TIMESERIES_FIELDS = [
    "trial_id", "scenario", "trial_number", "sample_wall_clock_utc",
    "elapsed_s", "sample_quality", "eligible",
    "m1_cpu_millicores", "m4_memory_growth_bytes_per_s",
    "m5_network_rx_bytes_per_s", "m6_network_tx_bytes_per_s",
    "t2_pressure_score", "confirmed_upper_6of8", "cpu_gate_hit",
    "public_state",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ms_between(t1_iso: Optional[str], t2_iso: Optional[str]) -> Optional[float]:
    if not t1_iso or not t2_iso:
        return None
    t1 = datetime.fromisoformat(t1_iso)
    t2 = datetime.fromisoformat(t2_iso)
    return round((t2 - t1).total_seconds() * 1000, 1)


def ensure_csv_headers() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if not SUMMARY_CSV.exists():
        with open(SUMMARY_CSV, "w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=SUMMARY_FIELDS).writeheader()
    if not TIMESERIES_CSV.exists():
        with open(TIMESERIES_CSV, "w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=TIMESERIES_FIELDS).writeheader()


def append_summary_row(row: Dict[str, Any]) -> None:
    with open(SUMMARY_CSV, "a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=SUMMARY_FIELDS).writerow(row)


def append_timeseries_rows(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    with open(TIMESERIES_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=TIMESERIES_FIELDS)
        for r in rows:
            writer.writerow(r)


def load_completed_count(scenario: str) -> int:
    if not SUMMARY_CSV.exists():
        return 0
    with open(SUMMARY_CSV, newline="", encoding="utf-8") as f:
        return sum(1 for r in csv.DictReader(f) if r.get("scenario") == scenario)


# ------------------------------------------------------------
# 2026-07-25: network-isolation instrumentation, ported from the proven
# Falco harness (run_kpimon_latency_trials.py) rather than re-invented -
# same busybox probe pod, same `nc -z` TCP-connect technique, same
# ClusterIP-not-FQDN choice (CoreDNS was intermittently flaky for the
# Service FQDN specifically during the Falco N=400 collection).
# ------------------------------------------------------------

def ensure_probe_pod() -> None:
    existing = subprocess.run(
        ["kubectl", "get", "pod", PROBE_POD_NAME, "-n", NS,
         "-o", "jsonpath={.status.phase}"],
        capture_output=True, text=True, timeout=15,
    )
    if existing.returncode == 0 and existing.stdout.strip() == "Running":
        return
    subprocess.run(
        ["kubectl", "delete", "pod", PROBE_POD_NAME, "-n", NS, "--ignore-not-found=true"],
        capture_output=True, text=True, timeout=30,
    )
    subprocess.run(
        ["kubectl", "run", PROBE_POD_NAME, "--image=busybox:1.36", "--restart=Never",
         "-n", NS, "--labels", PROBE_POD_LABEL, "--command", "--", "sleep", "999999"],
        capture_output=True, text=True, timeout=30,
    )
    deadline = time.time() + 60
    while time.time() < deadline:
        out = subprocess.run(
            ["kubectl", "get", "pod", PROBE_POD_NAME, "-n", NS,
             "-o", "jsonpath={.status.phase}"],
            capture_output=True, text=True, timeout=15,
        )
        if out.stdout.strip() == "Running":
            return
        time.sleep(2)


def get_kpimon_service_ip() -> str:
    try:
        return subprocess.check_output(
            ["kubectl", "get", "svc", "-n", NS, KPIMON_SERVICE_NAME,
             "-o", "jsonpath={.spec.clusterIP}"],
            text=True, timeout=30,
        ).strip()
    except Exception:
        return ""


def check_reachable(service_ip: str) -> bool:
    """Real TCP connect attempt from the dedicated probe pod to kpimon-go's
    own Service - verifies actual network-level reachability, not just
    whether a label exists."""
    if not service_ip:
        return False
    try:
        out = subprocess.run(
            ["kubectl", "exec", "-n", NS, PROBE_POD_NAME, "--",
             "nc", "-z", "-w", str(int(REACHABILITY_PROBE_TIMEOUT_SECONDS)),
             service_ip, str(KPIMON_SERVICE_PORT)],
            capture_output=True, text=True, timeout=REACHABILITY_PROBE_TIMEOUT_SECONDS + 5,
        )
        return out.returncode == 0
    except Exception:
        return False


def get_net_dev_counters(pod: str) -> "tuple[Optional[int], Optional[int]]":
    """rx/tx byte counters from the pod's own eth0, read via `kubectl exec
    ... cat /proc/net/dev` (the pod's own view of its interface) - no sudo
    required, and keeps working after a NetworkPolicy quarantine blocks
    the pod's actual traffic since kubectl exec goes through the kubelet
    API (local container-runtime attach), not the data-plane interface."""
    try:
        out = subprocess.run(
            ["kubectl", "exec", "-n", NS, pod, "-c", CONTAINER, "--", "cat", "/proc/net/dev"],
            capture_output=True, text=True, timeout=15,
        )
        for line in out.stdout.splitlines():
            if line.strip().startswith("eth0:"):
                fields = line.split(":", 1)[1].split()
                return int(fields[0]), int(fields[8])
    except Exception:
        pass
    return None, None


def get_svid_disabled(mech_snapshot: Optional[Dict[str, Any]]) -> Optional[bool]:
    """Reads the zt-xguard.io/svid-enabled label straight out of the
    verify_xapp_containment() response's own pod listing - that endpoint
    already returns full pod labels (see containment_orchestrator.py's
    verify_xapp_containment: pod_results includes "labels": labels), so
    this needs no new server-side field, just reading one already there."""
    if not mech_snapshot:
        return None
    pods = mech_snapshot.get("pods") or []
    if not pods:
        return None
    labels = pods[0].get("labels") or {}
    return labels.get("zt-xguard.io/svid-enabled") == "false"


def resolve_kpimon_pod() -> str:
    return subprocess.check_output(
        ["kubectl", "get", "pods", "-n", NS, "--field-selector=status.phase=Running",
         "-o", "name"], text=True, timeout=30,
    ).strip().lower()


def get_kpimon_pod_name() -> str:
    out = subprocess.check_output(
        ["kubectl", "get", "pods", "-n", NS, "-l", f"app={XAPP}",
         "-o", "jsonpath={.items[0].metadata.name}"],
        text=True, timeout=30,
    ).strip()
    if not out:
        raise RuntimeError("no Running kpimon-go pod found")
    return out


# 2026-07-24: EVERY exec below runs the target binary directly as argv,
# never via `sh -lc "..."` - confirmed live that wrapping commands in a
# shell here genuinely triggers Falco's own "Unexpected Shell" rule
# (ZTX-A1, matches any exec of sh/bash/dash/zsh/ksh/ash inside the
# container) and, via `sh -lc`'s `-l` login-shell flag reading /etc/passwd
# at init, "Sensitive File Access" (ZTX-A2) too - both real, unwanted
# Falco-driven detections that caused a genuine, confounding isolation of
# kpimon-go during an earlier T2-only trial run (Falco's own containment
# pipeline is fully active and completely independent of this harness).
# stress-ng's own --timeout flag (already embedded in every caller's args)
# makes it self-terminate without needing in-container `nohup ... &`
# shell backgrounding - the backgrounding instead happens at the Popen
# level below, entirely outside the container.

_active_stress_procs: Dict[str, "subprocess.Popen"] = {}


def preflight(pod: str) -> None:
    check = subprocess.run(
        ["kubectl", "exec", "-n", NS, pod, "-c", CONTAINER, "--", "stress-ng", "--version"],
        capture_output=True, text=True, timeout=15,
    )
    if check.returncode != 0:
        raise RuntimeError(f"stress-ng not available in {pod}/{CONTAINER}: {check.stderr}")
    # 2026-07-24 (follow-up): used to check "is stress-ng already running"
    # via `ps aux` first, only cleaning up conditionally. Confirmed live
    # that `ps aux` itself triggers Falco's "Sensitive File Access" rule -
    # `ps` reads /etc/passwd internally to resolve UIDs to usernames for
    # display, regardless of whether output is actually inspected for
    # that, and it isn't part of any exempted process tree. Simpler and
    # safe: always run the (already-verified-clean) pkill-based cleanup
    # unconditionally before every attack instead of conditionally
    # checking first - idempotent (a "no matching process" pkill exit is
    # harmless) and avoids the risky check entirely.
    cleanup_stress_ng(pod)


def run_stress_ng(pod: str, args: List[str]) -> None:
    """Launches stress-ng directly (no shell, no `nohup ... &`) via a
    non-blocking Popen - the kubectl exec process itself backgrounds the
    call from this harness's own perspective; stress-ng's own --timeout
    (part of args) makes it self-terminate remotely."""
    proc = subprocess.Popen(
        ["kubectl", "exec", "-n", NS, pod, "-c", CONTAINER, "--", "stress-ng"] + list(args),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    _active_stress_procs[pod] = proc


def cleanup_stress_ng(pod: str) -> None:
    """Two direct (non-shell) pkill calls, TERM then KILL - no `sh -c`
    chaining needed since a "no matching process" exit code is expected
    and harmless whenever stress-ng already self-terminated via --timeout."""
    subprocess.run(
        ["kubectl", "exec", "-n", NS, pod, "-c", CONTAINER, "--", "pkill", "-TERM", "stress-ng"],
        capture_output=True, text=True, timeout=15,
    )
    time.sleep(1)
    subprocess.run(
        ["kubectl", "exec", "-n", NS, pod, "-c", CONTAINER, "--", "pkill", "-KILL", "stress-ng"],
        capture_output=True, text=True, timeout=15,
    )
    proc = _active_stress_procs.pop(pod, None)
    if proc is not None:
        try:
            proc.wait(timeout=5)
        except Exception:
            pass


def read_state_file() -> Optional[Dict[str, Any]]:
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return None


def get_trust_state() -> Optional[Dict[str, Any]]:
    try:
        out = subprocess.run(
            ["kubectl", "exec", "-n", "zt-xguard", get_policy_engine_pod(), "--",
             "python3", "-c",
             "import urllib.request,json;print(json.dumps(json.loads(urllib.request.urlopen('http://localhost:5000/trust-state',timeout=5).read())))"],
            capture_output=True, text=True, timeout=15,
        )
        d = json.loads(out.stdout)
        for x in d.get("xapps", []):
            if x.get("xapp") == XAPP:
                return x
        return None
    except Exception:
        return None


def get_containment_verify() -> Optional[Dict[str, Any]]:
    try:
        out = subprocess.run(
            ["kubectl", "exec", "-n", "zt-xguard", get_policy_engine_pod(), "--",
             "python3", "-c",
             f"import urllib.request,json;r=urllib.request.urlopen('http://localhost:5000/csm/containment/verify?xapp={XAPP}',timeout=5);print(r.read().decode())"],
            capture_output=True, text=True, timeout=15,
        )
        return json.loads(out.stdout)
    except Exception:
        return None


def restore_kpimon() -> Dict[str, Any]:
    try:
        out = subprocess.run(
            ["kubectl", "exec", "-n", "zt-xguard", get_policy_engine_pod(), "--",
             "python3", "-c",
             "import urllib.request,json;"
             "req=urllib.request.Request('http://localhost:5000/csm/containment/restore',"
             f"data=json.dumps({{'xapp':'{XAPP}','namespace':'{NS}'}}).encode(),"
             "headers={'Content-Type':'application/json'},method='POST');"
             "print(urllib.request.urlopen(req,timeout=100).read().decode())"],
            capture_output=True, text=True, timeout=110,
        )
        return json.loads(out.stdout)
    except Exception as exc:
        return {"error": str(exc)}


_POLICY_ENGINE_POD_CACHE: Optional[str] = None


def get_policy_engine_pod() -> str:
    global _POLICY_ENGINE_POD_CACHE
    if _POLICY_ENGINE_POD_CACHE:
        return _POLICY_ENGINE_POD_CACHE
    pod = subprocess.check_output(
        ["kubectl", "get", "pods", "-n", "zt-xguard", "-l", "app=zt-xguard-policy-engine",
         "-o", "jsonpath={.items[0].metadata.name}"],
        text=True, timeout=30,
    ).strip()
    _POLICY_ENGINE_POD_CACHE = pod
    return pod


def check_t2_service_active() -> bool:
    out = subprocess.run(
        ["systemctl", "is-active", "ztx-t2-collector.service"],
        capture_output=True, text=True, timeout=10,
    )
    return out.stdout.strip() == "active"


def tail_collector_journal_since(since_iso: str) -> List[Dict[str, Any]]:
    """Structured JSON log lines from the T2 collector since a given time,
    with journald's own microsecond-precision receive timestamp attached
    (__REALTIME_TIMESTAMP, -o json) as "_real_time_utc" - this is the
    exact moment the collector's own process emitted that line, not
    whenever this harness next happened to poll for it. Every tick is
    logged (event="tick", 1Hz, m1/m4/m5/m6/t2_score/public_state), so a
    single query after a trial completes yields the full time-series at
    the collector's own native precision, plus the precise timestamps for
    reported_suspicious/reported_elevated/cpu_throttle_applied/
    cpu_throttle_released."""
    try:
        out = subprocess.run(
            ["journalctl", "-u", "ztx-t2-collector.service",
             "--since", since_iso, "-o", "json", "--no-pager"],
            capture_output=True, text=True, timeout=30,
        )
    except Exception:
        return []
    events = []
    for line in (out.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            envelope = json.loads(line)
        except Exception:
            continue
        message = envelope.get("MESSAGE")
        if not isinstance(message, str) or not message.startswith("{"):
            continue
        real_us = envelope.get("__REALTIME_TIMESTAMP")
        real_time_utc = None
        if real_us is not None:
            try:
                real_time_utc = datetime.fromtimestamp(int(real_us) / 1_000_000, tz=timezone.utc).isoformat()
            except Exception:
                real_time_utc = None
        try:
            payload = json.loads(message)
        except Exception:
            continue
        payload["_real_time_utc"] = real_time_utc
        events.append(payload)
    return events


def run_trial(
    scenario: str,
    trial_number: int,
    attack_fn,
    expected_to_detect: bool,
) -> Dict[str, Any]:
    """Runs one trial: preflight, sample baseline, launch attack_fn(pod,
    stop_event) in a background thread (attack_fn runs the scenario's own
    stress-ng sequence; for multi-phase scenarios it must check
    stop_event.is_set() between phases/cooldowns and return early if set -
    see run_a_burst_trials.py/run_a_memory_trials.py/
    run_a_stealth_trials.py for the pattern), poll for detection/
    containment CONCURRENTLY with the attack, then restore and settle.

    attack_fn must NOT clean up stress-ng itself on normal completion (the
    scenario's own script already lets stress-ng's own --timeout expire) -
    this function calls cleanup_stress_ng() unconditionally afterward as a
    safety net.
    """
    trial_id = f"{scenario}-{trial_number:03d}-{int(time.time())}"
    row: Dict[str, Any] = {k: "" for k in SUMMARY_FIELDS}
    row.update({"trial_id": trial_id, "scenario": scenario, "trial_number": trial_number,
                "expected_to_detect": expected_to_detect})

    pod = get_kpimon_pod_name()
    preflight(pod)

    ensure_probe_pod()
    service_ip = get_kpimon_service_ip()
    baseline_reachable = False
    for _ in range(REACHABILITY_RECHECK_ATTEMPTS):
        if check_reachable(service_ip):
            baseline_reachable = True
            break
        time.sleep(1)
    row["network_baseline_reachable"] = baseline_reachable
    rx0, tx0 = get_net_dev_counters(pod)
    row["net_rx_bytes_baseline"] = rx0 if rx0 is not None else ""
    row["net_tx_bytes_baseline"] = tx0 if tx0 is not None else ""

    t_issued = now_iso()
    row["t_attack_issued_utc"] = t_issued

    seen = {
        "detected": None, "elevated": None, "throttle_applied": None, "isolated": None,
    }

    # cpu_gate_hit/confirmed_upper_6of8 are NOT present in the journal's
    # reported_suspicious/reported_elevated/tick log lines (verified by
    # reading _post_signal/the tick log call directly - those log only
    # status+response text and m1/m4/m5/m6/t2_score respectively, not the
    # gate-confirmation booleans) - only the live state file carries them,
    # and it's overwritten every ~1s tick. Sampling it only once per main
    # loop iteration (which also does several seconds of kubectl exec/
    # journalctl work per iteration) reliably MISSED brief cpu_gate_hit=
    # True windows - confirmed live: the operator independently observed
    # ~24 real gate hits on the dashboard while this harness recorded
    # cpu_gate_hit_ever=False for the same trials, even though a
    # cpu_gate_hit=True is REQUIRED by the model's own logic for
    # reported_suspicious to ever fire at all (SUSPICIOUS =
    # confirmed_upper_6of8 AND cpu_gate_hit) - i.e. it was certainly true
    # at least once, this harness just never caught it. Fixed with a
    # dedicated background thread sampling the state file on its own
    # tight, independent cadence, decoupled entirely from the slower
    # network-bound work in the main loop below.
    max_score = None
    max_m1 = None
    cpu_gate_hit_ever = False
    confirmed_6of8_ever = False
    _flag_lock = threading.Lock()
    _stop_flag_sampler = threading.Event()

    def _flag_sampler_loop():
        nonlocal max_score, max_m1, cpu_gate_hit_ever, confirmed_6of8_ever
        while not _stop_flag_sampler.is_set():
            state = read_state_file()
            if state:
                with _flag_lock:
                    score = state.get("t2_pressure_score")
                    if score is not None:
                        max_score = score if max_score is None else max(max_score, score)
                    m1 = state.get("m1_cpu_millicores")
                    if m1 is not None:
                        max_m1 = m1 if max_m1 is None else max(max_m1, m1)
                    if state.get("cpu_gate_hit"):
                        cpu_gate_hit_ever = True
                    if state.get("confirmed_upper_6of8"):
                        confirmed_6of8_ever = True
            _stop_flag_sampler.wait(0.25)

    flag_sampler_thread = threading.Thread(target=_flag_sampler_loop, daemon=True)
    flag_sampler_thread.start()

    # 2026-07-25: attack_fn used to be called here and BLOCKED (via its own
    # internal time.sleep calls) for its full designed duration before the
    # polling loop below ever started - meaning that loop could only ever
    # observe /trust-state for the first time AFTER the attack had already
    # fully finished. Direct instrumented server-side evidence (a temporary
    # debug log inside ztx_v4_process_signal) proved real isolation happens
    # within seconds of detection, but every trial's recorded
    # "full_isolation_latency_ms" was actually just
    # (attack_duration_seconds*1000 - detection_latency_ms) plus a small
    # fixed cleanup/first-poll constant - a pure measurement artifact of
    # this ordering, confirmed by an near-perfect fit (residual std ~250ms)
    # across 11 real R1 trials. Fixed by running attack_fn in its own
    # thread and starting the poll loop immediately, concurrently - the
    # loop can now observe the real isolation moment whenever it actually
    # happens, not just after the attack's fixed duration elapses.
    stop_attack = threading.Event()
    attack_thread = threading.Thread(target=attack_fn, args=(pod, stop_attack), daemon=True)
    attack_thread.start()

    # ONE continuous 1s-cadence polling loop from t_issued through either
    # full isolation or a timeout - deliberately NOT split into a separate
    # "wait for detection" stage then a coarser "wait for isolation" stage
    # (an earlier version did split them with a coarser second-stage loop,
    # which added its own avoidable slop - see git history). Runs
    # concurrently with the attack thread above, not after it.
    detection_deadline = time.time() + DETECTION_TIMEOUT_SECONDS
    isolation_deadline: Optional[float] = None
    while True:
        now_mono = time.time()
        if seen["isolated"]:
            break
        if not seen["detected"] and now_mono >= detection_deadline:
            break
        if seen["detected"] and isolation_deadline is None:
            isolation_deadline = now_mono + FULL_ISOLATION_TIMEOUT_SECONDS
        if isolation_deadline is not None and now_mono >= isolation_deadline:
            break

        events = tail_collector_journal_since(t_issued)
        for ev in events:
            if ev.get("event") == "reported_elevated" and seen["elevated"] is None:
                seen["elevated"] = ev.get("_real_time_utc")
            if ev.get("event") == "reported_suspicious" and seen["detected"] is None:
                seen["detected"] = ev.get("_real_time_utc")
            if ev.get("event") == "cpu_throttle_applied" and seen["throttle_applied"] is None:
                seen["throttle_applied"] = ev.get("_real_time_utc")
        trust = get_trust_state()
        if trust and trust.get("state") == "ISOLATED" and seen["isolated"] is None:
            seen["isolated"] = now_iso()  # policy-engine-side transition, not journal-sourced

        time.sleep(POLL_INTERVAL_SECONDS)

    # Signal any still-running multi-phase attack (A_Burst/A_Memory/
    # A_Stealth) to stop between phases rather than firing further
    # pulses/steps after this trial has already moved on to restore/
    # settle/next-trial - real isolation is now expected to happen well
    # before a multi-phase attack's full designed duration completes,
    # which this concurrent poll loop can (correctly) observe early.
    stop_attack.set()
    attack_thread.join(timeout=10)
    cleanup_stress_ng(pod)

    _stop_flag_sampler.set()
    flag_sampler_thread.join(timeout=2)

    # Per-mechanism snapshot at the moment isolation is confirmed. All these
    # mechanisms apply synchronously within a single
    # _ztx_force_containment_for_xapp call server-side (same code path
    # Falco containment uses). direct_network_isolated specifically is
    # retried (MECH_RECHECK_ATTEMPTS times, MECH_RECHECK_INTERVAL_SECONDS
    # apart) rather than read once -- the original one-shot check read
    # False in 41/41 prior T2 trials despite the identical mechanism
    # confirming reliably (400/400) in the Falco dataset; retrying is the
    # correct fix regardless of whether that was a timing artifact or
    # something else, since it can only turn a real False into a real
    # True, never manufacture a false positive (verify_direct_network_
    # isolation() queries the live iptables rule table directly).
    mech_snapshot = get_containment_verify() if seen["isolated"] else None
    quarantine_marked_at_isolation = (mech_snapshot or {}).get("quarantine_marked")
    service_isolated_at_isolation = (mech_snapshot or {}).get("service_isolated")
    direct_network_isolated_at_isolation = (mech_snapshot or {}).get("direct_network_isolated")
    svid_disabled_at_isolation = get_svid_disabled(mech_snapshot)

    direct_recheck_attempts = 1 if seen["isolated"] else 0
    while seen["isolated"] and not direct_network_isolated_at_isolation and direct_recheck_attempts < MECH_RECHECK_ATTEMPTS:
        time.sleep(MECH_RECHECK_INTERVAL_SECONDS)
        mech_snapshot = get_containment_verify()
        direct_network_isolated_at_isolation = (mech_snapshot or {}).get("direct_network_isolated")
        # quarantine/service/SVID can only improve with more time too --
        # keep them in sync with whichever snapshot is now authoritative.
        quarantine_marked_at_isolation = (mech_snapshot or {}).get("quarantine_marked")
        service_isolated_at_isolation = (mech_snapshot or {}).get("service_isolated")
        svid_disabled_at_isolation = get_svid_disabled(mech_snapshot)
        direct_recheck_attempts += 1

    # Real network-level reachability cutoff, active TCP-probe verified
    # (same technique as the Falco harness), not just "did a label
    # change". Polls until unreachable or the recheck budget is spent.
    t_network_unreachable = ""
    if seen["isolated"]:
        for _ in range(REACHABILITY_RECHECK_ATTEMPTS):
            check_t = now_iso()
            if not check_reachable(service_ip):
                t_network_unreachable = check_t
                break
            time.sleep(1)
    rx1, tx1 = get_net_dev_counters(pod) if seen["isolated"] else (None, None)

    # Extended post-isolation observation hold -- keeps this trial's own
    # window (and any externally-running network_rxtx_sampler_exec.sh)
    # sampling well past the isolation moment, so throughput settling at
    # near-zero and STAYING there is actually captured, not just the
    # transition instant. Only applied when isolation actually happened.
    if seen["isolated"]:
        print(f"[t2-harness]   holding {POST_ISOLATION_OBSERVE_SECONDS:.0f}s post-isolation "
              f"for sustained-cutoff observation before restore...", flush=True)
        time.sleep(POST_ISOLATION_OBSERVE_SECONDS)

    # Final, single comprehensive journal query spanning the whole trial -
    # builds the full 1Hz time-series (every "tick" event, which carries
    # m1/m4/m5/m6/t2_score/public_state but NOT cpu_gate_hit/
    # confirmed_upper_6of8 - those two only exist in the state file,
    # already sampled into cpu_gate_hit_ever/confirmed_6of8_ever above) and
    # re-derives detected/elevated/throttle timestamps one more time in
    # case any were still missing from the incremental polling loop (e.g.
    # a signal that arrived in the gap between two poll iterations).
    all_events = tail_collector_journal_since(t_issued)
    ts_rows: List[Dict[str, Any]] = []
    for ev in all_events:
        if ev.get("event") == "tick":
            ts_rows.append({
                "trial_id": trial_id, "scenario": scenario, "trial_number": trial_number,
                "sample_wall_clock_utc": ev.get("_real_time_utc"),
                "elapsed_s": ev.get("elapsed_s"),
                "sample_quality": ev.get("sample_quality"),
                "eligible": "",
                "m1_cpu_millicores": ev.get("m1"),
                "m4_memory_growth_bytes_per_s": ev.get("m4"),
                "m5_network_rx_bytes_per_s": ev.get("m5"),
                "m6_network_tx_bytes_per_s": ev.get("m6"),
                "t2_pressure_score": ev.get("t2_score"),
                "confirmed_upper_6of8": "",
                "cpu_gate_hit": "",
                "public_state": ev.get("public_state"),
            })
            score = ev.get("t2_score")
            if score is not None:
                max_score = score if max_score is None else max(max_score, score)
            m1 = ev.get("m1")
            if m1 is not None:
                max_m1 = m1 if max_m1 is None else max(max_m1, m1)
        if ev.get("event") == "reported_elevated" and seen["elevated"] is None:
            seen["elevated"] = ev.get("_real_time_utc")
        if ev.get("event") == "reported_suspicious" and seen["detected"] is None:
            seen["detected"] = ev.get("_real_time_utc")
        if ev.get("event") == "cpu_throttle_applied" and seen["throttle_applied"] is None:
            seen["throttle_applied"] = ev.get("_real_time_utc")

    row["t_detected_utc"] = seen["detected"] or ""
    row["detection_latency_ms"] = ms_between(t_issued, seen["detected"]) if seen["detected"] else ""
    row["t_elevated_utc"] = seen["elevated"] or ""
    row["elevated_latency_ms"] = ms_between(t_issued, seen["elevated"]) if seen["elevated"] else ""
    row["t_throttle_applied_utc"] = seen["throttle_applied"] or ""
    row["immediate_containment_latency_ms"] = (
        ms_between(seen["detected"], seen["throttle_applied"]) if seen["detected"] and seen["throttle_applied"] else ""
    )
    row["t_isolated_utc"] = seen["isolated"] or ""
    row["full_isolation_latency_ms"] = (
        ms_between(seen["detected"], seen["isolated"]) if seen["detected"] and seen["isolated"] else ""
    )
    row["full_isolation_note"] = (
        "gated behind ztx_isolation_manager.DWELL_SECONDS=30.0 (deliberate operator-approved "
        "policy, not a mechanism-speed limit) - report as policy parameter + overhead, not raw latency"
    )
    row["post_dwell_overhead_ms"] = (
        round(row["full_isolation_latency_ms"] - 30000.0, 1)
        if isinstance(row["full_isolation_latency_ms"], float) else ""
    )
    row["quarantine_marked_at_isolation"] = quarantine_marked_at_isolation
    row["service_isolated_at_isolation"] = service_isolated_at_isolation
    row["direct_network_isolated_at_isolation"] = direct_network_isolated_at_isolation
    row["direct_network_isolated_recheck_attempts"] = direct_recheck_attempts
    row["svid_disabled_at_isolation"] = svid_disabled_at_isolation
    row["t_network_unreachable_utc"] = t_network_unreachable
    row["network_unreachable_latency_ms"] = (
        ms_between(t_issued, t_network_unreachable) if t_network_unreachable else ""
    )
    row["net_rx_bytes_at_isolated"] = rx1 if rx1 is not None else ""
    row["net_tx_bytes_at_isolated"] = tx1 if tx1 is not None else ""
    row["max_t2_pressure_score"] = max_score if max_score is not None else ""
    row["max_m1_cpu_millicores"] = max_m1 if max_m1 is not None else ""
    row["cpu_gate_hit_ever"] = cpu_gate_hit_ever
    row["confirmed_6of8_ever"] = confirmed_6of8_ever

    final_state_entry = get_trust_state()
    final_public_state = (final_state_entry or {}).get("state") or "NORMAL"
    row["final_public_state"] = final_public_state
    row["reached_compromised"] = bool(seen["detected"])
    row["reached_isolated"] = bool(seen["isolated"])

    if expected_to_detect:
        row["correct_classification"] = bool(seen["detected"])
    else:
        row["correct_classification"] = not bool(seen["detected"])

    row["outcome"] = "pass" if row["correct_classification"] else (
        "miss" if expected_to_detect else "false_positive"
    )

    # Recovery: restore (clears CSM_STATE + any real network isolation),
    # then wait for the collector to release its own cgroup throttle
    # (gated behind its own DWELL_SECONDS_MIRROR=30.0 safety hold) and for
    # the CPU-gate's 60s rolling window to fully clear the attack samples
    # before the next trial starts from a genuinely clean baseline.
    #
    # 2026-07-24: confirmed live a narrow race - restore recreates the
    # pod, but the T2 collector only notices the old cgroup path is gone
    # on its OWN next ~1Hz tick; if it posts one more resource_anomaly_t2
    # signal from a stale read of the old (about-to-be-deleted) container
    # in that brief window, it re-starts a fresh 30s dwell and genuinely
    # re-isolates a pod that isn't actually compromised anymore. Retrying
    # restore lets it clear once that race window has passed (confirmed
    # live: a second restore call cleanly succeeded right after a first
    # one's verification showed still-contained).
    restore_resp: Dict[str, Any] = {}
    restore_verified = False
    for attempt in range(3):
        restore_resp = restore_kpimon()
        restore_verified = (
            not (restore_resp.get("verification_after_restore", {}) or {}).get("contained", False)
            if isinstance(restore_resp, dict) else False
        )
        if restore_verified:
            break
        print(f"[t2-harness]   restore attempt {attempt + 1} still shows contained "
              f"(likely the pod-recreation/T2-repost race) - retrying...", flush=True)
        time.sleep(10)
    row["restore_verified"] = restore_verified

    throttle_deadline = time.time() + 45
    throttle_released = True
    while time.time() < throttle_deadline:
        events = tail_collector_journal_since(seen["throttle_applied"] or t_issued)
        if any(ev.get("event") == "cpu_throttle_released" for ev in events):
            throttle_released = True
            break
        if not seen["throttle_applied"]:
            throttle_released = True
            break
        throttle_released = False
        time.sleep(3)
    row["throttle_released_verified"] = throttle_released

    # 2026-07-24 (follow-up): STARTUP_GRACE_SECONDS in ztx_t2_collector.py
    # is 180.0 - a FULL 3 MINUTES the collector suppresses ALL reporting
    # after re-resolving its container context (which happens on every
    # pod recreation, i.e. every restore call under the current
    # RESTORE_POD_RECREATION_ENABLED=true containment design). A fixed
    # SETTLE_SECONDS=75s (well under 180s) meant every trial after the
    # first was launching its attack while still inside the PREVIOUS
    # trial's own startup-grace suppression window - confirmed as the
    # real cause of inconsistent detection timing (37s vs 71s across
    # otherwise-identical R1 trials) and the "warming up"/intermittently
    # unavailable pattern observed live on the dashboard. Fixed properly:
    # find the collector's own "resynced_context" event timestamp (logged
    # exactly when it detects the new pod and resets internal state) and
    # wait until STARTUP_GRACE_SECONDS has genuinely elapsed since THAT
    # moment, not a fixed guess. Falls back to a short baseline settle if
    # no resync event is found (restore didn't actually recreate the pod
    # this time, e.g. RESTORE_POD_RECREATION_ENABLED=false).
    resync_wait_start = time.time()
    resync_search_deadline = resync_wait_start + 30
    resync_at: Optional[float] = None
    while time.time() < resync_search_deadline:
        events = tail_collector_journal_since(t_issued)
        resync_events = [ev for ev in events if ev.get("event") == "resynced_context"]
        if resync_events:
            last_resync = resync_events[-1]
            try:
                resync_at = datetime.fromisoformat(last_resync["_real_time_utc"]).timestamp()
            except Exception:
                resync_at = time.time()
            break
        time.sleep(2)

    if resync_at is not None:
        grace_deadline = resync_at + STARTUP_GRACE_SECONDS + 10.0
        remaining = max(0.0, grace_deadline - time.time())
        print(f"[t2-harness]   pod was recreated - waiting {remaining:.0f}s for the collector's "
              f"{STARTUP_GRACE_SECONDS:.0f}s startup-grace window to clear before the next trial...", flush=True)
        time.sleep(remaining)
    else:
        print(f"[t2-harness]   no pod recreation detected - settling {SETTLE_SECONDS:.0f}s before next trial...", flush=True)
        time.sleep(SETTLE_SECONDS)

    append_timeseries_rows(ts_rows)
    return row


def print_trial_result(row: Dict[str, Any]) -> None:
    print(
        f"[t2-harness]   -> outcome={row['outcome']} "
        f"detect_ms={row['detection_latency_ms']} "
        f"throttle_ms={row['immediate_containment_latency_ms']} "
        f"isolate_ms={row['full_isolation_latency_ms']} "
        f"post_dwell_overhead_ms={row['post_dwell_overhead_ms']} "
        f"max_score={row['max_t2_pressure_score']} "
        f"cpu_gate_hit_ever={row['cpu_gate_hit_ever']}",
        flush=True,
    )
