#!/usr/bin/env python3
"""
ZT-XGuard live T2 resource-anomaly collector for kpimon-go.

step_xguard_02 Step C (2026-07-15). Runs on the Kubernetes node itself
(NOT inside any pod, NOT inside kpimon-go) with root/sudo access - because
per-container CPU/memory/network counters require reading cgroup v2 files
and /proc/<pid>/net/dev directly. The policy-engine pod's own ServiceAccount
has no RBAC for node-level stats (verified live: `kubectl auth can-i get
nodes/proxy` returns "no"), and kpimon-go's own :9090/ztx/metrics endpoint
only exposes RIC-activity counters (heartbeat/RMR/work-units) - confirmed
live, it does NOT expose CPU/memory/network at all. See
ZTXGUARD_SESSION_LOG_20260710.md Section 19 for the full investigation
that led to this design (RBAC check, live endpoint probe, and formula
verification below).

This script does not touch kpimon-go in any way - every read is either an
HTTP GET against its already-existing endpoint, or a root-level read of
files the kernel/kubelet already expose on the host. It reports findings
to the policy engine (zt-xguard namespace) via the same /csm/intent/ingest
HTTP endpoint any external signal source can already use.

FEATURE FORMULAS ARE NOT RECONSTRUCTED GUESSES. Verified byte-exact against
the real frozen-calibration CSV data before this script was written:
  - m1 (CPU) and m5/m6 (network RX/TX): exact match on D4 calibration data,
    2 independent row-pairs checked by hand.
  - m4 (memory growth): 2671/2671 ready rows matched to floating-point
    precision against the A-MEMORY-EXHAUSTION-BLIND dataset (the messiest
    available real attack run), which is what disambiguated "OLS slope of
    working-set memory over a trailing 30-SECOND time window" from every
    other candidate formula (fixed-sample-count windows and raw
    memory.current both failed to reproduce the recorded values).
Do not change these formulas without re-verifying against that same
evidence (see the git history / session log for the verification scripts)
- doing so silently invalidates the frozen model's calibration, since the
T2 statistic is only meaningful if computed the same way live as it was
during calibration.

Requires (pip install numpy pandas PyYAML, or use requirements.txt in this
directory): numpy, pandas, PyYAML. Requires ztx_model/ and
ztx_model_artifacts/ (copied verbatim from src/ztx_model/ and
outputs/step54,76/) to sit alongside this script on the node.

Usage:
    sudo python3 ztx_t2_collector.py
    sudo python3 ztx_t2_collector.py --interval 1.0 --policy-engine-url http://10.x.x.x:5000
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from ztx_model.streaming import StreamingScorer  # noqa: E402

# -----------------------------
# Fixed target: kpimon-go only. This detector was calibrated for kpimon-go
# specifically (see src/ztx_model/__init__.py DATASET_ROLES) and was never
# validated for any other xApp.
# -----------------------------
NAMESPACE = "ricxapp"
POD_LABEL_SELECTOR = "app=ricxapp-kpimon-go"
CONTAINER_NAME = "kpimon-go"
XAPP_NAME = "ricxapp-kpimon-go"  # must match the live XAPP_LIST entry exactly
METRICS_PORT = 9090
METRICS_PATH = "/ztx/metrics"
NET_IFACE = "eth0"

MEMORY_SLOPE_WINDOW_SECONDS = 30.0
DEFAULT_INTERVAL_SECONDS = 1.0
TIMING_TOLERANCE_SECONDS = 0.5  # judgment call, see collect_sample() docstring

# 2026-07-17: kpimon-go, once actually connected to a live RAN (srsRAN+UE),
# was observed being isolated ~2 minutes after every pod restart - real E2/RMR
# connection setup (SCTP handshake, initial subscription requests) produces a
# genuine CPU/network burst that the frozen model, never calibrated against
# live RAN traffic, reads as a confirmed anomaly. The dwell timer protects
# against a momentary blip, but a startup burst that lasts long enough to
# satisfy 6-of-8 is exactly the kind of sustained-but-benign pattern it can't
# tell apart from a real attack. This grace window suppresses REPORTING
# (scoring/logging still happen, for visibility) for a period after every
# resolve/resync of the tracked container - i.e. after every kpimon-go
# restart, not just the first one - so a benign startup burst can never
# trigger containment again. It does not mask a genuinely sustained anomaly
# past this window, and it does not change the frozen formulas or thresholds.
STARTUP_GRACE_SECONDS = 180.0

# Phase 2 (mechanism #3, 2026-07-17): CPU throttling during the COMPROMISED/
# ISOLATED dwell window, applied directly at the cgroup v2 level - out of
# band from Kubernetes' own resource-limit mechanism entirely, so kpimon-go's
# Deployment/pod spec (and therefore its image and the T2 calibration itself)
# is never touched.
#
# 40 millicores, NOT "20% of a core" (=200m) as originally picked - that
# first number was a generic round-number guess, not grounded in kpimon-go's
# actual numbers, and turned out to exactly equal its own K8s-declared
# `limits.cpu: 200m` (confirmed via `kubectl describe pod`) - throttling to
# the SAME ceiling Kubernetes already enforces would have been a no-op
# against any attack that could already reach that limit. Every observed m1
# reading this whole session, in normal operation, has sat around 1-3
# millicores (occasional small spikes to ~11) - 40m is ~15-40x that idle
# baseline (harmless normally, plenty of headroom for legitimate activity)
# while sitting meaningfully below the 200m ceiling a real flood attack
# could otherwise reach, so it actually constrains one instead of mirroring
# the existing limit.
CGROUP_THROTTLE_QUOTA_MILLICORES = 40
CGROUP_THROTTLE_PERIOD_US = 100000
# Mirrors ztx_isolation_manager.DWELL_SECONDS (=30.0) in the in-cluster
# policy-engine pod - can't import it directly, this collector is a
# completely separate VM-side process with no shared module boundary. Used
# only as a release safety-valve (see _check_throttle_release below), not to
# duplicate any actual decision logic.
DWELL_SECONDS_MIRROR = 30.0
THROTTLE_SAFETY_TIMEOUT_SECONDS = DWELL_SECONDS_MIRROR + 60.0

# Frozen thresholds, from v3_frozen_model_spec.yaml / v5_frozen_gate_manifest.json.
# 2026-07-16: WARNING_LIMIT is now also used live (not just for display) to
# report a distinct "elevated but not yet confirmed" signal, so the policy
# engine has a real WL<score<UCL SUSPICIOUS tier separate from the fully
# confirmed COMPROMISED tier - see report_elevated()/report_suspicious()
# below and ztx_state_engine.py's resource_anomaly_t2_elevated/resource_anomaly_t2 branches.
WARNING_LIMIT = 10.436432182404562
UPPER_LIMIT = 15.3084172374118

STEP54_DIR = SCRIPT_DIR / "ztx_model_artifacts" / "step54"
STEP76_DIR = SCRIPT_DIR / "ztx_model_artifacts" / "step76"

# Shared with the separate ztx_t2_visualizer pod via a hostPath mount of
# this same directory - display-only, the visualizer never computes a
# score itself, it just reads whatever this collector last wrote here.
STATE_DIR = Path("/var/lib/ztx-t2-state")
STATE_FILE = STATE_DIR / "latest.json"


def _run(cmd: list) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr}")
    return result.stdout.strip()


def _run_with_input(cmd: list, input_text: str) -> str:
    """Same contract as _run, but pipes input_text to the command's stdin -
    needed for `sudo tee <path>`, the standard safe way to write a
    root-owned file: `sudo echo x > path` does NOT work as expected, because
    the shell (not sudo) performs the redirection, as the invoking user, not
    root. `tee` itself runs as root via sudo and does the write directly."""
    result = subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr}")
    return result.stdout.strip()


def apply_cpu_throttle(cgroup_path: Path) -> None:
    """Cap CPU at CGROUP_THROTTLE_QUOTA_MILLICORES millicores via cgroup v2's
    cpu.max (syntax: "<quota_usec> <period_usec>"). Out-of-band from
    Kubernetes' own resource-limit mechanism entirely - see the module-level
    comment by CGROUP_THROTTLE_QUOTA_MILLICORES for why."""
    quota = int(CGROUP_THROTTLE_PERIOD_US * CGROUP_THROTTLE_QUOTA_MILLICORES / 1000)
    _run_with_input(["sudo", "tee", str(cgroup_path / "cpu.max")], f"{quota} {CGROUP_THROTTLE_PERIOD_US}\n")


def release_cpu_throttle(cgroup_path: Path) -> None:
    """Restore unrestricted CPU (cgroup v2 "max" quota)."""
    _run_with_input(["sudo", "tee", str(cgroup_path / "cpu.max")], f"max {CGROUP_THROTTLE_PERIOD_US}\n")


def resolve_container_context() -> Dict[str, Any]:
    """Resolve kpimon-go's container ID, host PID, cgroup v2 path, and pod IP.

    Exact method verified live on 2026-07-15 against the real running
    kpimon-go pod: kubectl -> containerID -> `sudo crictl inspect` -> host
    PID -> /proc/<pid>/cgroup -> cgroup v2 path. Matches the resolution
    logic used by every collect_n4/step77-81 driver script in this project
    (collector/collect_resources.py itself is not recoverable, but this
    resolution chain is identical across all of them and was independently
    re-verified live rather than trusted from the shell scripts alone).
    """
    pod_name = _run([
        "kubectl", "get", "pods", "-n", NAMESPACE, "-l", POD_LABEL_SELECTOR,
        "-o", "jsonpath={.items[0].metadata.name}",
    ])
    if not pod_name:
        raise RuntimeError(f"no pod found for -l {POD_LABEL_SELECTOR} in {NAMESPACE}")

    pod_ip = _run([
        "kubectl", "get", "pod", pod_name, "-n", NAMESPACE,
        "-o", "jsonpath={.status.podIP}",
    ])

    raw_container_id = _run([
        "kubectl", "get", "pod", pod_name, "-n", NAMESPACE,
        "-o", f'jsonpath={{.status.containerStatuses[?(@.name=="{CONTAINER_NAME}")].containerID}}',
    ])
    container_id = raw_container_id.split("://", 1)[-1]
    if not container_id:
        raise RuntimeError(f"could not resolve containerID for {CONTAINER_NAME} in pod {pod_name}")

    inspect_json = _run(["sudo", "crictl", "inspect", container_id])
    info = json.loads(inspect_json)
    host_pid = info.get("info", {}).get("pid")
    if not host_pid:
        raise RuntimeError(f"crictl inspect did not return a pid for container {container_id}")

    cgroup_line = _run(["sudo", "cat", f"/proc/{host_pid}/cgroup"])
    cgroup_relative = None
    for line in cgroup_line.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0":
            cgroup_relative = parts[2]
            break
    if not cgroup_relative:
        raise RuntimeError(f"could not resolve cgroup v2 path from /proc/{host_pid}/cgroup")

    cgroup_path = Path("/sys/fs/cgroup" + cgroup_relative)

    return {
        "pod_name": pod_name,
        "pod_ip": pod_ip,
        "container_id": container_id,
        "host_pid": int(host_pid),
        "cgroup_path": cgroup_path,
    }


def read_cgroup_counters(cgroup_path: Path) -> Dict[str, float]:
    """Read cgroup v2 cpu.stat/memory.current/memory.stat. Root required."""
    cpu_stat = _run(["sudo", "cat", str(cgroup_path / "cpu.stat")])
    usage_usec = None
    for line in cpu_stat.splitlines():
        if line.startswith("usage_usec "):
            usage_usec = float(line.split()[1])
            break
    if usage_usec is None:
        raise RuntimeError(f"usage_usec not found in {cgroup_path}/cpu.stat")

    memory_current = float(_run(["sudo", "cat", str(cgroup_path / "memory.current")]))

    memory_stat = _run(["sudo", "cat", str(cgroup_path / "memory.stat")])
    inactive_file = None
    for line in memory_stat.splitlines():
        if line.startswith("inactive_file "):
            inactive_file = float(line.split()[1])
            break
    if inactive_file is None:
        raise RuntimeError(f"inactive_file not found in {cgroup_path}/memory.stat")

    return {
        "cpu_usage_usec_total": usage_usec,
        "memory_current_bytes": memory_current,
        "memory_inactive_file_bytes": inactive_file,
    }


def read_net_dev(host_pid: int, iface: str = NET_IFACE) -> Tuple[float, float]:
    """Read RX/TX byte totals for `iface` from /proc/<pid>/net/dev.

    Verified live on 2026-07-15: this is where the network byte counters
    actually come from (cgroup v2 has no built-in per-container network
    accounting) - confirmed by reading kpimon-go's real /proc/<pid>/net/dev
    and cross-checking the standard column layout (8 RX fields then 8 TX
    fields after the "iface:" token; RX bytes = field 0, TX bytes = field 8).
    """
    content = _run(["sudo", "cat", f"/proc/{host_pid}/net/dev"])
    for line in content.splitlines():
        line = line.strip()
        if not line.startswith(f"{iface}:"):
            continue
        fields = line.split(":", 1)[1].split()
        rx_bytes = float(fields[0])
        tx_bytes = float(fields[8])
        return rx_bytes, tx_bytes
    raise RuntimeError(f"interface {iface} not found in /proc/{host_pid}/net/dev")


def fetch_kpimon_metrics(pod_ip: str) -> Optional[Dict[str, Any]]:
    """GET kpimon-go's own :9090/ztx/metrics (RIC-activity counters only -
    heartbeat/RMR/work-units, never CPU/memory/network, confirmed live).
    Returns None on any failure rather than raising, since this endpoint
    failing should not itself crash the collector.
    """
    url = f"http://{pod_ip}:{METRICS_PORT}{METRICS_PATH}"
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def ols_slope(t: list, y: list) -> Optional[float]:
    """Least-squares slope of y vs t. Pure Python, no numpy dependency for
    this one calculation - kept simple and independently checkable against
    the verification scripts used to confirm the m4 formula.
    """
    n = len(t)
    if n < 2:
        return None
    sx = sum(t)
    sy = sum(y)
    sxx = sum(x * x for x in t)
    sxy = sum(x * yy for x, yy in zip(t, y))
    denom = n * sxx - sx * sx
    if denom == 0:
        return None
    return (n * sxy - sx * sy) / denom


class KpimonT2Collector:
    def __init__(self, policy_engine_url: str, interval: float = DEFAULT_INTERVAL_SECONDS):
        self.policy_engine_url = policy_engine_url.rstrip("/")
        self.interval = interval

        self.scorer = StreamingScorer.from_frozen_artifacts(STEP54_DIR, STEP76_DIR)

        ctx = resolve_container_context()
        self.pod_name = ctx["pod_name"]
        self.pod_ip = ctx["pod_ip"]
        self.host_pid = ctx["host_pid"]
        self.cgroup_path = ctx["cgroup_path"]
        self._log("resolved_context", **{k: str(v) for k, v in ctx.items()})

        self._start_monotonic = time.monotonic()
        self._context_since_monotonic = self._start_monotonic
        self._prev: Optional[Dict[str, float]] = None
        self._prev_elapsed_s: Optional[float] = None
        self._prev_runtime_counters: Optional[Dict[str, Any]] = None

        # (elapsed_s, working_set_bytes) pairs within the trailing 30s window,
        # used for the m4 OLS slope. Verified live: time-based window, not a
        # fixed sample count.
        self._memory_window: Deque[Tuple[float, float]] = deque()

        self._throttled = False
        self._throttle_started_monotonic: Optional[float] = None
        # Live dwell countdown for visualization only (e.g. ztx_t2_visualizer.py) -
        # populated by _check_throttle_release's /trust-state poll, None
        # whenever no dwell window is pending for this xapp.
        self._last_dwell_remaining: Optional[float] = None

    def _log(self, event: str, **fields: Any) -> None:
        print(json.dumps({"component": "ztx_t2_collector", "event": event, **fields}, default=str), flush=True)

    def _resync_container_context(self) -> None:
        """Called after a detected counter reset (likely container restart)."""
        ctx = resolve_container_context()
        self.pod_name = ctx["pod_name"]
        self.pod_ip = ctx["pod_ip"]
        self.host_pid = ctx["host_pid"]
        self.cgroup_path = ctx["cgroup_path"]
        self._context_since_monotonic = time.monotonic()
        self._log("resynced_context", **{k: str(v) for k, v in ctx.items()})

    def collect_sample(self) -> Optional[Dict[str, Any]]:
        """Read one tick of raw data, compute the 4 model features and 6
        eligibility flags, and return a sample dict - or None if a read
        itself failed (transient, logged, next tick retries).

        timing_ok uses a fixed +/-0.5s tolerance around the nominal
        interval. This specific tolerance is a judgment call (the original
        collector's exact threshold could not be recovered - see session
        log Section 19) - it gates a QUALITY flag, not a feature formula,
        so getting it approximately right matters far less than the 4
        feature formulas above, which were independently byte-verified.
        """
        now_elapsed = time.monotonic() - self._start_monotonic

        try:
            cgroup_counters = read_cgroup_counters(self.cgroup_path)
            rx_bytes, tx_bytes = read_net_dev(self.host_pid)
        except Exception as exc:
            # A genuine kpimon-go pod/container restart gets a brand-new
            # containerd cgroup scope (new hash in the path), so a stale
            # cgroup_path/host_pid fails outright here rather than silently
            # returning smaller numbers - re-resolve and retry once before
            # giving up on this tick. A restart also invalidates all rolling
            # state (window/MEWMA), same as the counter-reset path below.
            self._log("read_error_reresolving", error=str(exc))
            try:
                self._resync_container_context()
                self._memory_window.clear()
                self.scorer.reset()
                self._prev = None
                self._prev_elapsed_s = None
                self._prev_runtime_counters = None
                cgroup_counters = read_cgroup_counters(self.cgroup_path)
                rx_bytes, tx_bytes = read_net_dev(self.host_pid)
            except Exception as exc2:
                self._log("read_error", error=str(exc2))
                return None

        endpoint_data = fetch_kpimon_metrics(self.pod_ip)
        metrics_endpoint_ok = endpoint_data is not None

        working_set = cgroup_counters["memory_current_bytes"] - cgroup_counters["memory_inactive_file_bytes"]

        resource_counter_reset = False
        timing_ok = True
        m1 = None
        m5 = None
        m6 = None

        if self._prev is not None and self._prev_elapsed_s is not None:
            dt = now_elapsed - self._prev_elapsed_s
            timing_ok = abs(dt - self.interval) <= TIMING_TOLERANCE_SECONDS

            d_cpu = cgroup_counters["cpu_usage_usec_total"] - self._prev["cpu_usage_usec_total"]
            d_rx = rx_bytes - self._prev["rx_bytes"]
            d_tx = tx_bytes - self._prev["tx_bytes"]

            if d_cpu < 0 or d_rx < 0 or d_tx < 0 or dt <= 0:
                resource_counter_reset = True
            else:
                m1 = (d_cpu / dt) / 1000.0
                m5 = d_rx / dt
                m6 = d_tx / dt

        runtime_counter_reset = False
        if endpoint_data is not None and self._prev_runtime_counters is not None:
            for key in ("heartbeat_total", "rmr_rx_total", "rmr_tx_total", "work_units_total"):
                prev_val = self._prev_runtime_counters.get(key)
                cur_val = endpoint_data.get(key)
                if prev_val is not None and cur_val is not None and cur_val < prev_val:
                    runtime_counter_reset = True
                    break

        if resource_counter_reset or runtime_counter_reset:
            self._log("counter_reset_detected", resource_counter_reset=resource_counter_reset,
                       runtime_counter_reset=runtime_counter_reset)
            self._memory_window.clear()
            self.scorer.reset()

        # Trailing 30-SECOND window (time-based, verified formula) for m4.
        self._memory_window.append((now_elapsed, working_set))
        while self._memory_window and (now_elapsed - self._memory_window[0][0]) > MEMORY_SLOPE_WINDOW_SECONDS:
            self._memory_window.popleft()

        window_span = self._memory_window[-1][0] - self._memory_window[0][0] if len(self._memory_window) >= 2 else 0.0
        m4_memory_slope_ready = window_span >= (MEMORY_SLOPE_WINDOW_SECONDS - 1.0)
        m4 = None
        if m4_memory_slope_ready:
            t_vals = [p[0] for p in self._memory_window]
            y_vals = [p[1] for p in self._memory_window]
            m4 = ols_slope(t_vals, y_vals)

        # Update reset-detection state for next tick.
        self._prev = {
            "cpu_usage_usec_total": cgroup_counters["cpu_usage_usec_total"],
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
        }
        self._prev_elapsed_s = now_elapsed
        if endpoint_data is not None:
            self._prev_runtime_counters = endpoint_data

        eligible = (
            metrics_endpoint_ok
            and timing_ok
            and m4_memory_slope_ready
            and not resource_counter_reset
            and not runtime_counter_reset
            and m1 is not None
            and m5 is not None
            and m6 is not None
            and m4 is not None
        )

        if eligible:
            sample_quality = "ok"
        elif not metrics_endpoint_ok:
            sample_quality = "endpoint_error"
        elif resource_counter_reset or runtime_counter_reset:
            sample_quality = "counter_reset"
        elif not timing_ok:
            sample_quality = "timing_jitter"
        elif not m4_memory_slope_ready:
            sample_quality = "memory_slope_warmup"
        else:
            sample_quality = "first_sample"

        return {
            "elapsed_s": now_elapsed,
            "m1_cpu_millicores": m1,
            "m4_memory_growth_bytes_per_s": m4,
            "m5_network_rx_bytes_per_s": m5,
            "m6_network_tx_bytes_per_s": m6,
            "eligible": eligible,
            "sample_quality": sample_quality,
            "metrics_endpoint_ok": metrics_endpoint_ok,
            "timing_ok": timing_ok,
            "m4_memory_slope_ready": m4_memory_slope_ready,
            "resource_counter_reset": resource_counter_reset,
            "runtime_counter_reset": runtime_counter_reset,
            "activity": {
                "heartbeat_ok": bool(endpoint_data) and endpoint_data.get("heartbeat_total", 0) is not None,
                "heartbeat_total": (endpoint_data or {}).get("heartbeat_total"),
                "work_units_processed": (endpoint_data or {}).get("work_units_total"),
                "uptime_seconds": (endpoint_data or {}).get("uptime_seconds"),
            },
        }

    def _post_signal(self, signal: str, sample: Dict[str, Any], result: Any, log_event: str) -> None:
        payload = {
            "xapp": XAPP_NAME,
            "signal": signal,
            "namespace": NAMESPACE,
            "source": "ztx_t2_collector",
            "evidence": {
                "activity": sample["activity"],
                "metrics": {
                    "m1_cpu_millicores": sample["m1_cpu_millicores"],
                    "m4_memory_growth_bytes_per_s": sample["m4_memory_growth_bytes_per_s"],
                    "m5_network_rx_bytes_per_s": sample["m5_network_rx_bytes_per_s"],
                    "m6_network_tx_bytes_per_s": sample["m6_network_tx_bytes_per_s"],
                },
                "t2_pressure_score": result.v3_pressure_score,
                "confirmed_upper_6of8": result.confirmed_upper_6of8,
                "cpu_gate_hit": result.cpu_gate_hit,
                "elapsed_s": result.elapsed_s,
            },
        }
        url = f"{self.policy_engine_url}/csm/intent/ingest"
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        # 25s, not 5s: confirmed live this session that /csm/intent/ingest's
        # response is genuinely slow (several seconds) whenever the decision
        # is COMPROMISED, because the containment-attempt code inside it
        # tries and fails against the known, deliberately-unfixed RBAC gap
        # before ever returning - that's expected, accepted behavior, not
        # something to chase. Catching bare Exception, not just
        # urllib.error.URLError - a raw socket TimeoutError (confirmed live,
        # crashed the whole collector process) is a DIFFERENT exception
        # class that URLError does not catch.
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                response_body = resp.read().decode("utf-8", errors="replace")
                self._log(log_event, status=resp.status, response=response_body[:500])
                try:
                    decision_state = json.loads(response_body).get("state")
                except Exception:
                    decision_state = None
                if decision_state in ("COMPROMISED", "ISOLATED"):
                    self._apply_throttle_if_needed(decision_state)
        except Exception as exc:
            self._log("report_failed", signal=signal, error=repr(exc))

    def _apply_throttle_if_needed(self, decision_state: str) -> None:
        if self._throttled:
            return
        try:
            apply_cpu_throttle(self.cgroup_path)
            self._throttled = True
            self._throttle_started_monotonic = time.monotonic()
            self._log("cpu_throttle_applied", decision_state=decision_state,
                       quota_millicores=CGROUP_THROTTLE_QUOTA_MILLICORES)
        except Exception as exc:
            self._log("cpu_throttle_apply_failed", error=repr(exc))

    def _check_throttle_release(self) -> None:
        """Called once per tick while throttled (only then - zero overhead
        otherwise). Releases either once the policy engine reports kpimon-go
        back to NORMAL, or on a hard safety timeout regardless - so a
        network hiccup reading /trust-state can never strand kpimon-go
        throttled indefinitely.

        2026-07-19: DWELL_SECONDS_MIRROR was defined (as a "release
        safety-valve") but never actually enforced as a minimum hold before
        this method's early-release check - live testing (R1 attack,
        Session Log Section 22) reproducibly showed cpu_throttle_applied
        immediately followed by cpu_throttle_released in the very same tick,
        because /trust-state's per-xapp "state" field can already read back
        "NORMAL" a moment later even while the underlying signal is still
        actively elevated. Now enforced explicitly below - the throttle must
        hold for at least DWELL_SECONDS_MIRROR before an early release via
        the state-normal path is even considered, matching the dwell
        semantics this constant was always meant to mirror."""
        if not self._throttled:
            return

        elapsed = time.monotonic() - (self._throttle_started_monotonic or time.monotonic())
        if elapsed >= THROTTLE_SAFETY_TIMEOUT_SECONDS:
            self._last_dwell_remaining = None
            self._release_throttle("safety_timeout")
            return

        # 2026-07-25: poll /trust-state every tick while throttled (not just
        # once elapsed >= DWELL_SECONDS_MIRROR, as the release-check below
        # still requires) purely to surface the live isolation dwell
        # countdown for visualization - this endpoint now carries
        # isolation_dwell_seconds_remaining (app.py's csm_state_payload).
        # Kept as a separate try/except from the release check so a fetch
        # failure here never blocks the actual release logic below.
        try:
            req = urllib.request.Request(f"{self.policy_engine_url}/trust-state", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            xapps = payload.get("xapps") or []
            entry = next((x for x in xapps if x.get("xapp") == XAPP_NAME), None)
        except Exception as exc:
            entry = None
            self._log("throttle_release_check_failed", error=repr(exc))

        if entry is not None:
            self._last_dwell_remaining = entry.get("isolation_dwell_seconds_remaining")

        if elapsed < DWELL_SECONDS_MIRROR:
            return

        if entry is not None and entry.get("state") == "NORMAL":
            self._release_throttle("state_normal")

    def _release_throttle(self, reason: str) -> None:
        try:
            release_cpu_throttle(self.cgroup_path)
        except Exception as exc:
            self._log("cpu_throttle_release_failed", error=repr(exc))
            return
        self._throttled = False
        self._throttle_started_monotonic = None
        self._last_dwell_remaining = None
        self._log("cpu_throttle_released", reason=reason)

    def report_suspicious(self, sample: Dict[str, Any], result: Any) -> None:
        """Fully confirmed: UCL exceedance + 6-of-8 + cpu_gate all true
        together - the frozen model's own public_state == "SUSPICIOUS".
        Maps to COMPROMISED in ztx_state_engine.py's resource_anomaly_t2
        branch (not SUSPICIOUS - corrected 2026-07-16, see that branch's
        comment for why)."""
        self._post_signal("resource_anomaly_t2", sample, result, "reported_suspicious")

    def report_elevated(self, sample: Dict[str, Any], result: Any) -> None:
        """Score above WARNING_LIMIT but not yet fully confirmed (i.e. not
        also past UCL with 6-of-8 and cpu_gate). Added 2026-07-16 so the
        agreed 4-state design has a real WL<score<UCL SUSPICIOUS tier,
        separate from the fully-confirmed COMPROMISED tier - the frozen
        model itself never reports this on its own since its own
        public_state is binary. Maps to SUSPICIOUS in ztx_state_engine.py's
        resource_anomaly_t2_elevated branch."""
        self._post_signal("resource_anomaly_t2_elevated", sample, result, "reported_elevated")

    def _write_state_file(self, sample: Dict[str, Any], result: Optional[Any]) -> None:
        """Write the latest tick's result to a shared JSON file, so the
        (separate, display-only) ztx_t2_visualizer pod can show the real
        T2 score/state without duplicating any scoring logic itself - it
        just reads whatever this collector, the actual production scorer,
        last computed. Atomic write (temp file + rename) so the visualizer
        never reads a half-written file.
        """
        state = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "elapsed_s": sample["elapsed_s"],
            "sample_quality": sample["sample_quality"],
            "eligible": sample["eligible"],
            "m1_cpu_millicores": sample["m1_cpu_millicores"],
            "m4_memory_growth_bytes_per_s": sample["m4_memory_growth_bytes_per_s"],
            "m5_network_rx_bytes_per_s": sample["m5_network_rx_bytes_per_s"],
            "m6_network_tx_bytes_per_s": sample["m6_network_tx_bytes_per_s"],
            "ready": result.ready if result is not None else False,
            "public_state": result.public_state if result is not None else "NORMAL",
            "t2_pressure_score": result.v3_pressure_score if result is not None else None,
            # Per-feature normalized excess (0 = at/under the clean-baseline
            # center, higher = further above it) - lets a caller identify WHICH
            # resource dimension is actually elevated (e.g. cpu vs memory-growth)
            # without re-deriving anything, since this is exactly what the
            # frozen model itself computes each tick. Purely read-only exposure.
            "directional_excess": result.directional_excess if result is not None else None,
            "confirmed_upper_6of8": result.confirmed_upper_6of8 if result is not None else None,
            "cpu_gate_hit": result.cpu_gate_hit if result is not None else None,
            # Live counts behind the two booleans above (added 2026-08-25, purely
            # additive - see ScoreResult in ztx_model/streaming.py) so a dashboard
            # can show "5/8 confirmed" / "12/60 cpu-rate" instead of just a flag.
            "upper_hits": result.upper_hits if result is not None else None,
            "upper_window": result.upper_window if result is not None else None,
            "cpu_exceed_hits": result.cpu_exceed_hits if result is not None else None,
            "cpu_exceed_window": result.cpu_exceed_window if result is not None else None,
            "cpu_gate_floor_millicores": self.scorer.spec.cpu_gate_floor,
            "cpu_gate_window_l": self.scorer.spec.cpu_gate_window_l,
            "cpu_gate_rate_r": self.scorer.spec.cpu_gate_rate_r,
            "confirmation_k": self.scorer.spec.confirmation_k,
            "confirmation_l": self.scorer.spec.confirmation_l,
            # Included here so the visualizer never needs its own copy of these constants.
            "warning_limit": WARNING_LIMIT,
            "upper_limit": UPPER_LIMIT,
            "isolation_dwell_seconds_remaining": self._last_dwell_remaining,
            "throttled": self._throttled,
            # ztx-soc-dashboard's app.js already had a "prefer explicit field,
            # else infer" branch for these two exact names - they were never
            # actually emitted, so it always fell back to guessing throttle
            # state from (ready and confirmed and gate). Emit the real values
            # so that branch activates instead of inferring.
            "throttle_active": self._throttled,
            "quota_millicores": CGROUP_THROTTLE_QUOTA_MILLICORES,
            "dwell_seconds_total": DWELL_SECONDS_MIRROR,
            # RIC activity (from :9090/ztx/metrics) - included here so the
            # visualizer can display it WITHOUT polling that endpoint itself.
            # Two independent 1Hz pollers hitting the same endpoint was
            # confirmed live to roughly double kpimon-go's measured network
            # rate, directly inflating the T2 score - this is the fix for
            # that, not a workaround (see session log Section 19).
            "activity": sample.get("activity"),
        }
        try:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            tmp_path = STATE_DIR / ".latest.json.tmp"
            tmp_path.write_text(json.dumps(state), encoding="utf-8")
            tmp_path.replace(STATE_FILE)
        except Exception as exc:
            self._log("state_file_write_failed", error=repr(exc))

    def run_forever(self) -> None:
        self._log("collector_started", pod=self.pod_name, pod_ip=self.pod_ip,
                   cgroup_path=str(self.cgroup_path), policy_engine_url=self.policy_engine_url,
                   interval=self.interval)
        while True:
            tick_start = time.monotonic()

            # This is a monitoring daemon meant to run unattended for the
            # duration of an attack scenario - confirmed live that a single
            # unexpected exception in one tick's processing (a slow HTTP
            # response manifesting as a raw TimeoutError, not the narrower
            # exception type originally caught) killed the entire process,
            # silently ending detection mid-attack. One tick's failure must
            # never take down the whole collector.
            try:
                sample = self.collect_sample()
                if sample is not None:
                    if sample["eligible"]:
                        result = self.scorer.update({
                            "elapsed_s": sample["elapsed_s"],
                            "m1_cpu_millicores": sample["m1_cpu_millicores"],
                            "m4_memory_growth_bytes_per_s": sample["m4_memory_growth_bytes_per_s"],
                            "m5_network_rx_bytes_per_s": sample["m5_network_rx_bytes_per_s"],
                            "m6_network_tx_bytes_per_s": sample["m6_network_tx_bytes_per_s"],
                        })
                        self._log(
                            "tick",
                            elapsed_s=round(sample["elapsed_s"], 3),
                            sample_quality=sample["sample_quality"],
                            m1=sample["m1_cpu_millicores"],
                            m4=sample["m4_memory_growth_bytes_per_s"],
                            m5=sample["m5_network_rx_bytes_per_s"],
                            m6=sample["m6_network_tx_bytes_per_s"],
                            ready=result.ready,
                            public_state=result.public_state,
                            t2_score=result.v3_pressure_score,
                        )
                        self._write_state_file(sample, result)
                        in_startup_grace = (time.monotonic() - self._context_since_monotonic) < STARTUP_GRACE_SECONDS
                        # 2026-07-16: dispatch on score tier, not just the frozen
                        # model's own binary public_state, so a real WL<score<UCL
                        # tier is reported too - see report_elevated()/
                        # report_suspicious() docstrings for the exact mapping.
                        if result.ready and in_startup_grace:
                            self._log("report_suppressed_startup_grace", public_state=result.public_state,
                                       t2_score=result.v3_pressure_score,
                                       seconds_since_context=round(time.monotonic() - self._context_since_monotonic, 1))
                        elif result.ready:
                            if result.public_state == "SUSPICIOUS":
                                self.report_suspicious(sample, result)
                            elif result.v3_pressure_score is not None and result.v3_pressure_score > WARNING_LIMIT:
                                self.report_elevated(sample, result)
                    else:
                        self._log("tick_skipped", elapsed_s=round(sample["elapsed_s"], 3),
                                   sample_quality=sample["sample_quality"])
                        self._write_state_file(sample, None)
            except Exception as exc:
                self._log("tick_error", error=repr(exc))

            # Only ever does anything (an extra GET /trust-state) while a
            # throttle is actively applied - zero overhead the rest of the
            # time. Runs every tick regardless of this tick's own
            # eligibility, so release isn't blocked by an ineligible sample.
            try:
                self._check_throttle_release()
            except Exception as exc:
                self._log("throttle_release_tick_error", error=repr(exc))

            elapsed_processing = time.monotonic() - tick_start
            sleep_for = max(0.0, self.interval - elapsed_processing)
            time.sleep(sleep_for)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_SECONDS, help="Sampling interval in seconds (default 1.0)")
    parser.add_argument("--policy-engine-url", type=str, default=None,
                         help="Base URL of the policy engine, e.g. http://10.x.x.x:5000. "
                              "If omitted, resolved automatically via the zt-xguard-policy-engine Service ClusterIP.")
    args = parser.parse_args()

    policy_engine_url = args.policy_engine_url
    if not policy_engine_url:
        cluster_ip = _run([
            "kubectl", "get", "svc", "zt-xguard-policy-engine", "-n", "zt-xguard",
            "-o", "jsonpath={.spec.clusterIP}",
        ])
        if not cluster_ip:
            raise RuntimeError("could not resolve zt-xguard-policy-engine Service ClusterIP; pass --policy-engine-url explicitly")
        policy_engine_url = f"http://{cluster_ip}:5000"

    collector = KpimonT2Collector(policy_engine_url=policy_engine_url, interval=args.interval)
    collector.run_forever()


if __name__ == "__main__":
    main()
