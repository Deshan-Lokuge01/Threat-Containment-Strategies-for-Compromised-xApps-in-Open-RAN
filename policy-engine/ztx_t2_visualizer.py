#!/usr/bin/env python3
"""
ZT-XGuard live raw-metrics visualizer for kpimon-go.

Display-only - no scoring, no reporting anywhere. Prints a colored,
continuously-updating table of all 11 PRIMARY_METRIC_COLUMNS to stdout,
once per second, so it can be watched via `kubectl logs -f` / k9s like any
other live telemetry view in this cluster.

Does NOT poll kpimon-go's :9090/ztx/metrics endpoint itself - confirmed
live (2026-07-15) that a second independent 1Hz poller hitting the same
endpoint as ztx_t2_collector.py roughly doubled kpimon-go's measured
network rate, directly and artificially inflating the T2 score. RIC
activity display is read from the collector's own shared state file
instead - there is exactly one poller of that endpoint, ever.

Runs as its own dedicated pod (deliberately NOT a sidecar on the
policy-engine Deployment) with hostPID: true and a read-only hostPath
mount of /sys/fs/cgroup, since reading per-container CPU/memory/network/
filesystem counters requires host-level access the policy-engine's own
ServiceAccount does not have (see ZTXGUARD_SESSION_LOG_20260710.md
Section 19). Isolated into its own pod so this elevated access doesn't
extend to a component with a broader blast radius.

Stock python:3.11-slim image, no pip installs - resolves kpimon-go's pod
IP/container ID via the K8s API directly (stdlib urllib + the pod's own
mounted ServiceAccount token), then finds the matching host PID by
scanning /proc/*/cgroup for that container ID (visible via hostPID,
no crictl/containerd socket needed).
"""
from __future__ import annotations

import json
import os
import ssl
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

NAMESPACE = "ricxapp"
POD_LABEL_SELECTOR = "app=ricxapp-kpimon-go"
CONTAINER_NAME = "kpimon-go"
NET_IFACE = "eth0"
INTERVAL_SECONDS = 1.0

# Written by ztx_t2_collector.py (the real, production scorer) via a
# hostPath mount of the same directory - display-only, this pod never
# computes a T2 score itself.
T2_STATE_FILE = Path("/var/lib/ztx-t2-state/latest.json")

SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
RED = "\033[31m"
MAGENTA = "\033[35m"
DIM = "\033[2m"


def _k8s_api_get(path: str) -> Any:
    token = (SA_DIR / "token").read_text().strip()
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ["KUBERNETES_SERVICE_PORT"]
    url = f"https://{host}:{port}{path}"
    ctx = ssl.create_default_context(cafile=str(SA_DIR / "ca.crt"))
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def resolve_pod_context() -> Dict[str, Any]:
    pods = _k8s_api_get(f"/api/v1/namespaces/{NAMESPACE}/pods?labelSelector={POD_LABEL_SELECTOR}")
    items = pods.get("items") or []
    if not items:
        raise RuntimeError(f"no pod found for -l {POD_LABEL_SELECTOR} in {NAMESPACE}")
    pod = items[0]
    pod_name = pod["metadata"]["name"]
    pod_ip = pod.get("status", {}).get("podIP")

    container_id = None
    for cs in pod.get("status", {}).get("containerStatuses", []):
        if cs.get("name") == CONTAINER_NAME:
            container_id = cs.get("containerID", "").split("://", 1)[-1]
            break
    if not container_id:
        raise RuntimeError(f"could not resolve containerID for {CONTAINER_NAME} in pod {pod_name}")

    host_pid = None
    for proc_dir in Path("/proc").iterdir():
        if not proc_dir.name.isdigit():
            continue
        try:
            cgroup_text = (proc_dir / "cgroup").read_text()
        except Exception:
            continue
        if container_id in cgroup_text:
            host_pid = int(proc_dir.name)
            break
    if host_pid is None:
        raise RuntimeError(f"could not find a /proc/*/cgroup entry matching container {container_id}")

    # NOT derived from /proc/<host_pid>/cgroup's relative path field -
    # that path is relative to the READING process's own cgroup namespace,
    # which differs between this pod and kpimon-go's even though hostPID
    # shares the PID namespace (cgroup namespace is separate). Confirmed
    # live: that approach produced "/sys/fs/cgroup/../../../kubepods-..."
    # (wrong - "up 3 then back down" from THIS pod's own deep cgroup path,
    # not an absolute path). Search the bind-mounted host cgroup tree
    # directly for the container ID instead - that's namespace-independent
    # since it's a plain filesystem walk over what's bind-mounted.
    cgroup_path = None
    cgroup_suffix = f"cri-containerd-{container_id}.scope"
    for candidate in Path("/sys/fs/cgroup").rglob(cgroup_suffix):
        if candidate.is_dir():
            cgroup_path = candidate
            break
    if cgroup_path is None:
        raise RuntimeError(f"could not find {cgroup_suffix} under /sys/fs/cgroup")

    return {
        "pod_name": pod_name,
        "pod_ip": pod_ip,
        "container_id": container_id,
        "host_pid": host_pid,
        "cgroup_path": cgroup_path,
    }


def read_raw_metrics(cgroup_path: Path, host_pid: int) -> Dict[str, Optional[float]]:
    def _read(p: Path) -> Optional[str]:
        try:
            return p.read_text()
        except Exception:
            return None

    out: Dict[str, Optional[float]] = {}

    cpu_stat = _read(cgroup_path / "cpu.stat") or ""
    for line in cpu_stat.splitlines():
        if line.startswith("usage_usec "):
            out["cpu_usage_usec_total"] = float(line.split()[1])
        elif line.startswith("nr_periods "):
            out["cpu_nr_periods_total"] = float(line.split()[1])
        elif line.startswith("nr_throttled "):
            out["cpu_nr_throttled_total"] = float(line.split()[1])

    mem_current = _read(cgroup_path / "memory.current")
    out["memory_current_bytes"] = float(mem_current) if mem_current else None

    mem_stat = _read(cgroup_path / "memory.stat") or ""
    for line in mem_stat.splitlines():
        if line.startswith("inactive_file "):
            out["memory_inactive_file_bytes"] = float(line.split()[1])

    io_stat = _read(cgroup_path / "io.stat") or ""
    read_bytes_total = 0.0
    write_bytes_total = 0.0
    for line in io_stat.splitlines():
        for token in line.split()[1:]:
            if token.startswith("rbytes="):
                read_bytes_total += float(token.split("=", 1)[1])
            elif token.startswith("wbytes="):
                write_bytes_total += float(token.split("=", 1)[1])
    if io_stat:
        out["filesystem_read_bytes_total"] = read_bytes_total
        out["filesystem_write_bytes_total"] = write_bytes_total

    net_dev = _read(Path(f"/proc/{host_pid}/net/dev")) or ""
    for line in net_dev.splitlines():
        line = line.strip()
        if line.startswith(f"{NET_IFACE}:"):
            fields = line.split(":", 1)[1].split()
            out["network_rx_bytes_total"] = float(fields[0])
            out["network_tx_bytes_total"] = float(fields[8])

    fd_dir = Path(f"/proc/{host_pid}/fd")
    try:
        out["fd_count"] = float(sum(1 for _ in fd_dir.iterdir()))
    except Exception:
        out["fd_count"] = None

    status_text = _read(Path(f"/proc/{host_pid}/status")) or ""
    for line in status_text.splitlines():
        if line.startswith("Threads:"):
            out["thread_count"] = float(line.split()[1])

    net_tcp = _read(Path(f"/proc/{host_pid}/net/tcp")) or ""
    net_udp = _read(Path(f"/proc/{host_pid}/net/udp")) or ""
    socket_count = max(0, len(net_tcp.splitlines()) - 1) + max(0, len(net_udp.splitlines()) - 1)
    out["socket_count"] = float(socket_count)

    return out


def read_t2_state() -> Optional[Dict[str, Any]]:
    try:
        return json.loads(T2_STATE_FILE.read_text())
    except Exception:
        return None


def fmt(value: Optional[float], unit: str = "", decimals: int = 2) -> str:
    if value is None:
        return f"{DIM}n/a{RESET}"
    return f"{GREEN}{value:,.{decimals}f}{RESET}{unit}"


def render_t2_section(t2_state: Optional[Dict[str, Any]]) -> list:
    lines = [f"  {BOLD}{MAGENTA}T2 / MEWMA RESOURCE-PRESSURE SCORE  (ztx_t2_collector.py){RESET}",
             f"  {'-' * 74}"]

    if t2_state is None:
        lines.append(f"  {DIM}no data yet - is ztx_t2_collector.py running?{RESET}")
        lines.append(f"  {DIM}(sudo ./.t2-collector-venv/bin/python3 ztx_t2_collector.py on the node){RESET}")
        lines.append("")
        return lines

    wl = t2_state.get("warning_limit")
    ucl = t2_state.get("upper_limit")
    score = t2_state.get("t2_pressure_score")
    ready = t2_state.get("ready")
    public_state = t2_state.get("public_state") or "NORMAL"
    confirmed = t2_state.get("confirmed_upper_6of8")
    cpu_gate = t2_state.get("cpu_gate_hit")

    def badge(flag: Optional[bool], on_label: str, off_label: str) -> str:
        if flag is None:
            return f"{DIM}n/a{RESET}"
        if flag:
            return f"{BOLD}{RED} {on_label} {RESET}"
        return f"{DIM} {off_label} {RESET}"

    if not ready:
        lines.append(f"  {DIM}warming up - {t2_state.get('sample_quality', '?')} (elapsed_s={t2_state.get('elapsed_s', 0):.1f}){RESET}")
    elif score is None:
        lines.append(f"  {DIM}no score yet{RESET}")
    else:
        # 2026-07-16: display the POLICY-LEVEL 3-tier state (what
        # ztx_state_engine.py actually decides), not the frozen model's own
        # raw binary public_state directly - that binary field only flips
        # away from "NORMAL" once fully confirmed (past UCL + 6-of-8 +
        # cpu_gate), so a score sitting between WL and UCL always showed
        # "NORMAL" here even after the collector started reporting a real
        # WL-crossing SUSPICIOUS signal (resource_anomaly_t2_elevated) to
        # the policy engine - display-only fix, does not touch collector
        # signal-dispatch logic or policy engine decision logic, both of
        # which were already correct.
        if public_state == "SUSPICIOUS":
            policy_state, color = "COMPROMISED", RED
        elif wl is not None and score > wl:
            policy_state, color = "SUSPICIOUS", YELLOW
        else:
            policy_state, color = "NORMAL", GREEN
        bar_width = 40
        filled = min(bar_width, int((score / ucl) * bar_width)) if ucl else 0
        bar = "#" * filled + "." * (bar_width - filled)
        lines.append(f"  {'T2 score':<18}{color}{score:>10.3f}{RESET}   [{color}{bar}{RESET}]")
        lines.append(f"  {'WL (warning)':<18}{YELLOW}{wl:>10.3f}{RESET}      {'UCL (upper)':<12}{RED}{ucl:>8.3f}{RESET}")
        lines.append(f"  {'state':<18}{color}{BOLD}{policy_state:>10}{RESET}  {DIM}(raw model verdict: {public_state}){RESET}")
        lines.append(f"  {'6-of-8 confirmed':<18}{badge(confirmed, 'CONFIRMED', 'not yet')}"
                      f"   {'cpu_gate_hit':<14}{badge(cpu_gate, 'GATE HIT', 'below rate')}")
    lines.append(f"  {DIM}last update: {t2_state.get('time', '?')}{RESET}")
    lines.extend(render_dwell_section(t2_state))
    lines.append("")
    return lines


def render_dwell_section(t2_state: Dict[str, Any]) -> list:
    """Isolation-dwell countdown - the 30s policy window between an xapp
    first reaching COMPROMISED (T2-driven, DWELL_30S timing) and the actual
    network-isolation action. Reads isolation_dwell_seconds_remaining, which
    ztx_isolation_manager.py tracks server-side and app.py's csm_state_payload
    now surfaces live via /trust-state - this collector polls that once per
    tick while its own cgroup throttle is applied (see
    _check_throttle_release) and writes it into the same state file this
    visualizer already reads, so no extra network path is needed here."""
    lines = [f"  {BOLD}{MAGENTA}ISOLATION DWELL (COMPROMISED -> ISOLATED, 30s policy window){RESET}",
             f"  {'-' * 74}"]

    throttled = t2_state.get("throttled")
    remaining = t2_state.get("isolation_dwell_seconds_remaining")
    total = t2_state.get("dwell_seconds_total") or 30.0

    if not throttled and remaining is None:
        lines.append(f"  {DIM}no pending dwell - xapp not currently COMPROMISED{RESET}")
        lines.append("")
        return lines

    if throttled:
        lines.append(f"  {RED}{BOLD} CPU THROTTLE ACTIVE {RESET}  {DIM}(immediate, cgroup-level - applied on detection, no dwell){RESET}")

    if remaining is None:
        # Throttled but the last /trust-state poll saw no dwell remaining -
        # either isolation already completed or the xapp cleared to NORMAL.
        lines.append(f"  {DIM}dwell: n/a (isolated, or awaiting next poll){RESET}")
    else:
        elapsed = max(0.0, total - remaining)
        bar_width = 40
        filled = min(bar_width, int((elapsed / total) * bar_width)) if total else 0
        bar = "#" * filled + "." * (bar_width - filled)
        dcolor = RED if remaining <= 5 else YELLOW
        lines.append(f"  {'dwell elapsed':<18}{dcolor}{elapsed:>6.1f}s / {total:.0f}s{RESET}   [{dcolor}{bar}{RESET}]")
        lines.append(f"  {'isolates in':<18}{dcolor}{BOLD}{remaining:>6.1f}s{RESET}  {DIM}(network isolation applies once this reaches 0){RESET}")
    lines.append("")
    return lines


def render(ctx: Dict[str, Any], prev: Optional[Dict[str, float]], cur: Dict[str, float],
           dt: Optional[float], t2_state: Optional[Dict[str, Any]]) -> str:
    lines = []
    lines.append(f"{BOLD}{CYAN}{'=' * 78}{RESET}")
    lines.append(f"{BOLD}{CYAN}  ZT-XGuard T2 Detector - Live Raw Metrics (kpimon-go){RESET}")
    lines.append(f"{BOLD}{CYAN}{'=' * 78}{RESET}")
    lines.append(f"  {YELLOW}Pod:{RESET} {ctx['pod_name']}   {YELLOW}Host PID:{RESET} {ctx['host_pid']}   {YELLOW}Time:{RESET} {time.strftime('%H:%M:%S')}")
    lines.append("")

    lines.extend(render_t2_section(t2_state))

    def rate(key_total: str) -> Optional[float]:
        if prev is None or dt is None or dt <= 0:
            return None
        a, b = prev.get(key_total), cur.get(key_total)
        if a is None or b is None:
            return None
        return (b - a) / dt

    m1 = None
    if prev is not None and dt is not None and dt > 0:
        a, b = prev.get("cpu_usage_usec_total"), cur.get("cpu_usage_usec_total")
        if a is not None and b is not None:
            m1 = (b - a) / dt / 1000.0

    m2 = None
    if prev is not None:
        dp, dt_ = cur.get("cpu_nr_throttled_total", 0) - prev.get("cpu_nr_throttled_total", 0), \
                   cur.get("cpu_nr_periods_total", 0) - prev.get("cpu_nr_periods_total", 0)
        if dt_:
            m2 = dp / dt_

    m3 = None
    if cur.get("memory_current_bytes") is not None and cur.get("memory_inactive_file_bytes") is not None:
        m3 = cur["memory_current_bytes"] - cur["memory_inactive_file_bytes"]

    m5 = rate("network_rx_bytes_total")
    m6 = rate("network_tx_bytes_total")
    m7 = rate("filesystem_read_bytes_total")
    m8 = rate("filesystem_write_bytes_total")

    lines.append(f"  {BOLD}{MAGENTA}RESOURCE METRICS{RESET}")
    lines.append(f"  {'-' * 74}")
    lines.append(f"  {'m1  cpu_millicores':<32}{fmt(m1, ' mcpu')}")
    lines.append(f"  {'m2  cpu_throttle_ratio':<32}{fmt(m2, '', 4)}")
    lines.append(f"  {'m3  memory_working_set_bytes':<32}{fmt(m3, ' B', 0)}")
    lines.append(f"  {'m4  memory_growth_bytes_per_s':<32}{DIM}see T2 section above (30s OLS window){RESET}")
    lines.append(f"  {'m5  network_rx_bytes_per_s':<32}{fmt(m5, ' B/s')}")
    lines.append(f"  {'m6  network_tx_bytes_per_s':<32}{fmt(m6, ' B/s')}")
    lines.append(f"  {'m7  filesystem_read_bytes_per_s':<32}{fmt(m7, ' B/s')}")
    lines.append(f"  {'m8  filesystem_write_bytes_per_s':<32}{fmt(m8, ' B/s')}")
    lines.append(f"  {'m9  socket_count':<32}{fmt(cur.get('socket_count'), '', 0)}")
    lines.append(f"  {'m10 fd_count':<32}{fmt(cur.get('fd_count'), '', 0)}")
    lines.append(f"  {'m11 thread_count':<32}{fmt(cur.get('thread_count'), '', 0)}")
    lines.append("")

    lines.append(f"  {BOLD}{MAGENTA}RIC ACTIVITY (:9090/ztx/metrics, via ztx_t2_collector.py){RESET}")
    lines.append(f"  {'-' * 74}")
    activity = (t2_state or {}).get("activity") or {}
    if activity:
        lines.append(f"  {'heartbeat_total':<32}{fmt(activity.get('heartbeat_total'), '', 0)}")
        lines.append(f"  {'work_units_processed':<32}{fmt(activity.get('work_units_processed'), '', 0)}")
        lines.append(f"  {'uptime_seconds':<32}{fmt(activity.get('uptime_seconds'), ' s', 0)}")
    else:
        lines.append(f"  {DIM}no data yet - is ztx_t2_collector.py running?{RESET}")
    lines.append(f"  {DIM}this pod does not poll kpimon-go's endpoint itself - reading a second")
    lines.append(f"  {DIM}poller into the same endpoint was confirmed to distort the T2 score.{RESET}")
    lines.append(f"{BOLD}{CYAN}{'=' * 78}{RESET}")
    return "\n".join(lines)


def main() -> None:
    ctx = resolve_pod_context()
    print(f"{BOLD}{GREEN}Resolved kpimon-go context: {json.dumps({k: str(v) for k, v in ctx.items()})}{RESET}", flush=True)

    prev: Optional[Dict[str, float]] = None
    prev_time: Optional[float] = None

    while True:
        # kpimon-go's pod/container can restart independently of this
        # viewer (confirmed live - a restart invalidates the cgroup path/
        # host PID resolved at startup, since the new container gets a new
        # containerd scope). Re-resolve whenever the cached path stops
        # existing, rather than resolving once and silently going stale.
        if not ctx["cgroup_path"].exists():
            print(f"{BOLD}{YELLOW}cgroup path gone (kpimon-go likely restarted) - re-resolving...{RESET}", flush=True)
            try:
                ctx = resolve_pod_context()
                print(f"{BOLD}{GREEN}Re-resolved kpimon-go context: {json.dumps({k: str(v) for k, v in ctx.items()})}{RESET}", flush=True)
                prev = None
                prev_time = None
            except Exception as exc:
                print(f"{BOLD}{RED}re-resolve failed: {exc!r}{RESET}", flush=True)
                time.sleep(INTERVAL_SECONDS)
                continue

        now = time.monotonic()
        cur = read_raw_metrics(ctx["cgroup_path"], ctx["host_pid"])
        t2_state = read_t2_state()
        dt = (now - prev_time) if prev_time is not None else None

        # clear screen + move cursor home so this reads as a live-updating
        # dashboard in a log tail, not a scroll of stacked frames
        print("\033[2J\033[H" + render(ctx, prev, cur, dt, t2_state), flush=True)

        prev = cur
        prev_time = now
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
