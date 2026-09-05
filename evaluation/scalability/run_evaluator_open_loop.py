#!/usr/bin/env python3
"""Open-loop scalability test for the deployed ZT-XGuard evaluator.

For N logical xApps, schedule exactly one non-containment evaluation request
per xApp per second. Latency and the one-second deadline are measured from the
scheduled arrival time, so client or server queueing cannot be hidden. The
endpoint executes the deployed decision/evidence path but cannot initiate
containment; every response is validated accordingly.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import random
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NAMESPACE = "zt-xguard"
DEPLOYMENT = "zt-xguard-policy-engine"
SERVICE = "zt-xguard-policy-engine"
PORT = 5000
ALLOWED_STATES = {"NORMAL", "SUSPICIOUS", "COMPROMISED"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    return ordered[lo] if lo == hi else ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def kubectl(*args: str) -> str:
    return subprocess.check_output(["kubectl", *args], text=True, timeout=30).strip()


def deployment_snapshot() -> dict:
    raw = kubectl("-n", NAMESPACE, "get", "pod", "-l", f"app={DEPLOYMENT}", "-o", "json")
    items = json.loads(raw)["items"]
    if len(items) != 1:
        raise RuntimeError(f"expected exactly one evaluator pod, got {len(items)}")
    pod = items[0]
    status = pod["status"]["containerStatuses"][0]
    return {
        "pod": pod["metadata"]["name"],
        "uid": pod["metadata"]["uid"],
        "ready": bool(status.get("ready")),
        "restart_count": int(status.get("restartCount", 0)),
        "image": pod["spec"]["containers"][0]["image"],
        "node": pod["spec"]["nodeName"],
    }


def cgroup_snapshot(pod: str) -> dict:
    command = (
        "cat /sys/fs/cgroup/cpu.stat; "
        "printf 'memory_current '; cat /sys/fs/cgroup/memory.current; "
        "printf 'memory_events '; tr '\\n' ',' </sys/fs/cgroup/memory.events"
    )
    output = kubectl("-n", NAMESPACE, "exec", pod, "--", "sh", "-c", command)
    values: dict[str, int] = {}
    mode = "cpu"
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "memory_current":
            values["memory_current_bytes"] = int(parts[1])
            mode = "events"
        elif parts[0] == "memory_events":
            for entry in " ".join(parts[1:]).strip(",").split(","):
                fields = entry.split()
                if len(fields) == 2:
                    values[f"memory_event_{fields[0]}"] = int(fields[1])
        elif mode == "cpu" and len(parts) == 2:
            values[f"cpu_{parts[0]}"] = int(parts[1])
    required = {"cpu_usage_usec", "cpu_nr_throttled", "cpu_throttled_usec", "memory_current_bytes"}
    if not required <= values.keys():
        raise RuntimeError(f"incomplete cgroup snapshot: {values}")
    return values


def service_url() -> str:
    ip = kubectl("-n", NAMESPACE, "get", "svc", SERVICE, "-o", "jsonpath={.spec.clusterIP}")
    return f"http://{ip}:{PORT}/csm/intent/evaluate"


def validate_response(data: dict, expected_xapp: str) -> tuple[bool, str, str]:
    if data.get("ok") is not True or not isinstance(data.get("result"), dict):
        return False, "invalid_api_envelope", ""
    result = data["result"]
    state = str(result.get("state") or result.get("decision_state") or "").upper()
    if result.get("xapp") != expected_xapp:
        return False, "xapp_identity_mismatch", state
    if state not in ALLOWED_STATES:
        return False, f"invalid_trust_state:{state}", state
    if bool(result.get("containment_required")):
        return False, "unexpected_containment_required", state
    if str(result.get("containment_action") or "NONE").upper() != "NONE":
        return False, "unexpected_containment_action", state
    reasons = result.get("reasons")
    rule_ids = result.get("rule_ids")
    if not isinstance(reasons, list) or not reasons or not isinstance(rule_ids, list) or not rule_ids:
        return False, "missing_machine_readable_reasons", state
    return True, "", state


def request_one(url: str, xapp: str, request_id: str, scheduled_ns: int, timeout: float) -> dict:
    send_ns = time.perf_counter_ns()
    payload = {
        "xapp": xapp,
        "signal": "high_cpu",
        "evidence": {
            "valid_activity": True,
            "synthetic_loadtest": True,
            "namespace": "ricxapp",
            "request_id": request_id,
        },
    }
    req = urllib.request.Request(
        url, data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    code = 0
    error = ""
    state = ""
    response_valid = False
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            code = response.getcode()
            data = json.load(response)
        response_valid, error, state = validate_response(data, xapp)
    except urllib.error.HTTPError as exc:
        code, error = exc.code, f"http_error:{exc.code}"
    except Exception as exc:
        error = f"{type(exc).__name__}:{exc}"
    end_ns = time.perf_counter_ns()
    return {
        "request_id": request_id,
        "xapp": xapp,
        "scheduled_offset_ms": scheduled_ns / 1e6,
        "send_lag_ms": (send_ns - scheduled_ns) / 1e6,
        "service_latency_ms": (end_ns - send_ns) / 1e6,
        "end_to_end_ms": (end_ns - scheduled_ns) / 1e6,
        "deadline_missed": int(end_ns - scheduled_ns > 1_000_000_000),
        "http_code": code,
        "response_valid": int(response_valid),
        "state": state,
        "error": error,
    }


def run_cell(url: str, n: int, repetition: int, duration: int, timeout: float, max_workers: int) -> tuple[dict, list[dict], list[dict]]:
    before_pod = deployment_snapshot()
    if not before_pod["ready"]:
        raise RuntimeError(f"evaluator pod is not ready: {before_pod}")
    before_cgroup = cgroup_snapshot(before_pod["pod"])
    # Excluded warm-up validates the endpoint and establishes connections.
    for i in range(min(10, n)):
        now = time.perf_counter_ns()
        warm = request_one(url, f"scale-n{n:03d}-x{i:03d}", f"warm-n{n}-r{repetition}-{i}", now, timeout)
        if not warm["response_valid"]:
            raise RuntimeError(f"warm-up response invalid: {warm}")
    start_ns = time.perf_counter_ns() + 500_000_000
    submitted_ns = completed_ns = None
    futures = []
    client_cpu_start = time.process_time_ns()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for second in range(duration):
            scheduled_ns = start_ns + second * 1_000_000_000
            delay = (scheduled_ns - time.perf_counter_ns()) / 1e9
            if delay > 0:
                time.sleep(delay)
            for i in range(n):
                request_id = f"n{n}-r{repetition}-s{second:03d}-x{i:03d}"
                xapp = f"scale-n{n:03d}-x{i:03d}"
                futures.append(pool.submit(request_one, url, xapp, request_id, scheduled_ns, timeout))
            if submitted_ns is None:
                submitted_ns = time.perf_counter_ns()
        rows = [future.result() for future in as_completed(futures)]
        completed_ns = time.perf_counter_ns()
    client_cpu_ns = time.process_time_ns() - client_cpu_start
    after_cgroup = cgroup_snapshot(before_pod["pod"])
    after_pod = deployment_snapshot()
    if before_pod["uid"] != after_pod["uid"] or before_pod["restart_count"] != after_pod["restart_count"]:
        raise RuntimeError(f"evaluator restarted during cell: before={before_pod}, after={after_pod}")
    rows.sort(key=lambda row: row["request_id"])
    expected = n * duration
    if len(rows) != expected or len({row["request_id"] for row in rows}) != expected:
        raise RuntimeError(f"request accounting mismatch: expected={expected}, rows={len(rows)}")
    valid = sum(int(row["response_valid"]) for row in rows)
    service = [float(row["service_latency_ms"]) for row in rows]
    end_to_end = [float(row["end_to_end_ms"]) for row in rows]
    send_lag = [float(row["send_lag_ms"]) for row in rows]
    wall_s = (completed_ns - start_ns) / 1e9
    cpu_delta_us = after_cgroup["cpu_usage_usec"] - before_cgroup["cpu_usage_usec"]
    throttled_delta_us = after_cgroup["cpu_throttled_usec"] - before_cgroup["cpu_throttled_usec"]
    summary = {
        "workloads": n,
        "repetition": repetition,
        "duration_s": duration,
        "offered_rate_requests_s": n,
        "expected_requests": expected,
        "observed_requests": len(rows),
        "valid_responses": valid,
        "invalid_responses": expected - valid,
        "error_rate": (expected - valid) / expected,
        "deadline_misses": sum(int(row["deadline_missed"]) for row in rows),
        "deadline_miss_rate": statistics.fmean(int(row["deadline_missed"]) for row in rows),
        "send_lag_p95_ms": percentile(send_lag, 0.95),
        "service_latency_mean_ms": statistics.fmean(service),
        "service_latency_p50_ms": percentile(service, 0.50),
        "service_latency_p95_ms": percentile(service, 0.95),
        "service_latency_p99_ms": percentile(service, 0.99),
        "service_latency_max_ms": max(service),
        "end_to_end_p95_ms": percentile(end_to_end, 0.95),
        "end_to_end_p99_ms": percentile(end_to_end, 0.99),
        "drain_wall_s": wall_s,
        "achieved_completion_rate_requests_s": expected / wall_s,
        "evaluator_cpu_time_s": cpu_delta_us / 1e6,
        "evaluator_mean_cpu_cores": cpu_delta_us / 1e6 / wall_s,
        "evaluator_throttled_time_s": throttled_delta_us / 1e6,
        "evaluator_throttle_events": after_cgroup["cpu_nr_throttled"] - before_cgroup["cpu_nr_throttled"],
        "evaluator_memory_before_bytes": before_cgroup["memory_current_bytes"],
        "evaluator_memory_after_bytes": after_cgroup["memory_current_bytes"],
        "client_cpu_time_s": client_cpu_ns / 1e9,
        "pod_uid": before_pod["uid"],
        "pod_restart_count": before_pod["restart_count"],
    }
    per_xapp = []
    for i in range(n):
        xapp = f"scale-n{n:03d}-x{i:03d}"
        selected = [row for row in rows if row["xapp"] == xapp]
        per_xapp.append({
            "workloads": n, "repetition": repetition, "xapp": xapp,
            "expected_requests": duration, "observed_requests": len(selected),
            "valid_responses": sum(int(row["response_valid"]) for row in selected),
            "deadline_misses": sum(int(row["deadline_missed"]) for row in selected),
            "end_to_end_mean_ms": statistics.fmean(float(row["end_to_end_ms"]) for row in selected),
        })
    return summary, rows, per_xapp


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError(f"refusing to write empty CSV: {path}")
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--levels", nargs="+", type=int, default=[1, 10, 20, 50, 75, 100])
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--duration", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--max-workers", type=int, default=256)
    parser.add_argument("--settle", type=float, default=5.0)
    parser.add_argument("--output")
    args = parser.parse_args()
    if any(n <= 0 for n in args.levels) or args.repetitions <= 0 or args.duration <= 0:
        parser.error("levels, repetitions and duration must be positive")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.output or ROOT / "experiments" / "scalability" / "results" / f"evaluator-{timestamp}")
    out.mkdir(parents=True, exist_ok=False)
    url = service_url()
    pod = deployment_snapshot()
    # Rotate order to reduce systematic time/order bias while retaining all levels in every repetition.
    orders = []
    for rep in range(args.repetitions):
        order = list(args.levels)
        if rep == 1:
            order.reverse()
        elif rep >= 2:
            random.Random(20260807 + rep).shuffle(order)
        orders.append(order)
    manifest = {
        "schema": "zt-xguard-evaluator-open-loop-manifest-v1",
        "created_utc": utc_now(),
        "endpoint": url,
        "endpoint_semantics": "deployed evaluation/evidence path; response must require no containment",
        "workload_model": "one high_cpu evaluation signal per logical xApp per second",
        "claim_boundary": (
            "Measures deployed evaluator and evidence-collection path. It does not measure Falco eBPF capture, "
            "resource-detector scoring, Kubernetes containment, Calico propagation or SPIRE renewal."
        ),
        "levels": args.levels,
        "repetitions": args.repetitions,
        "duration_s_per_cell": args.duration,
        "deadline_ms_from_scheduled_arrival": 1000,
        "execution_orders": orders,
        "signal": "high_cpu",
        "expected_state": "SUSPICIOUS",
        "expected_containment_required": False,
        "pod": pod,
        "python": sys.version,
        "platform": platform.platform(),
        "source_sha256": sha256(Path(__file__)),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    summaries: list[dict] = []
    requests: list[dict] = []
    accounting: list[dict] = []
    for repetition, order in enumerate(orders, 1):
        for n in order:
            summary, rows, per_xapp = run_cell(url, n, repetition, args.duration, args.timeout, args.max_workers)
            summaries.append(summary)
            for row in rows:
                requests.append({"workloads": n, "repetition": repetition, **row})
            accounting.extend(per_xapp)
            print(
                f"N={n:3d} rep={repetition} valid={summary['valid_responses']}/{summary['expected_requests']} "
                f"p95_e2e={summary['end_to_end_p95_ms']:.1f}ms "
                f"deadline_miss={100*summary['deadline_miss_rate']:.2f}% "
                f"cpu={summary['evaluator_mean_cpu_cores']:.3f} cores",
                flush=True,
            )
            time.sleep(args.settle)
    write_csv(out / "evaluator_run_summary.csv", summaries)
    write_csv(out / "evaluator_requests.csv", requests)
    write_csv(out / "evaluator_xapp_accounting.csv", accounting)
    expected_cells = len(args.levels) * args.repetitions
    expected_requests = sum(args.levels) * args.duration * args.repetitions
    if len(summaries) != expected_cells or len(requests) != expected_requests:
        raise RuntimeError("final matrix accounting failed")
    if any(int(row["observed_requests"]) != int(row["expected_requests"]) for row in summaries):
        raise RuntimeError("one or more cells lost request records")
    hashes = []
    for path in sorted(out.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            hashes.append(f"{sha256(path)}  {path.name}")
    (out / "SHA256SUMS").write_text("\n".join(hashes) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
