#!/usr/bin/env python3
"""ZT-XGuard logical resource-detector scalability benchmark.

This benchmark does not claim to create physical xApps. It measures the
canonical workload shape of the deployed resource detector: one independent
stateful StreamingScorer per protected workload, receiving one admissible
telemetry sample per second. Runs are accelerated, but each logical 1 Hz
cycle is timed against its real 1 second processing deadline.

Every (N, repetition) cell executes in a fresh subprocess so detector state,
Python allocator state and process resource counters cannot leak between
cells. Raw per-cycle records and per-workload accounting are retained.
"""
from __future__ import annotations

import argparse
import csv
import gc
import hashlib
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import time
import types
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import yaml


ROOT = Path(__file__).resolve().parents[2]
LEGACY_ENGINE = ROOT / "ztx-control-plane" / "policy-engine"
STEP54 = LEGACY_ENGINE / "ztx_model_artifacts" / "step54"
STEP76 = LEGACY_ENGINE / "ztx_model_artifacts" / "step76"
DEFAULT_TRACE = ROOT / "data" / "diagnostic" / "D4" / (
    "D4-CURRENT-NORMAL-SANITY-V1-1UE-10PPS-20260702T150850Z"
) / "raw_metrics.csv"
FEATURE_COLUMNS = (
    "m1_cpu_millicores",
    "m4_memory_growth_bytes_per_s",
    "m5_network_rx_bytes_per_s",
    "m6_network_tx_bytes_per_s",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def percentile(values: list[float], q: float) -> float:
    if not values:
        raise ValueError("percentile of empty sequence")
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return ordered[lo]
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def rss_bytes() -> int:
    with Path("/proc/self/status").open(encoding="utf-8") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    raise RuntimeError("VmRSS missing from /proc/self/status")


def read_admissible_trace(path: Path) -> tuple[list[dict[str, float]], dict[str, int]]:
    accepted: list[dict[str, float]] = []
    rejected: dict[str, int] = {}
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required = {
            "elapsed_s", "sample_quality", "timing_ok", "metrics_endpoint_ok",
            "resource_counter_reset", "runtime_counter_reset", *FEATURE_COLUMNS,
        }
        missing = sorted(required - set(reader.fieldnames or []))
        if missing:
            raise ValueError(f"trace is missing required columns: {missing}")
        for row in reader:
            reason = None
            if row["sample_quality"] != "ok":
                reason = f"sample_quality:{row['sample_quality']}"
            elif row["timing_ok"] != "1":
                reason = "timing_invalid"
            elif row["metrics_endpoint_ok"] != "1":
                reason = "metrics_endpoint_invalid"
            elif row["resource_counter_reset"] != "0":
                reason = "resource_counter_reset"
            elif row["runtime_counter_reset"] != "0":
                reason = "runtime_counter_reset"
            try:
                numeric = {key: float(row[key]) for key in ("elapsed_s", *FEATURE_COLUMNS)}
                if not all(math.isfinite(value) for value in numeric.values()):
                    reason = reason or "non_finite_scoring_value"
            except (TypeError, ValueError):
                reason = reason or "non_numeric_scoring_value"
                numeric = {}
            if reason:
                rejected[reason] = rejected.get(reason, 0) + 1
            else:
                accepted.append(numeric)
    if len(accepted) < 300:
        raise ValueError(f"only {len(accepted)} admissible samples; at least 300 required")
    elapsed = [r["elapsed_s"] for r in accepted]
    if any(b <= a for a, b in zip(elapsed, elapsed[1:])):
        raise ValueError("accepted trace timestamps are not strictly increasing")
    return accepted, rejected


def load_streaming_types():
    # streaming.py imports pandas only in its artifact loader. The benchmark
    # constructs FrozenDetectorSpec from the same frozen CSV/YAML/JSON files
    # using csv.DictReader, then runs the unmodified StreamingScorer.update().
    # A stub prevents an unavailable local pandas package from blocking that
    # import; no pandas operation is invoked in this benchmark.
    sys.modules.setdefault("pandas", types.ModuleType("pandas"))
    sys.path.insert(0, str(LEGACY_ENGINE))
    from ztx_model.mewma import warmup_steps
    from ztx_model.streaming import FrozenDetectorSpec, StreamingScorer
    return FrozenDetectorSpec, StreamingScorer, warmup_steps


def load_frozen_spec():
    FrozenDetectorSpec, _, warmup_steps = load_streaming_types()
    model = yaml.safe_load((STEP54 / "v3_frozen_model_spec.yaml").read_text(encoding="utf-8"))
    with (STEP54 / "v3_effective_center_scale.csv").open(newline="", encoding="utf-8") as f:
        params = {row["feature_id"]: row for row in csv.DictReader(f)}
    feature_ids = list(model["features"])
    with (STEP54 / "v3_pressure_state_precision.csv").open(newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    precision_names = rows[0][1:]
    if precision_names != feature_ids or [row[0] for row in rows[1:]] != feature_ids:
        raise ValueError("precision matrix feature order does not match frozen model")
    precision = np.asarray([[float(v) for v in row[1:]] for row in rows[1:]], dtype=float)
    gate = json.loads((STEP76 / "v5_frozen_gate_manifest.json").read_text(encoding="utf-8"))
    if gate["decision_gates"] != ["cpu"]:
        raise ValueError(f"unexpected decision gates: {gate['decision_gates']}")
    cpu = gate["gates"]["cpu"]
    return FrozenDetectorSpec(
        feature_ids=feature_ids,
        columns=[params[k]["column"] for k in feature_ids],
        transform_names=[params[k]["selected_transform"] for k in feature_ids],
        transform_lambdas=[None] * len(feature_ids),
        centers=np.asarray([float(params[k]["center"]) for k in feature_ids]),
        effective_scales=np.asarray([float(params[k]["effective_scale"]) for k in feature_ids]),
        precision=precision,
        window_seconds=int(model["window_seconds"]),
        lambda_value=float(model["lambda_value"]),
        warmup_states=warmup_steps(float(model["lambda_value"])),
        upper_control_limit=float(model["upper_limit"]),
        confirmation_l=8,
        confirmation_k=6,
        cpu_column="m1_cpu_millicores",
        cpu_gate_floor=float(cpu["per_sample_floor"]),
        cpu_gate_window_l=int(cpu["window_l"]),
        cpu_gate_rate_r=float(cpu["rate_r"]),
    )


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError(f"refusing to write empty CSV: {path}")
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def worker(args: argparse.Namespace) -> int:
    trace, rejected = read_admissible_trace(Path(args.trace))
    spec = load_frozen_spec()
    _, StreamingScorer, _ = load_streaming_types()
    scorers = [StreamingScorer(spec=spec) for _ in range(args.workloads)]
    rng = random.Random(args.seed)
    offsets = [rng.randrange(0, len(trace) - args.ticks) for _ in scorers]
    counts = [{"updates": 0, "ready": 0, "normal": 0, "suspicious": 0} for _ in scorers]
    gc.collect()
    start_rss = rss_bytes()
    start_cpu = time.process_time_ns()
    start_wall = time.perf_counter_ns()
    cycles: list[dict] = []
    order = list(range(args.workloads))
    for tick in range(args.ticks):
        rng.shuffle(order)
        cycle_start = time.perf_counter_ns()
        ready = suspicious = 0
        score_checksum = 0.0
        for index in order:
            sample = dict(trace[offsets[index] + tick])
            sample["elapsed_s"] = float(tick + 1)
            result = scorers[index].update(sample)
            item = counts[index]
            item["updates"] += 1
            if result.ready:
                ready += 1
                item["ready"] += 1
            item[result.public_state.lower()] += 1
            suspicious += int(result.public_state == "SUSPICIOUS")
            if result.v3_pressure_score is not None:
                score_checksum += result.v3_pressure_score
        cycle_ns = time.perf_counter_ns() - cycle_start
        cycles.append({
            "workloads": args.workloads,
            "repetition": args.repetition,
            "seed": args.seed,
            "logical_second": tick + 1,
            "updates": args.workloads,
            "ready_outputs": ready,
            "suspicious_outputs": suspicious,
            "cycle_latency_ms": cycle_ns / 1e6,
            "deadline_ms": 1000.0,
            "deadline_missed": int(cycle_ns > 1_000_000_000),
            "score_checksum": f"{score_checksum:.12f}",
        })
    wall_ns = time.perf_counter_ns() - start_wall
    cpu_ns = time.process_time_ns() - start_cpu
    end_rss = rss_bytes()
    latencies = [float(row["cycle_latency_ms"]) for row in cycles]
    accounting = []
    for i, item in enumerate(counts):
        accounting.append({
            "workloads": args.workloads,
            "repetition": args.repetition,
            "virtual_xapp_id": f"virtual-xapp-{i:03d}",
            **item,
        })
    expected = args.workloads * args.ticks
    observed = sum(row["updates"] for row in accounting)
    if observed != expected or any(row["updates"] != args.ticks for row in accounting):
        raise RuntimeError(f"accounting mismatch: expected={expected}, observed={observed}")
    result = {
        "schema": "zt-xguard-detector-capacity-worker-v1",
        "started_utc": args.started_utc,
        "finished_utc": utc_now(),
        "workloads": args.workloads,
        "repetition": args.repetition,
        "seed": args.seed,
        "ticks": args.ticks,
        "expected_updates": expected,
        "observed_updates": observed,
        "trace_accepted_rows": len(trace),
        "trace_rejected": rejected,
        "wall_time_s": wall_ns / 1e9,
        "cpu_time_s": cpu_ns / 1e9,
        "throughput_updates_s": expected / (wall_ns / 1e9),
        "cpu_utilization_one_core_pct": 100.0 * cpu_ns / wall_ns,
        "rss_start_bytes": start_rss,
        "rss_end_bytes": end_rss,
        "rss_delta_bytes": end_rss - start_rss,
        "cycle_latency_mean_ms": statistics.fmean(latencies),
        "cycle_latency_median_ms": statistics.median(latencies),
        "cycle_latency_p95_ms": percentile(latencies, 0.95),
        "cycle_latency_p99_ms": percentile(latencies, 0.99),
        "cycle_latency_max_ms": max(latencies),
        "deadline_misses": sum(int(row["deadline_missed"]) for row in cycles),
        "deadline_miss_rate": statistics.fmean(int(row["deadline_missed"]) for row in cycles),
        "cycles": cycles,
        "accounting": accounting,
    }
    Path(args.worker_output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


def parent(args: argparse.Namespace) -> int:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.output or ROOT / "experiments" / "scalability" / "results" / timestamp)
    out.mkdir(parents=True, exist_ok=False)
    trace = Path(args.trace).resolve()
    accepted, rejected = read_admissible_trace(trace)
    manifest = {
        "schema": "zt-xguard-detector-capacity-manifest-v1",
        "created_utc": utc_now(),
        "benchmark": "independent stateful resource-detector workflows",
        "claim_boundary": (
            "Accelerated logical-workflow capacity benchmark; it does not represent physical pods, "
            "Falco eBPF load, Kubernetes containment, Calico propagation or SPIRE renewal load."
        ),
        "levels": args.levels,
        "repetitions": args.repetitions,
        "ticks_per_workload": args.ticks,
        "logical_input_rate_hz_per_workload": 1,
        "deadline_ms_per_logical_cycle": 1000,
        "trace": str(trace.relative_to(ROOT)),
        "trace_sha256": sha256(trace),
        "trace_total_rows": len(accepted) + sum(rejected.values()),
        "trace_accepted_rows": len(accepted),
        "trace_rejected_by_reason": rejected,
        "admissibility_predicate": {
            "sample_quality": "ok",
            "timing_ok": "1",
            "metrics_endpoint_ok": "1",
            "resource_counter_reset": "0",
            "runtime_counter_reset": "0",
            "scoring_features": "finite numeric values",
        },
        "model_artifacts": {
            str(p.relative_to(ROOT)): sha256(p) for p in (
                STEP54 / "v3_frozen_model_spec.yaml",
                STEP54 / "v3_effective_center_scale.csv",
                STEP54 / "v3_pressure_state_precision.csv",
                STEP76 / "v5_frozen_gate_manifest.json",
            )
        },
        "python": sys.version,
        "platform": platform.platform(),
        "numpy": np.__version__,
        "source_sha256": sha256(Path(__file__)),
        "run_isolation": "fresh subprocess for every (N, repetition) cell",
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    summaries: list[dict] = []
    cycles: list[dict] = []
    accounting: list[dict] = []
    for n in args.levels:
        for repetition in range(1, args.repetitions + 1):
            seed = args.base_seed + n * 1000 + repetition
            worker_file = out / f"worker_n{n}_r{repetition}.json"
            command = [
                sys.executable, str(Path(__file__).resolve()), "--worker",
                "--workloads", str(n), "--repetition", str(repetition),
                "--ticks", str(args.ticks), "--seed", str(seed),
                "--trace", str(trace), "--worker-output", str(worker_file),
                "--started-utc", utc_now(),
            ]
            subprocess.run(command, cwd=ROOT, check=True)
            result = json.loads(worker_file.read_text(encoding="utf-8"))
            cycles.extend(result.pop("cycles"))
            accounting.extend(result.pop("accounting"))
            result.pop("trace_rejected", None)
            summaries.append(result)
    write_csv(out / "detector_run_summary.csv", summaries)
    write_csv(out / "detector_cycles.csv", cycles)
    write_csv(out / "detector_workload_accounting.csv", accounting)
    expected_cells = len(args.levels) * args.repetitions
    if len(summaries) != expected_cells:
        raise RuntimeError(f"missing cells: expected {expected_cells}, got {len(summaries)}")
    if any(int(row["deadline_misses"]) != 0 for row in summaries):
        print("WARNING: one or more logical 1 Hz deadlines were missed", file=sys.stderr)
    hashes = []
    for path in sorted(out.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            hashes.append(f"{sha256(path)}  {path.name}")
    (out / "SHA256SUMS").write_text("\n".join(hashes) + "\n", encoding="utf-8")
    print(out)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--levels", nargs="+", type=int, default=[1, 10, 20, 50, 75, 100])
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--ticks", type=int, default=300)
    parser.add_argument("--base-seed", type=int, default=20260807)
    parser.add_argument("--trace", default=str(DEFAULT_TRACE))
    parser.add_argument("--output")
    parser.add_argument("--workloads", type=int)
    parser.add_argument("--repetition", type=int)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--worker-output")
    parser.add_argument("--started-utc")
    args = parser.parse_args()
    if args.worker and not all(v is not None for v in (
        args.workloads, args.repetition, args.seed, args.worker_output, args.started_utc,
    )):
        parser.error("worker mode requires workloads, repetition, seed, worker-output and started-utc")
    if args.ticks <= 0 or args.repetitions <= 0 or any(n <= 0 for n in args.levels):
        parser.error("levels, repetitions and ticks must all be positive")
    return args


if __name__ == "__main__":
    parsed = parse_args()
    raise SystemExit(worker(parsed) if parsed.worker else parent(parsed))
