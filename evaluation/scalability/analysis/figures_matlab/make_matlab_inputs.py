#!/usr/bin/env python3
"""Emit tidy, graph-ready CSVs for the three scalability figures.

Reads the canonical result files (Experiment 1/2/3) and writes one flat CSV per
figure into this directory, so the accompanying MATLAB .m scripts can redraw the
graphs without touching the raw per-cycle / per-request data.
"""
from __future__ import annotations

import csv
import json
import math
import statistics
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parents[1] / "results"
DET = RESULTS / "exp1-detector-20260807T171528Z" / "detector_run_summary.csv"
EVAL = RESULTS / "exp2-evaluator-20260807T172001Z" / "evaluator_run_summary.csv"
PHYS = RESULTS / "exp3-realxapps-20260807T175932Z" / "real_concurrent_summary.json"


def wilson(successes: int, n: int, z: float = 1.959963984540054):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = successes / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = (z / d) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (p, max(0.0, c - h), min(1.0, c + h))


def detector_csv():
    rows = {}
    with DET.open() as fh:
        for r in csv.DictReader(fh):
            rows.setdefault(int(r["workloads"]), []).append(r)
    out = HERE / "detector_scaling.csv"
    with out.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["N_contexts", "updates", "mean_ms", "p95_ms", "max_ms",
                    "deadline_misses"])
        for n in sorted(rows):
            reps = rows[n]
            w.writerow([
                n,
                sum(int(x["observed_updates"]) for x in reps),
                round(statistics.mean(float(x["cycle_latency_mean_ms"]) for x in reps), 4),
                round(statistics.mean(float(x["cycle_latency_p95_ms"]) for x in reps), 4),
                round(max(float(x["cycle_latency_max_ms"]) for x in reps), 4),
                sum(int(x["deadline_misses"]) for x in reps),
            ])
    print("wrote", out)


def evaluator_csv():
    rows = {}
    with EVAL.open() as fh:
        for r in csv.DictReader(fh):
            rows.setdefault(int(r["offered_rate_requests_s"]), []).append(r)
    out = HERE / "evaluator_scaling.csv"
    with out.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["offered_rate_eval_s", "miss_rate_pct", "service_p95_ms",
                    "cpu_cores"])
        for rate in sorted(rows):
            reps = rows[rate]
            w.writerow([
                rate,
                round(statistics.mean(float(x["deadline_miss_rate"]) for x in reps) * 100, 3),
                round(statistics.mean(float(x["service_latency_p95_ms"]) for x in reps), 1),
                round(statistics.mean(float(x["evaluator_mean_cpu_cores"]) for x in reps), 3),
            ])
    print("wrote", out)


def physical_csv():
    d = json.loads(PHYS.read_text())
    out = HERE / "physical_scaling.csv"
    with out.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["K", "attempts", "successes", "wilson_lo", "wilson_hi",
                    "net_med_s", "net_p95_s", "net_max_s",
                    "service_med_s", "identity_med_s", "packetfilter_med_s"])
        for k in sorted(d["levels"], key=int):
            lvl = d["levels"][k]
            _, lo, hi = wilson(lvl["successes"], lvl["attempts"])
            nu = lvl["network_unreachable_ms"]
            w.writerow([
                k, lvl["attempts"], lvl["successes"], round(lo, 4), round(hi, 4),
                round(nu["median"] / 1000, 3), round(nu["p95"] / 1000, 3),
                round(nu["max"] / 1000, 3),
                round(lvl["service_isolated_ms"]["median"] / 1000, 3),
                round(lvl["identity_disabled_ms"]["median"] / 1000, 3),
                round(lvl["direct_packet_filter_ms"]["median"] / 1000, 3),
            ])
    print("wrote", out)


if __name__ == "__main__":
    detector_csv()
    evaluator_csv()
    physical_csv()
