#!/usr/bin/env python3
"""Assemble ONE self-contained folder of graph-ready CSVs for MATLAB.

Reads the v2 campaign result dirs and writes flat, tidy CSVs (one row per data
point) into scalability_matlab_package/ so the accompanying .m scripts can
redraw every scalability figure on a machine that has MATLAB.
"""
from __future__ import annotations
import csv
import json
import math
import statistics as st
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
CAMP = HERE / "results" / "campaign-20260808T051632Z"
PKG = HERE / "scalability_matlab_package"
PKG.mkdir(exist_ok=True)


def pct(vals, q):
    s = sorted(vals)
    i = (len(s) - 1) * q
    lo, hi = math.floor(i), math.ceil(i)
    return s[lo] if lo == hi else s[lo] + (s[hi] - s[lo]) * (i - lo)


# ---------------- Exp 1: detector scaling (per N) ----------------
det = defaultdict(list)
with (CAMP / "exp1" / "detector_run_summary.csv").open() as fh:
    for r in csv.DictReader(fh):
        det[int(r["workloads"])].append(r)
with (PKG / "exp1_detector_scaling.csv").open("w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["N_contexts", "reps", "updates", "mean_ms", "p50_ms", "p95_ms",
                "p99_ms", "max_ms", "cpu_cores", "rss_mib", "deadline_misses",
                "decision_equiv_ok"])
    for n in sorted(det):
        g = det[n]
        w.writerow([
            n, len(g),
            sum(int(x["observed_updates"]) for x in g),
            round(st.mean(float(x["cycle_latency_mean_ms"]) for x in g), 4),
            round(st.mean(float(x["cycle_latency_median_ms"]) for x in g), 4),
            round(st.mean(float(x["cycle_latency_p95_ms"]) for x in g), 4),
            round(st.mean(float(x["cycle_latency_p99_ms"]) for x in g), 4),
            round(max(float(x["cycle_latency_max_ms"]) for x in g), 4),
            round(st.mean(float(x["cpu_utilization_one_core_pct"]) for x in g) / 100.0, 4),
            round(st.mean(float(x["rss_end_bytes"]) for x in g) / (1024 * 1024), 2),
            sum(int(x["deadline_misses"]) for x in g),
            int(all(x.get("decision_equiv_ok", "True") == "True" for x in g)),
        ])

# ---------------- Exp 2: evaluator saturation (per offered rate) ----------------
ev = defaultdict(list)
with (CAMP / "exp2" / "sweep" / "evaluator_run_summary.csv").open() as fh:
    for r in csv.DictReader(fh):
        ev[int(r["offered_rate_requests_s"])].append(r)
with (PKG / "exp2_evaluator_scaling.csv").open("w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["offered_rate_eval_s", "reps", "achieved_rate_eval_s",
                "completion_pct", "deadline_miss_pct", "error_pct",
                "service_p50_ms", "service_p95_ms", "service_p99_ms",
                "e2e_p95_ms", "e2e_p99_ms", "cpu_cores"])
    for rate in sorted(ev):
        g = ev[rate]
        achieved = st.mean(float(x["achieved_completion_rate_requests_s"]) for x in g)
        w.writerow([
            rate, len(g), round(achieved, 3),
            round(100 * st.mean(float(x["achieved_completion_rate_requests_s"]) / rate for x in g), 2),
            round(100 * st.mean(float(x["deadline_miss_rate"]) for x in g), 3),
            round(100 * st.mean(float(x["error_rate"]) for x in g), 3),
            round(st.mean(float(x["service_latency_p50_ms"]) for x in g), 1),
            round(st.mean(float(x["service_latency_p95_ms"]) for x in g), 1),
            round(st.mean(float(x["service_latency_p99_ms"]) for x in g), 1),
            round(st.mean(float(x["end_to_end_p95_ms"]) for x in g), 1),
            round(st.mean(float(x["end_to_end_p99_ms"]) for x in g), 1),
            round(st.mean(float(x["evaluator_mean_cpu_cores"]) for x in g), 3),
        ])

# ---------------- Exp 3: per-trial (for boxplot raw points) ----------------
trials = [json.loads(l) for l in (CAMP / "exp3_formal" /
          "concurrent_containment_trials.jsonl").read_text().splitlines() if l.strip()]
valid = [t for t in trials if t.get("validity") == "VALID"]
with (PKG / "exp3_trials.csv").open("w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["trial_id", "round", "K", "target_set", "trial_success",
                "all_nontargets_reachable", "launch_skew_ms",
                "T_identity_all_s", "T_policy_all_s", "T_service_all_s",
                "T_nodefilter_all_s", "T_all_isolated_s"])
    for t in sorted(valid, key=lambda x: x["trial_id"]):
        def s(k):
            v = t.get(k)
            return round(v / 1000, 3) if isinstance(v, (int, float)) else ""
        w.writerow([t["trial_id"], t["round"], t["k"],
                    "|".join(x.replace("ricxapp-", "") for x in t["target_set"]),
                    int(bool(t["trial_success"])), int(bool(t["all_nontargets_reachable"])),
                    t["launch_skew_ms"], s("T_identity_all"), s("T_policy_all"),
                    s("T_service_all"), s("T_nodefilter_all"), s("T_all_isolated")])

# ---------------- Exp 3: per-K stage summary (median/IQR/min/max) ----------------
STAGES = ["T_identity_all", "T_policy_all", "T_service_all", "T_nodefilter_all", "T_all_isolated"]
with (PKG / "exp3_perK_summary.csv").open("w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["K", "valid_trials", "successes", "success_pct",
                "stage", "n", "median_s", "iqr_s", "min_s", "max_s"])
    for k in [1, 2, 3, 4]:
        kt = [t for t in valid if t["k"] == k]
        succ = sum(1 for t in kt if t["trial_success"])
        for stg in STAGES:
            v = [t[stg] / 1000 for t in kt if isinstance(t.get(stg), (int, float))]
            if v:
                w.writerow([k, len(kt), succ, round(100 * succ / len(kt), 1), stg,
                            len(v), round(st.median(v), 3),
                            round(pct(v, 0.75) - pct(v, 0.25), 3),
                            round(min(v), 3), round(max(v), 3)])

print("CSVs written to", PKG)
for f in sorted(PKG.glob("*.csv")):
    print("  ", f.name)
