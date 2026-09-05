#!/usr/bin/env python3
"""Render the 4 chosen v2 scalability figures as report-ready PDFs.

Reads the tidy v2 CSVs in experiments/scalability/scalability_matlab_package/
(the exact same data behind the MATLAB package) and writes PDFs directly into
the live report folder. Read-only over the CSVs; no evidence dir is mutated.
Stdlib csv + matplotlib only (no pandas).
"""
from __future__ import annotations
import csv
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PKG = Path(__file__).resolve().parents[1] / "scalability_matlab_package"
REPORT = Path("/home/nearric/Desktop/FYP/zt-xguard/report_revision_three_state/"
              "FYP_Final_Report___Open_RAN_Threat_Containment/final new")

plt.rcParams.update({
    "font.size": 11, "font.family": "serif", "axes.grid": True,
    "grid.alpha": 0.3, "axes.axisbelow": True, "figure.dpi": 150,
})
C = {"p50": "#08519c", "p95": "#3182bd", "p99": "#6a3d9a", "max": "#e6550d",
     "ok": "#31a354", "fail": "#e6550d", "line": "#08519c"}


def rows(name):
    with open(PKG / name, newline="") as f:
        return list(csv.DictReader(f))


def save(fig, stem):
    fig.tight_layout()
    fig.savefig(REPORT / f"{stem}.pdf")
    fig.savefig(REPORT / f"{stem}.png", dpi=200)
    plt.close(fig)
    print("wrote", stem)


# ---- Fig 1: detector cycle latency vs N -----------------------------------
def fig_detector():
    d = rows("exp1_detector_scaling.csv")
    N = [int(r["N_contexts"]) for r in d]
    fig, ax = plt.subplots(figsize=(6.6, 4.0))
    for key, lbl, mk in (("p50_ms", "p50", "o"), ("p95_ms", "p95", "s"),
                         ("p99_ms", "p99", "^"), ("max_ms", "max", "d")):
        ax.plot(N, [float(r[key]) for r in d], mk + "-", color=C[key.split("_")[0]],
                lw=1.6, ms=5, label=lbl)
    ax.axhline(1000, color="0.5", lw=1, ls="-")
    ax.text(N[0], 1050, "1 Hz processing budget = 1000 ms", color="0.4",
            fontsize=8, va="bottom")
    ax.set_yscale("log")
    ax.set_xlabel("Independent detector contexts $N$")
    ax.set_ylabel("Per-cycle scoring latency (ms)")
    ax.set_xticks(N)
    ax.legend(frameon=False, loc="center right")
    ax.set_title("Detector computational scalability ($N=1..80$, 0 budget misses)",
                 fontsize=10)
    save(fig, "exp1_detector_latency")


# ---- Fig 2: evaluator deadline-miss vs offered rate (PRIMARY Exp2) ---------
def fig_evaluator_miss():
    d = rows("exp2_evaluator_scaling.csv")
    r = [float(x["offered_rate_eval_s"]) for x in d]
    miss = [float(x["deadline_miss_pct"]) for x in d]
    fig, ax = plt.subplots(figsize=(6.2, 3.9))
    ax.axvspan(0, 22.5, color="#c7e9c0", alpha=0.5)
    ax.axvspan(22.5, 27.5, color="#fee391", alpha=0.5)
    ax.axvspan(27.5, max(r) + 2, color="#fc9272", alpha=0.5)
    ax.plot(r, miss, "o-", color=C["line"], lw=1.8, ms=6)
    ax.set_xlim(0, max(r) + 2)
    ax.set_ylim(-3, 100)
    ax.set_xlabel("Offered rate (eval/s)")
    ax.set_ylabel("End-to-end 1 s deadline-miss rate (%)")
    ax.set_title("Policy decision-plane SLO: stable $\\leq$20/s, knee $\\approx$25--30/s",
                 fontsize=10)
    save(fig, "exp2_deadline_miss")


# ---- Fig 2b: offered vs achieved throughput (SUPPORT) ---------------------
def fig_evaluator_saturation():
    d = rows("exp2_evaluator_scaling.csv")
    r = [float(x["offered_rate_eval_s"]) for x in d]
    ach = [float(x["achieved_rate_eval_s"]) for x in d]
    fig, ax = plt.subplots(figsize=(5.8, 3.8))
    ax.plot([0, max(r)], [0, max(r)], "--", color="0.6", lw=1.2, label="ideal $y=x$")
    ax.plot(r, ach, "o-", color=C["line"], lw=1.8, ms=6, label="achieved")
    ax.set_xlim(0, max(r) + 2)
    ax.set_xlabel("Offered rate (eval/s)")
    ax.set_ylabel("Achieved completion rate (eval/s)")
    ax.legend(frameon=False, loc="upper left")
    ax.set_title("Throughput saturation of the decision plane", fontsize=10)
    save(fig, "exp2_saturation")


# ---- Fig 2c: service latency vs offered rate (SUPPORT) --------------------
def fig_evaluator_latency():
    d = rows("exp2_evaluator_scaling.csv")
    r = [float(x["offered_rate_eval_s"]) for x in d]
    fig, ax = plt.subplots(figsize=(5.8, 3.8))
    for key, lbl, mk, c in (("service_p50_ms", "p50", "o", C["p50"]),
                            ("service_p95_ms", "p95", "s", C["p95"]),
                            ("service_p99_ms", "p99", "^", C["max"])):
        ax.plot(r, [float(x[key]) for x in d], mk + "-", color=c, lw=1.8, ms=5, label=lbl)
    ax.axvline(27.5, color="0.4", ls=":", lw=1.2)
    ax.text(27.5, ax.get_ylim()[1], " knee", color="0.4", fontsize=8, va="top")
    ax.set_yscale("log")
    ax.set_xlabel("Offered rate (eval/s)")
    ax.set_ylabel("Service latency (ms), send$\\rightarrow$response")
    ax.legend(frameon=False, loc="upper left")
    ax.set_title("Request service latency approaching saturation (log $y$)", fontsize=10)
    save(fig, "exp2_latency")


# ---- Fig 3: Exp3 per-stage latency vs K -----------------------------------
def fig_fourlock():
    t = rows("exp3_trials.csv")
    Ks = [1, 2, 3, 4]
    stages = [("T_identity_all_s", "Identity", "#08519c"),
              ("T_policy_all_s", "NetworkPolicy-select", "#3182bd"),
              ("T_service_all_s", "Service isolation", "#6baed6"),
              ("T_nodefilter_all_s", "Node packet-filter", "#e6550d"),
              ("T_all_isolated_s", "Verified unreachable", "#31a354")]
    fig, ax = plt.subplots(figsize=(6.6, 4.2))
    for col, lbl, c in stages:
        meds = []
        for K in Ks:
            vals = [float(r[col]) for r in t if int(r["K"]) == K and r[col]]
            meds.append(statistics.median(vals))
            xs = [K + (i - len(vals) / 2) * 0.045 for i in range(len(vals))]
            ax.scatter(xs, vals, s=16, color=c, alpha=0.45, zorder=2)
        ax.plot(Ks, meds, "o-", color=c, lw=1.8, ms=5, label=lbl, zorder=3)
    ax.set_xlabel("Concurrent compromised xApps $K$")
    ax.set_ylabel("Attack-onset latency (s)")
    ax.set_xticks(Ks)
    ax.legend(frameon=False, loc="upper left", fontsize=8)
    ax.set_title("Per-stage containment latency vs concurrency (raw points + median)",
                 fontsize=10)
    save(fig, "exp3_fourlock_vs_K")


if __name__ == "__main__":
    print("report folder:", REPORT, "exists:", REPORT.is_dir())
    fig_detector()
    fig_evaluator_miss()
    fig_evaluator_saturation()
    fig_evaluator_latency()
    fig_fourlock()
    print("done")
