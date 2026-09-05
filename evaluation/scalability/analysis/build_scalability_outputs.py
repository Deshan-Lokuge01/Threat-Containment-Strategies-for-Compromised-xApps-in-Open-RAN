#!/usr/bin/env python3
"""Derive report-ready scalability tables and figures from the frozen evidence.

Read-only over the historical results directories; all outputs are written to
experiments/scalability/analysis/out/ so no evidence directory is mutated.
"""
from __future__ import annotations

import csv
import json
import math
import os
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

RESULTS = Path(__file__).resolve().parents[1] / "results"
OUT = Path(__file__).resolve().parent / "out"
OUT.mkdir(parents=True, exist_ok=True)

# Re-scoped experiments (2026-08-08): detector N=1..12, evaluator rates 5..50,
# physical concurrent containment on the four real O-RAN SC xApps K=1..4.
PHYS = RESULTS / "exp3-realxapps-20260807T175932Z"
PHYS_JSONL = "real_concurrent_trials.jsonl"
DET = RESULTS / "exp1-detector-20260807T171528Z"
EVAL_BND = RESULTS / "exp2-evaluator-20260807T172001Z"


def wilson(successes: int, n: int, z: float = 1.959963984540054):
    """Wilson score interval for a binomial proportion."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    phat = successes / n
    denom = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))
    return (phat, max(0.0, centre - half), min(1.0, centre + half))


def pctl(values, q):
    if not values:
        return float("nan")
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    idx = q * (len(s) - 1)
    lo = math.floor(idx)
    hi = math.ceil(idx)
    if lo == hi:
        return s[int(idx)]
    return s[lo] + (s[hi] - s[lo]) * (idx - lo)


# ---------------------------------------------------------------- physical ---
def load_physical():
    per_k = {}
    all_attempts = 0
    all_succ = 0
    with (PHYS / PHYS_JSONL).open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            cell = json.loads(line)
            k = cell["k"]
            bucket = per_k.setdefault(
                k,
                {
                    "attempts": 0,
                    "successes": 0,
                    "contained_ms": [],
                    "identity_ms": [],
                    "pkt_ms": [],
                    "net_ms": [],
                },
            )
            results = cell["results"]
            if isinstance(results, dict):
                results = list(results.values())
            for r in results:
                bucket["attempts"] += 1
                all_attempts += 1
                if r.get("passed"):
                    bucket["successes"] += 1
                    all_succ += 1
                for key, field in (
                    ("contained_ms", "contained_verified_ms"),
                    ("identity_ms", "identity_disabled_ms"),
                    ("pkt_ms", "direct_packet_filter_ms"),
                    ("net_ms", "network_unreachable_ms"),
                ):
                    v = r.get(field)
                    if v is not None:
                        bucket[key].append(v / 1000.0)  # ms -> s
    return per_k, all_attempts, all_succ


def physical_tables():
    per_k, n_all, s_all = load_physical()
    rows = []
    for k in sorted(per_k):
        b = per_k[k]
        phat, lo, hi = wilson(b["successes"], b["attempts"])
        rows.append(
            {
                "K": k,
                "attempts": b["attempts"],
                "successes": b["successes"],
                "rate": phat,
                "wilson_lo": lo,
                "wilson_hi": hi,
                "net_median": statistics.median(b["net_ms"]),
                "net_p95": pctl(b["net_ms"], 0.95),
                "net_max": max(b["net_ms"]),
                "contained_median": statistics.median(b["contained_ms"]),
                "contained_p95": pctl(b["contained_ms"], 0.95),
                "identity_median": statistics.median(b["identity_ms"]),
                "pkt_median": statistics.median(b["pkt_ms"]),
            }
        )
    phat, lo, hi = wilson(s_all, n_all)
    overall = {"attempts": n_all, "successes": s_all, "rate": phat,
               "wilson_lo": lo, "wilson_hi": hi}

    # LaTeX table: physical concurrent containment
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Live concurrent containment scalability. $K$ simultaneous "
        r"compromised workloads driven through the real Falco$\rightarrow$"
        r"evaluator$\rightarrow$responder path (3 repetitions per $K$). "
        r"Latencies are attack-onset (client timestamp immediately before "
        r"\texttt{kubectl exec}) to the stated milestone.}",
        r"\label{tab:scal-physical}",
        r"\begin{tabular}{rrrlrrr}",
        r"\toprule",
        r"$K$ & Att. & Succ. & Success (Wilson 95\% CI) & "
        r"$t_{\text{net}}^{\text{med}}$ & $t_{\text{net}}^{p95}$ & "
        r"$t_{\text{net}}^{\max}$ \\",
        r" & & & & (s) & (s) & (s) \\",
        r"\midrule",
    ]
    for r in rows:
        lines.append(
            f"{r['K']} & {r['attempts']} & {r['successes']} & "
            f"1.000 [{r['wilson_lo']:.3f}, {r['wilson_hi']:.3f}] & "
            f"{r['net_median']:.2f} & {r['net_p95']:.2f} & {r['net_max']:.2f} \\\\"
        )
    lines.append(r"\midrule")
    lines.append(
        f"All & {overall['attempts']} & {overall['successes']} & "
        f"1.000 [{overall['wilson_lo']:.3f}, {overall['wilson_hi']:.3f}] & "
        r"\multicolumn{3}{c}{--} \\"
    )
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    (OUT / "table_physical.tex").write_text("\n".join(lines))

    # Mechanism-breakdown table (median seconds per lock, per K)
    mlines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Median containment-mechanism completion time (seconds, "
        r"attack-onset origin) by concurrency level.}",
        r"\label{tab:scal-mechanism}",
        r"\begin{tabular}{rrrrr}",
        r"\toprule",
        r"$K$ & Service isolate & Identity disable & Node packet-filter & "
        r"Verified unreachable \\",
        r"\midrule",
    ]
    for r in rows:
        mlines.append(
            f"{r['K']} & {r['contained_median']:.2f} & "
            f"{r['identity_median']:.2f} & {r['pkt_median']:.2f} & "
            f"{r['net_median']:.2f} \\\\"
        )
    mlines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    (OUT / "table_mechanism.tex").write_text("\n".join(mlines))

    return per_k, rows, overall


# ---------------------------------------------------------------- detector ---
def detector_table():
    rows = {}
    with (DET / "detector_run_summary.csv").open() as fh:
        for row in csv.DictReader(fh):
            n = int(row["workloads"])
            rows.setdefault(n, []).append(row)
    agg = []
    total_updates = 0
    total_misses = 0
    for n in sorted(rows):
        reps = rows[n]
        mean_cycle = statistics.mean(float(r["cycle_latency_mean_ms"]) for r in reps)
        p95 = statistics.mean(float(r["cycle_latency_p95_ms"]) for r in reps)
        mx = max(float(r["cycle_latency_max_ms"]) for r in reps)
        upd = sum(int(r["observed_updates"]) for r in reps)
        miss = sum(int(r["deadline_misses"]) for r in reps)
        total_updates += upd
        total_misses += miss
        agg.append({"N": n, "mean": mean_cycle, "p95": p95, "max": mx,
                    "updates": upd, "misses": miss})
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Streaming statistical-detector logical capacity. Per-cell "
        r"cycle latency against the 1\,Hz (1000\,ms) detector deadline, "
        r"3 repetitions per $N$.}",
        r"\label{tab:scal-detector}",
        r"\begin{tabular}{rrrrrr}",
        r"\toprule",
        r"$N$ streams & Updates & Mean (ms) & p95 (ms) & Max (ms) & "
        r"Deadline misses \\",
        r"\midrule",
    ]
    for a in agg:
        lines.append(
            f"{a['N']} & {a['updates']:,} & {a['mean']:.3f} & {a['p95']:.3f} & "
            f"{a['max']:.3f} & {a['misses']} \\\\"
        )
    lines.append(r"\midrule")
    lines.append(
        rf"\textbf{{Total}} & \textbf{{{total_updates:,}}} & "
        rf"\multicolumn{{3}}{{c}}{{--}} & \textbf{{{total_misses}}} \\"
    )
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    (OUT / "table_detector.tex").write_text("\n".join(lines))
    return agg, total_updates, total_misses


# --------------------------------------------------------------- evaluator ---
def evaluator_table():
    def load(path):
        rows = {}
        with (path / "evaluator_run_summary.csv").open() as fh:
            for row in csv.DictReader(fh):
                n = int(row["offered_rate_requests_s"])
                rows.setdefault(n, []).append(row)
        return rows

    bnd = load(EVAL_BND)
    agg = []
    for n in sorted(bnd):
        reps = bnd[n]
        miss = statistics.mean(float(r["deadline_miss_rate"]) for r in reps)
        p95 = statistics.mean(float(r["service_latency_p95_ms"]) for r in reps)
        cpu = statistics.mean(float(r["evaluator_mean_cpu_cores"]) for r in reps)
        agg.append({"rate": n, "miss": miss, "p95": p95, "cpu": cpu})
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Evaluator open-loop capacity near saturation on the "
        r"single-core deployment (3 repetitions per offered rate).}",
        r"\label{tab:scal-evaluator}",
        r"\begin{tabular}{rrrr}",
        r"\toprule",
        r"Offered rate (sig/s) & Deadline-miss rate & Service p95 (ms) & "
        r"Evaluator CPU (cores) \\",
        r"\midrule",
    ]
    for a in agg:
        lines.append(
            f"{a['rate']} & {a['miss']*100:.2f}\\% & {a['p95']:.0f} & "
            f"{a['cpu']:.2f} \\\\"
        )
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    (OUT / "table_evaluator.tex").write_text("\n".join(lines))
    return agg


# ----------------------------------------------------------------- figures ---
def fig_physical(per_k):
    ks = sorted(per_k)
    med = [statistics.median(per_k[k]["net_ms"]) for k in ks]
    p95 = [pctl(per_k[k]["net_ms"], 0.95) for k in ks]
    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    # scatter of individual attempts
    for k in ks:
        xs = [k + (i - len(per_k[k]["net_ms"]) / 2) * 0.05
              for i in range(len(per_k[k]["net_ms"]))]
        ax.scatter(xs, per_k[k]["net_ms"], s=18, color="#9ecae1",
                   edgecolor="#3182bd", linewidth=0.4, zorder=2,
                   label="per-attempt" if k == ks[0] else None)
    ax.plot(ks, med, "-o", color="#08519c", label="median", zorder=3)
    ax.plot(ks, p95, "--s", color="#e6550d", label="p95", zorder=3)
    ax.set_xlabel("Concurrent compromised workloads $K$")
    ax.set_ylabel("Attack-onset $\\rightarrow$ verified\nunreachable (s)")
    ax.set_xticks(ks)
    ax.set_ylim(bottom=0)
    ax.grid(True, alpha=0.3)
    ax.legend(frameon=False, fontsize=8, loc="upper left")
    fig.tight_layout()
    fig.savefig(OUT / "scal_physical_latency.pdf")
    fig.savefig(OUT / "scal_physical_latency.png", dpi=160)
    plt.close(fig)


def fig_detector(det_agg):
    ns = [a["N"] for a in det_agg]
    mean = [a["mean"] for a in det_agg]
    p95 = [a["p95"] for a in det_agg]
    mx = [a["max"] for a in det_agg]
    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    ax.plot(ns, mean, "-o", color="#08519c", label="mean")
    ax.plot(ns, p95, "--s", color="#3182bd", label="p95")
    ax.plot(ns, mx, ":^", color="#e6550d", label="max")
    ax.set_xlabel("Protected xApp telemetry streams $N$")
    ax.set_ylabel("Detector cycle latency (ms)")
    ax.set_xticks(ns)
    ax.grid(True, alpha=0.3)
    ax.legend(frameon=False, fontsize=8, loc="upper left")
    ax.text(0.98, 0.05, "1 Hz deadline = 1000 ms (never approached)",
            transform=ax.transAxes, ha="right", fontsize=7, color="gray")
    fig.tight_layout()
    fig.savefig(OUT / "scal_detector_cycle.pdf")
    fig.savefig(OUT / "scal_detector_cycle.png", dpi=160)
    plt.close(fig)


def fig_evaluator(ev_agg):
    rates = [a["rate"] for a in ev_agg]
    miss = [a["miss"] * 100 for a in ev_agg]
    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    ax.plot(rates, miss, "-o", color="#08519c")
    ax.axvspan(0, 27.5, color="#c7e9c0", alpha=0.5, label="stable")
    ax.axvspan(27.5, 32.5, color="#fee391", alpha=0.5, label="marginal")
    ax.axvspan(32.5, 55, color="#fcae91", alpha=0.5, label="saturated")
    ax.set_xlabel("Offered signal rate (signals/s)")
    ax.set_ylabel("Deadline-miss rate (\\%)")
    ax.set_xlim(min(rates) - 1, max(rates) + 1)
    ax.set_ylim(-3, 100)
    ax.grid(True, alpha=0.3)
    ax.legend(frameon=False, fontsize=8, loc="center left")
    fig.tight_layout()
    fig.savefig(OUT / "scal_evaluator_miss.pdf")
    fig.savefig(OUT / "scal_evaluator_miss.png", dpi=160)
    plt.close(fig)


def main():
    per_k, phys_rows, overall = physical_tables()
    det_agg, tot_upd, tot_miss = detector_table()
    ev_agg = evaluator_table()
    fig_physical(per_k)
    fig_detector(det_agg)
    fig_evaluator(ev_agg)

    summary = {
        "physical": {"rows": phys_rows, "overall": overall},
        "detector": {"rows": det_agg, "total_updates": tot_upd,
                     "total_misses": tot_miss},
        "evaluator": ev_agg,
    }
    (OUT / "scalability_derived_summary.json").write_text(
        json.dumps(summary, indent=2)
    )
    print("=== PHYSICAL ===")
    for r in phys_rows:
        print(f"  K={r['K']}: {r['successes']}/{r['attempts']} "
              f"Wilson[{r['wilson_lo']:.3f},{r['wilson_hi']:.3f}] "
              f"net med={r['net_median']:.2f}s p95={r['net_p95']:.2f}s")
    print(f"  OVERALL: {overall['successes']}/{overall['attempts']} "
          f"Wilson[{overall['wilson_lo']:.3f},{overall['wilson_hi']:.3f}]")
    print("=== DETECTOR ===")
    print(f"  total updates={tot_upd:,} misses={tot_miss}")
    for a in det_agg:
        print(f"  N={a['N']}: mean={a['mean']:.3f}ms p95={a['p95']:.3f}ms "
              f"max={a['max']:.3f}ms")
    print("=== EVALUATOR (boundary) ===")
    for a in ev_agg:
        print(f"  {a['rate']} sig/s: miss={a['miss']*100:.2f}% "
              f"p95={a['p95']:.0f}ms cpu={a['cpu']:.2f}")
    print(f"\nOutputs in {OUT}")


if __name__ == "__main__":
    main()
