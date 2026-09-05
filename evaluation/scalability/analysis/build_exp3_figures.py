#!/usr/bin/env python3
"""Exp 3 (real-xApp concurrent isolation) graph-ready figures.

Small-n (5-6 valid trials/K): show every raw trial point plus median/IQR,
never p95/p99. Trial is the independent unit. Reads the campaign trials CSV.
"""
from __future__ import annotations
import csv
import statistics as st
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

FORMAL = Path(sys.argv[1])
OUT = FORMAL / "figures"
OUT.mkdir(exist_ok=True)

rows = []
with (FORMAL / "concurrent_containment_trials.csv").open() as fh:
    for r in csv.DictReader(fh):
        if r.get("validity") != "VALID":
            continue
        rows.append(r)

Ks = [1, 2, 3, 4]
STAGES = [
    ("T_identity_all", "Identity", "#08519c"),
    ("T_policy_all", "NetworkPolicy-select", "#3182bd"),
    ("T_service_all", "Service isolation", "#6baed6"),
    ("T_nodefilter_all", "Node packet-filter", "#e6550d"),
    ("T_all_isolated", "Verified unreachable", "#31a354"),
]


def vals(field, k):
    out = []
    for r in rows:
        if int(r["K"]) == k and r.get(field) not in ("", "None", None):
            out.append(float(r[field]) / 1000.0)  # ms -> s
    return out


# ---- Figure F: K vs four-lock (+final) latency, raw points + median line ----
fig, ax = plt.subplots(figsize=(6.4, 4.0))
for field, label, color in STAGES:
    meds = []
    for k in Ks:
        v = vals(field, k)
        meds.append(st.median(v) if v else float("nan"))
        # jittered raw points
        xs = [k + (i - len(v) / 2) * 0.045 for i in range(len(v))]
        ax.scatter(xs, v, s=16, color=color, alpha=0.5, edgecolor="none", zorder=2)
    ax.plot(Ks, meds, "-o", color=color, lw=1.8, ms=5, label=label, zorder=3)
ax.set_xlabel("Concurrent compromised xApps K")
ax.set_ylabel("Attack-onset latency (s)")
ax.set_xticks(Ks)
ax.grid(True, alpha=0.3)
ax.legend(frameon=False, fontsize=8, loc="upper left")
ax.set_title("Per-stage containment latency vs concurrency (raw trial points + median)",
             fontsize=9)
fig.tight_layout()
fig.savefig(OUT / "exp3_fourlock_vs_K.pdf")
fig.savefig(OUT / "exp3_fourlock_vs_K.png", dpi=160)
plt.close(fig)

# ---- Figure G: T_all_isolated boxplot by K + raw points ----
fig, ax = plt.subplots(figsize=(5.4, 3.8))
data = [vals("T_all_isolated", k) for k in Ks]
bp = ax.boxplot(data, positions=Ks, widths=0.5, patch_artist=True,
                showfliers=False, medianprops=dict(color="#08306b", lw=1.6))
for patch in bp["boxes"]:
    patch.set_facecolor("#c6dbef")
    patch.set_alpha(0.7)
for k, v in zip(Ks, data):
    xs = [k + (i - len(v) / 2) * 0.05 for i in range(len(v))]
    ax.scatter(xs, v, s=22, color="#08519c", zorder=3, edgecolor="white", linewidth=0.4)
ax.set_xlabel("Concurrent compromised xApps K")
ax.set_ylabel("$T_{\\mathrm{all-isolated}}$ (s)")
ax.set_xticks(Ks)
ax.set_ylim(bottom=0)
ax.grid(True, alpha=0.3, axis="y")
ax.set_title("Concurrent-containment makespan (n=6/K; raw points + box)", fontsize=9)
fig.tight_layout()
fig.savefig(OUT / "exp3_makespan_boxplot.pdf")
fig.savefig(OUT / "exp3_makespan_boxplot.png", dpi=160)
plt.close(fig)

# ---- graph-ready CSV (one row per K per stage, median/IQR/min/max) ----
def stat(v):
    if not v:
        return (None, None, None, None)
    s = sorted(v)
    def pct(q):
        i = (len(s) - 1) * q
        import math
        lo = math.floor(i); hi = math.ceil(i)
        return s[lo] if lo == hi else s[lo] + (s[hi] - s[lo]) * (i - lo)
    return (round(st.median(s), 3), round(pct(0.75) - pct(0.25), 3),
            round(min(s), 3), round(max(s), 3))


with (OUT / "exp3_graph_ready.csv").open("w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["K", "stage", "n", "median_s", "iqr_s", "min_s", "max_s"])
    for k in Ks:
        for field, label, _ in STAGES:
            m, iqr, mn, mx = stat(vals(field, k))
            w.writerow([k, label, len(vals(field, k)), m, iqr, mn, mx])

print("Exp3 figures + graph-ready CSV in", OUT)
for k in Ks:
    v = vals("T_all_isolated", k)
    print(f"  K={k}: n={len(v)} makespan median={st.median(v):.2f}s" if v else f"  K={k}: no data")
