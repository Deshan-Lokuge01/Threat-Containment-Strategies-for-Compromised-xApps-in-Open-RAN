# ZT-XGuard scalability — MATLAB figure package

Everything needed to regenerate the scalability figures on a machine that has
MATLAB. Self-contained: **4 CSVs + 8 MATLAB scripts + 1 driver**. No toolboxes
beyond base MATLAB are required (boxes in Exp3 are drawn manually).

Source campaign: `results/campaign-20260808T051632Z/` (Exp1 detector sweep,
Exp2 policy-engine sweep, Exp3 formal concurrent-containment, 24 valid trials).

## How to run
```matlab
cd scalability_matlab_package
run_all        % regenerates all PDFs + PNGs into this folder
```
Or run any single figure, e.g. `fig_exp3_fourlock`.
Each script writes a vector `*.pdf` and a 200-dpi `*.png` beside itself.

## Data files
| CSV | Experiment | Key columns |
|-----|-----------|-------------|
| `exp1_detector_scaling.csv` | E1 detector compute scalability (N = 1..80) | `N_contexts, p50_ms, p95_ms, p99_ms, max_ms, cpu_cores, rss_mib, deadline_misses, decision_equiv_ok` |
| `exp2_evaluator_scaling.csv` | E2 policy-engine throughput (offered-rate sweep) | `offered_rate_eval_s, achieved_rate_eval_s, service_p50/p95/p99_ms, deadline_miss_pct, cpu_cores` |
| `exp3_trials.csv` | E3 per-trial (n=6 per K, K=1..4) | `K, trial_success, all_nontargets_reachable, launch_skew_ms, T_identity/policy/service/nodefilter/all_isolated_s` |
| `exp3_perK_summary.csv` | E3 per-K, per-stage summary | `K, valid_trials, successes, success_pct, stage, median_s, iqr_s, min_s, max_s` |

## Scripts → output
| Script | Output figure(s) |
|--------|------------------|
| `fig_exp1_detector.m` | `exp1_detector_latency.{pdf,png}` — cycle latency vs N, 1 Hz budget line |
| `fig_exp1_resource.m` | `exp1_detector_cpu.*`, `exp1_detector_rss.*` |
| `fig_exp1_latency_dist.m` | `exp1_latency_distribution.*` — full per-tick latency box/whisker per N (reads `raw_campaign_data/exp1/detector_cycles.csv`) |
| `fig_exp2_saturation.m` | `exp2_saturation.*` — offered vs achieved (y=x ideal) |
| `fig_exp2_latency.m` | `exp2_latency.*` — p50/p95/p99, saturation knee |
| `fig_exp2_deadline_miss.m` | `exp2_deadline_miss.*` — 1 s deadline-miss %, stable/marginal/saturated bands |
| `fig_exp3_fourlock.m` | `exp3_fourlock_vs_K.*` — per-stage latency vs K (raw points + median) |
| `fig_exp3_makespan_boxplot.m` | `exp3_makespan_boxplot.*` — T_all_isolated by K |
| `fig_exp3_nontarget.m` | `exp3_nontarget_correctness.*` — non-target correctness by K |

## Raw campaign data (`raw_campaign_data/`)
The 4 CSVs above are tidy, figure-ready summaries. `raw_campaign_data/` holds the
**complete** underlying campaign export, for auditing / redrawing from raw:
- `exp1/detector_cycles.csv` — every per-tick cycle latency (~15.4k rows);
  `detector_run_summary.csv` (per-N, source of `exp1_detector_scaling.csv`);
  `detector_workload_accounting.csv` (per virtual-xApp).
- `exp2/evaluator_requests.csv` — every request (~31.5k rows);
  `evaluator_run_summary.csv` (per-rate, source of `exp2_evaluator_scaling.csv`);
  `evaluator_xapp_accounting.csv`.
- `exp3_formal/concurrent_containment_raw.csv` (per-xApp, per-lock timestamps);
  `concurrent_containment_trials.csv` (per-trial, source of `exp3_trials.csv`);
  `concurrent_containment_summary.csv` (per-K, incl. Wilson CI columns);
  `trial_schedule.csv`; `exp3_graph_ready.csv`.

The `fig_*.m` scripts read **only** the 4 tidy CSVs — you don't need the raw
folder to make the figures; it's there for completeness.

## Restyling
Each script starts with a `% ---- STYLE ----` block (colours, line width, font
size, figure size, region cutoffs). Edit only that block; the plotting code
below reads from it.

## Notes on statistics
Exp3 has small n (6 trials/K), so figures show **raw trial points plus median /
IQR** — deliberately **not** p95/p99. Exp1/Exp2 are high-count load sweeps where
p95/p99 are meaningful and are plotted.
