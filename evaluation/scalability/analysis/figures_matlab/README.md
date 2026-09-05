# Scalability figures — MATLAB inputs and scripts

Self-contained MATLAB scripts that redraw the three scalability figures from
tidy CSVs. No dependency on the `ztx_style` framework, so you can restyle each
one by editing the `STYLE` block at the top.

## Files
- `detector_scaling.csv`  — Experiment 1: one row per N detector contexts (N, updates, mean_ms, p95_ms, max_ms, deadline_misses)
- `evaluator_scaling.csv` — Experiment 2: one row per offered rate (rate, miss_rate_pct, service_p95_ms, cpu_cores)
- `physical_scaling.csv`  — Experiment 3: one row per concurrency K (K, attempts, successes, wilson_lo/hi, net med/p95/max, per-mechanism medians)
- `fig_scal_01_detector.m`   — detector cycle latency vs N
- `fig_scal_02_evaluator.m`  — evaluator deadline-miss rate vs offered rate (shaded bands)
- `fig_scal_03_physical.m`   — attack-onset-to-unreachable latency vs K
- `make_matlab_inputs.py`    — regenerates the three CSVs from the canonical result dirs

## Usage
```matlab
cd experiments/scalability/analysis/figures_matlab
fig_scal_01_detector
fig_scal_02_evaluator
fig_scal_03_physical
```
Each script writes `scal_*.pdf` and `scal_*.png` beside itself.

## Notes
- Requires MATLAB R2020a+ (`exportgraphics`). Written to standard idioms but
  NOT run here (no MATLAB/Octave on the dev box) — sanity-check on first run.
- To refresh the CSVs after a re-run: `python3 make_matlab_inputs.py`.
- Canonical source dirs: `../../results/exp1-detector-*`, `exp2-evaluator-*`,
  `exp3-realxapps-*`. The Python/matplotlib versions of the same figures live in
  `../out/` and are produced by `../build_scalability_outputs.py`.
