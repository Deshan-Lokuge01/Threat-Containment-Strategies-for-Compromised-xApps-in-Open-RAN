# Evaluation

The measurements behind the report and the CCNC paper. Everything here is real data collected on the
live testbed, with the raw artifacts kept alongside the summaries.

## `scalability/`

Three campaigns:

- **Detector scaling** — state-engine update latency as monitored contexts grow from N=1 to N=80
  (five reps each). p50/p95/p99 latency, CPU, RSS, and deadline misses. Zero deadline misses across
  the whole sweep.
- **Evaluator scaling** — signal-evaluation throughput as the offered rate rises to saturation, with
  the knee where deadline misses climb.
- **Physical containment** — real concurrent isolation of K=1…4 xApps, with per-mechanism latencies
  (NetworkPolicy, service, identity, packet-filter) and Wilson confidence intervals on success.

Raw per-run JSON, `detector_cycles.csv`, run summaries, and manifests are kept under
`scalability/results/`.

## `datasets/`

The capture data used to calibrate and evaluate the T² detector — clean/normal runs and attack runs
(CPU flood, burst, stealth, combined), with cAdvisor snapshots and raw metric time series.

## `figure-data/`

The per-figure CSVs (`fig_4_xx_*`) that back the report's Chapter 4 figures, with a `SHA256SUMS` for
integrity.

## `figures/`

The rendered report figures (PDF) — detection latency, containment latency, T² time series, CPU
enforcement, scalability saturation, the four-lock-vs-K plot, and the policy-engine overhead
breakdown.

## `analysis/`

Scripts that turn the raw results into the figures and summary tables.
