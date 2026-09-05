# FYP Report Graph-to-Dataset Inventory

Canonical report inspected:

`/home/nearric/Downloads/report/FYP_Final_Report___Open_RAN_Threat_Containment-4.pdf`

The PDF has 130 pages and was created on 2026-08-26. This inventory covers all
20 data-bearing graphs. Architecture diagrams, workflow diagrams, and terminal
screenshots are listed separately because they do not have datasets.

## Status Legend

- **Exact**: the source dataset and its relationship to the plotted values were
  verified from a retained plotting script or loader.
- **Matched**: the source data were verified from values, dimensions, captions,
  and retained analysis outputs, but the exact final plotting script was not
  retained.
- **Missing raw data**: only the rendered graph and reported aggregate values
  remain on this VM.
- **Provenance mismatch**: the retained generator does not use the dataset
  claimed by the report.

## Graph Inventory

### Figure 3.8 - Benign M1 CPU distribution

**Status: Exact dataset match; final plot script not found.**

Raw datasets:

- `/home/nearric/Desktop/FYP/janindu lap/Undergraduate Project/New folder_DATA COLLECTION/N1/N1-OFFICIAL-1UE-10PPS-20260626T121005Z/raw_metrics.csv`
- `/home/nearric/Desktop/FYP/janindu lap/Undergraduate Project/New folder_DATA COLLECTION/N2/N2-OFFICIAL-1UE-10PPS-20260626T132023Z/raw_metrics.csv`

Column: `m1_cpu_millicores`.

The pooled 3,600 values reproduce the displayed statistics: mean
`1.611899 mCPU`, median `1.346000 mCPU`, approximate p99 `4.484 mCPU`, and
maximum `56.638 mCPU`. The graph truncates the displayed bulk at p99. The
"Idealized Skew Shape" is a fitted/illustrative overlay, not a separate
experimental dataset.

Report asset: `/home/nearric/Downloads/report/fig_m1_zoomed_skew.pdf`.

### Figure 3.9 - Raw z-score versus one-sided rectified contribution

**Status: Missing raw data; appears illustrative.**

No CSV, MATLAB script, MATLAB `.fig`, spreadsheet, or archive member containing
the plotted 600-second trajectory was found. Only the rendered file remains:

`/home/nearric/Downloads/report/one_sided_excess_detail.pdf`

The mathematical relationship is `max(0, z)` versus `abs(z)`, but the actual
trajectory cannot be reproduced exactly from a retained dataset.

### Figure 3.10 - Wilks CPU floor

**Status: Provenance mismatch. Do not treat the current graph as an empirical
plot of the claimed 5,400 samples.**

Intended real datasets:

- Figure 3.8's N1 and N2 raw CSVs.
- `/home/nearric/Desktop/FYP/janindu lap/Undergraduate Project/New folder_DATA COLLECTION/N3/N3-OFFICIAL-1UE-10PPS-20260626T142748Z/raw_metrics.csv`

The real `m1_cpu_millicores` values pool to `n=5,400`; their maximum is
`56.638 mCPU`. The frozen provenance is recorded in:

`/home/nearric/Desktop/FYP/janindu lap/Undergraduate Project/New folder_DATA COLLECTION/outputs/step76/20260703T102820Z/v5_frozen_gate_manifest.json`

However, the retained generator
`IEEE_CCNC_PAPER_FIGURES_STUDIO/paper_n3_fig2_wilks_cpu_floor_calibration.m`
uses `rng(42)` and synthesizes 1,200 Gaussian-derived values. It does not read
N1, N2, or N3. The figure should be regenerated from the three real CSVs before
submission.

### Figure 4.10 - Keylime system-admission overhead

**Status: Missing raw data. Only six plotted aggregate values remain.**

Visible values recovered from the vector PDF:

| Scenario | Admission latency (s) |
|---|---:|
| No attestation | 0.0013459 |
| 30 s period | 1.2662 |
| 10 s period | 1.2908 |
| 5 s period | 1.2862 |
| 2 s period | 1.3040 |
| 1 s period | 1.3048 |

Report asset: `/home/nearric/Downloads/report/keylime grph.pdf`.

No per-trial data, sample counts, uncertainty values, or generating script were
found anywhere under the home directory or in the inspected report archives.

### Figure 4.18 - Secure-onboarding latency over 200 trials

**Status: Missing raw data.**

Only the rendered PNG remains:

`/home/nearric/Downloads/report/Secure_onboading_graph.png`

The report gives summary information (native mean `2.53 s`, zero-trust mean
`9.91 s`, and zero-trust range approximately `3-17 s`), but the two 200-value
trial series, a generation script, and a spreadsheet were not found. Pixel
digitization would only produce approximations and should not be represented as
the original dataset.

### Figures 4.19 and 4.20 - Behavioral detection and containment

**Status: Exact.** Both figures use the same 400-trial dataset (eight attacks,
50 trials per attack):

`/home/nearric/Desktop/FYP/zt-xguard/xApps_Attcks/evaluation/kpimon_latency_trials.csv`

The audit copy consumed by MATLAB is:

`/home/nearric/Desktop/FYP/zt-xguard/xApps_Attcks/evaluation/figures_matlab/data/kpimon_latency_trials.csv`

Figure 4.19 uses attack-to-first-visible-decision/action and full containment
latencies. Figure 4.20 uses the per-mechanism columns
`quarantine_label_latency_ms`, `svid_disabled_latency_ms`,
`service_isolated_latency_ms`, `network_unreachable_latency_ms`, and
`direct_iptables_latency_ms`.

Verified loader/generator:

- `xApps_Attcks/evaluation/figures_matlab/ztx_load_falco.m`
- `xApps_Attcks/evaluation/figures_matlab/fig_falco_02_containment_and_network_latency.m`

The analysis folds `outcome in {pass, wrong_rule}` into successful containment;
this is documented in `xApps_Attcks/evaluation/HANDOVER_ieee_ccnc_figures.md`.

### Figure 4.21 - Held-out clean D1/D2 score timelines

**Status: Exact, with report aliases.**

The report's D1 and D2 labels map as follows:

| Report label/panel | Collection ID | Plot-ready scores | Raw telemetry |
|---|---|---|---|
| D1 (top) | D4 | `outputs/step77/20260703T133033Z/step77_d4_final_scores.csv` | `D4/D4-CURRENT-NORMAL-SANITY-V1-1UE-10PPS-20260702T150850Z/raw_metrics.csv` |
| D2 (bottom) | N5 | `outputs/step77/20260703T133033Z/step77_n5_final_scores.csv` | `N5/N5-CLEAN-1UE-10PPS-20260629T042240Z/raw_metrics.csv` |

All four relative paths are under:

`/home/nearric/Desktop/FYP/janindu lap/Undergraduate Project/New folder_DATA COLLECTION/`

Generator: `fig_c_clean_timelines_d4_n5.m` in that same directory.

### Figure 4.22 - A1 CPU-exhaustion development timeline

**Status: Exact, with a report alias.** Report A1 maps to collection
`R1_FRESH`.

Plot-ready scores:

`.../outputs/step77/20260703T133033Z/step77_r1_fresh_final_scores.csv`

Raw telemetry:

`.../R1-CPU-BOUNDED-FRESH-BLIND-20260703T121547Z/raw_metrics.csv`

Generator: `.../fig2_representative_detection_timeline.m`.

Here and below, `...` means the mathematical-model base directory shown under
Figure 4.21.

### Figure 4.23 - A2 combined CPU and memory evaluation

**Status: Exact, with a report alias and a data-quality caveat.** Report A2 maps
to the collection ID `R6_STEALTH_COMBINED60M_V1`.

Plot-ready scores:

`.../outputs/step76/20260703T102820Z/step76_r6_v5_scores.csv`

Raw telemetry:

`.../R6/R6-STEALTH-COMBINED60M-V1-1UE-10PPS-20260702T180528Z/raw_metrics.csv`

Generator lineage: `.../fig2e_r6_representative_timeline.m` and
`.../matlab/fig_I_r6_multivariate.m`.

The collection contains 5,700 raw samples and matches the report's 58-minute
active phase. The retained generator documents
`final_collection_acceptance=0` due to 51 metrics-endpoint errors, 60 timing
errors, and sample lag up to about 18 seconds. This caveat should accompany the
result.

### Figure 4.24 - A3 stealth staircase

**Status: Exact.**

Plot-ready scores:

`.../outputs/step80/20260704T043144Z/step80_scored_a_stealth.csv`

Raw telemetry and ground-truth phase timeline:

- `.../A-STEALTH-BOUNDARY-FULL-BLIND-20260704T005034Z/raw_metrics.csv`
- `.../A-STEALTH-BOUNDARY-FULL-BLIND-20260704T005034Z/stealth_phase_timeline.csv`

Generator: `.../fig2c_a_stealth_representative_timeline.m`.

### Figure 4.25 - A4 burst pulse train

**Status: Exact.**

Plot-ready scores:

`.../outputs/step81/20260704T043215Z/step81_scored_a_burst.csv`

Raw telemetry and pulse ground truth:

- `.../A-BURST-PULSETRAIN-BLIND-20260704T023154Z/raw_metrics.csv`
- `.../A-BURST-PULSETRAIN-BLIND-20260704T023154Z/burst_pulses_timeline.csv`

Generator: `.../fig2d_a_burst_representative_timeline.m`.

### Figure 4.26 - Deployed statistical detection/containment latency

**Status: Exact dataset; exact final plotting script not retained.**

Per-trial dataset (51 rows plus header):

`/home/nearric/Desktop/FYP/zt-xguard/xApps_Attcks/evaluation/kpimon_t2_trials_clean.csv`

The graph uses `detection_latency_ms` and `post_dwell_overhead_ms` grouped by
`scenario`. The fixed 30-second dwell is intentionally omitted from the plotted
containment values. Superseded CSVs in this directory are explicitly invalid and
must not be substituted.

### Figure 4.27 - Reversible CPU throttle

**Status: Exact.**

Per-tick dataset:

`/home/nearric/Desktop/FYP/zt-xguard/xApps_Attcks/evaluation/kpimon_t2_timeseries.csv`

Trial event metadata:

`/home/nearric/Desktop/FYP/zt-xguard/xApps_Attcks/evaluation/kpimon_t2_trials_clean.csv`

Generator:

`/home/nearric/Desktop/FYP/zt-xguard/xApps_Attcks/evaluation/figures_matlab/fig_t2_12_cpu_enforcement.m`

The primary plotted column is `m1_cpu_millicores`; detection and throttle markers
come from the per-trial CSV.

### Figure 4.28 - RIC indication/network throughput cutoff

**Status: Exact.**

Plot-ready aligned dataset:

`/home/nearric/Desktop/FYP/zt-xguard/xApps_Attcks/evaluation/kpimon_t2_network_throughput_aligned.csv`

Parent datasets:

- `xApps_Attcks/evaluation/kpimon_t2_timeseries_network_demo.csv`
- `xApps_Attcks/evaluation/kpimon_t2_trials_network_demo.csv`

Generator: `xApps_Attcks/evaluation/make_ccnc_extra_figs.py` (first plotting
block). It aligns ten mechanism-verification trials to `isolated_rel_s` and bins
RX/TX rates in two-second intervals. This small network-demo batch is separate
from the canonical 51-row statistical evaluation dataset.

### Figure 4.29 - Detector computational scalability

**Status: Exact.**

Plot-ready dataset:

`experiments/scalability/scalability_matlab_package/exp1_detector_scaling.csv`

Raw campaign datasets:

- `experiments/scalability/results/campaign-20260808T051632Z/exp1/detector_cycles.csv`
- `experiments/scalability/results/campaign-20260808T051632Z/exp1/detector_run_summary.csv`
- `experiments/scalability/results/campaign-20260808T051632Z/exp1/detector_workload_accounting.csv`

Generator: `experiments/scalability/scalability_matlab_package/fig_exp1_detector.m`.

### Figures 4.30 and 4.31 - Evaluator deadline misses and saturation knee

**Status: Exact.** Both use:

`experiments/scalability/scalability_matlab_package/exp2_evaluator_scaling.csv`

Raw campaign datasets:

- `experiments/scalability/results/campaign-20260808T051632Z/exp2/sweep/evaluator_requests.csv`
- `experiments/scalability/results/campaign-20260808T051632Z/exp2/sweep/evaluator_run_summary.csv`
- `experiments/scalability/results/campaign-20260808T051632Z/exp2/sweep/evaluator_xapp_accounting.csv`

Generators:

- Figure 4.30: `fig_exp2_deadline_miss.m`
- Figure 4.31 upper panel: `fig_exp2_saturation.m`
- Figure 4.31 lower panel: `fig_exp2_latency.m`

All generators are in `experiments/scalability/scalability_matlab_package/`.

### Figure 4.32 - Concurrent four-lock containment

**Status: Exact.**

Plot-ready per-trial dataset:

`experiments/scalability/scalability_matlab_package/exp3_trials.csv`

Plot-ready summary:

`experiments/scalability/scalability_matlab_package/exp3_perK_summary.csv`

Raw campaign datasets:

- `experiments/scalability/results/campaign-20260808T051632Z/exp3_formal/concurrent_containment_raw.csv`
- `experiments/scalability/results/campaign-20260808T051632Z/exp3_formal/concurrent_containment_trials.csv`
- `experiments/scalability/results/campaign-20260808T051632Z/exp3_formal/figures/exp3_graph_ready.csv`

Generator: `experiments/scalability/scalability_matlab_package/fig_exp3_fourlock.m`.

### Figure 4.33 - Policy-engine CPU and memory overhead

**Status: Exact.** Both panels use:

`experiments/overhead_comparison/components_timeseries.csv`

Generator:

`experiments/overhead_comparison/build_policyengine_figures.py`

The upper panel combines `baseline_cores` and `policy_engine_cores`; the lower
panel combines `baseline_mem_mb` and `policy_engine_mem_mb`. The older
`overhead_timeseries.csv` measures a broader framework configuration and is not
the source used by the report's policy-engine-only graph.

## Figures Without Datasets

The following are diagrams or screenshots rather than graphs backed by numeric
datasets: Figures 1.1, 1.2, 3.1-3.7, 3.11, 4.1-4.9, and 4.11-4.17.

## Required Corrections Before Reuse

1. Regenerate Figure 3.10 directly from N1, N2, and N3. The retained generator
   currently creates synthetic values and contradicts the caption.
2. Recover the original per-trial data for Figures 4.10 and 4.18 from the team
   members or machines that ran those experiments. The VM only retains rendered
   outputs and summary values.
3. Disclose Figure 4.23's documented collection-quality failure, or rerun the
   A2/R6 combined attack collection under the frozen model.
4. Preserve the D1/D2/A1/A2 alias mapping above when packaging supplementary
   data; renaming files without a provenance table makes the report difficult to
   audit.
