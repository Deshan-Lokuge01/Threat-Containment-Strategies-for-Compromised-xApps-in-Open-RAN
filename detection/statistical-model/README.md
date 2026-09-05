# Statistical detection — the T² resource / DoS detector

Resource-exhaustion attacks (MITRE **T1499, Endpoint Denial of Service**) don't trip a kernel rule —
the xApp is doing "normal" things, just too much of them. We catch these with a deterministic
statistical detector rather than a black-box model (see
[`../../docs/research-journey.md`](../../docs/research-journey.md) for why we dropped the ML approach).

## How it works

The T² collector samples kpimon-go's resource metrics (CPU millicores, memory, network) and feeds a
**MEWMA (Multivariate Exponentially Weighted Moving Average)** control statistic. A sample above the
warning limit raises **SUSPICIOUS**; the detector only escalates to **COMPROMISED** when two
conditions hold together:

1. **6-of-8 corroboration** — at least six of the last eight samples exceed the upper control limit,
   so a single spike can't trigger isolation.
2. **CPU rate-of-exceedance gate** — sustained exceedance over a rolling window above the calibrated
   CPU floor.

By the time it fires, roughly a minute of corroborated evidence has accumulated. Every threshold is
frozen in a calibration manifest and is never retrained at runtime, so the decision is reproducible
and explainable.

## Why deterministic, not ML

A control that isolates workloads on its own has to be defensible. With frozen thresholds we can point
at the exact number that was crossed and for how long. A trained model gave us drift, false positives
on benign load bursts, and decisions we couldn't cleanly justify — fine for research, wrong for an
automatic containment trigger.

## Files

- `ztx_t2_collector.py` — the live collector and MEWMA / 6-of-8 / CPU-gate logic.
- `model/` — the frozen model and calibration manifests.
- `collector/` — resource-collection helpers.

The DoS attack scripts that exercise this detector are in
[`../../attacks/dos/`](../../attacks/dos/): sustained CPU flood, burst pulse-train, low-and-slow
stealth staircase, and a combined CPU+memory+disk scenario, plus a benign control that must **not**
trigger.
