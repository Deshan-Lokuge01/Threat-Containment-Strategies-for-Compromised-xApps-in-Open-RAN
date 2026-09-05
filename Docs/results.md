# Results

All numbers below come from measurements on the live testbed. Figures are in
[`../evaluation/figures/`](../evaluation/figures/); raw data in [`../evaluation/`](../evaluation/).

## Containment latency (per mechanism)

The four locks run in parallel, so wall-clock containment is the slowest — the SVID withdrawal.

| Lock | Measured time-to-effect |
|------|------------------------|
| Calico NetworkPolicy (control-plane apply) | ~0.06–0.28 s |
| Service isolation (real endpoint drain) | ~0.4–0.8 s |
| Node iptables DROP (rule + verify) | ~0.8–1.3 s |
| SVID revocation (full SPIRE withdrawal) | ~3.7–4.6 s |
| **Parallel total (≈ SVID)** | **~4–5 s** |

## Detection

- **Behavioural (Falco):** kernel-event detection is effectively immediate (millisecond decision
  once the syscall is observed).
- **Resource / DoS (T²):** detection is the time from attack onset to confirmed COMPROMISED —
  seconds, dominated by the 6-of-8 corroboration window (roughly a minute of evidence), by design.

## Scalability

**Detector scaling** (state-engine update latency, N monitored contexts, 5 reps each):

| N | updates | p50 (ms) | p95 (ms) | deadline misses |
|---|---------|----------|----------|-----------------|
| 1 | 1,540 | 0.04 | 0.07 | 0 |
| 10 | 15,400 | 0.40 | 0.82 | 0 |
| 40 | 61,600 | 1.72 | 3.93 | 0 |
| 80 | 123,200 | 3.56 | 7.62 | 0 |

Latency grows linearly and stays sub-10 ms at p95 up to N=80, with **zero deadline misses**.

**Evaluator scaling** (offered vs achieved evaluation rate): clean completion up to ~25 eval/s; the
saturation knee is around 30 eval/s (deadline misses rise sharply), capped by a single CPU core.

**Physical containment** (real concurrent isolation of K xApps): 26/26 isolations succeeded across
K=1…4; per-incident network cutoff median rose from ~1.9 s (K=1) to ~7.6 s (K=4), identity revocation
median ~1.6 s → ~5.0 s.

## Takeaway

Detection is deterministic and explainable; containment is layered and completes in a few seconds
even under concurrent load; and the control plane scales linearly well past the size of a realistic
Near-RT RIC xApp fleet.
