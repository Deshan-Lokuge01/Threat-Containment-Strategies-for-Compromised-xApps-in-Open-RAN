# ZT-XGuard Step 45 Report: Corrective Model v2

**Generated:** 2026-06-29T03:05:07Z  
**Reason:** Step 44H failed because absolute M3 memory baseline dominated clean N4 T2 scores.  
**Corrective action:** remove M3 from the covariance detector and retain M4 memory-growth dynamics.  

N1 and N2 were used for fitting. N3 was used for clean calibration. N4 was scored only after the v2 artifact was frozen and is post-hoc diagnostic evidence, not a new untouched final test.

| Selected v2 field | Value |
|---|---:|
| Window seconds | 8 |
| Half-life seconds | 3 |
| Lambda | 0.206299 |
| Warning limit | 12.8587 |
| Upper limit | 25.5888 |
| Persistence K/L | 12/16 |

| N4 post-hoc diagnostic metric | Value |
|---|---:|
| Warning FP rate | 0.0395415 |
| UCL FP rate | 0.00229226 |
| Persistent upper FP rate | 0 |
| Public NORMAL occupancy | 0.960458 |

Next required validation: collect a new N5 clean normal run after this v2 freeze and score it once as the untouched final clean evaluation.