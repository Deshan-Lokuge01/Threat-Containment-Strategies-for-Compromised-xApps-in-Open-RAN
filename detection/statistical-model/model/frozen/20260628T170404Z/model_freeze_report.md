# ZT-XGuard Step 42 Model Freeze Report

Generated: 2026-06-28T17:04:04Z

## Frozen Configuration

- Window W: 5 seconds
- Half-life H: 3 seconds
- Lambda: 0.206299
- Warning quantile: 0.975
- Upper-control quantile: 0.995
- Persistence: K=8 of L=10 scored states

## Frozen N3 Calibration Evidence

- First scored state: 24 seconds
- Warning limit: 311.9748221181776
- Upper limit: 324.00635209317034
- Upper false-positive rate on clean N3: 0.005148741418764302
- Upper true-negative rate on clean N3: 0.9948512585812357
- Persistent upper false-positive rate on clean N3: 0.0
- Persistent upper true-negative rate on clean N3: 1.0

## State Policy

The detector directly supports NORMAL and SUSPICIOUS resource-behavior decisions. COMPROMISED is assigned only with corroborating attack/context evidence such as CALDERA operation logs, stress-ng command evidence, labelled attack ground truth, or operator review. Resource metrics alone must not be used as proof of compromise.

## Freeze Boundary

After this artifact, evaluation data and attack data must be scored without changing transforms, centers, scales, feature set, covariance, MEWMA-state covariance, lambda, thresholds, persistence, or M3 scoring policy.
