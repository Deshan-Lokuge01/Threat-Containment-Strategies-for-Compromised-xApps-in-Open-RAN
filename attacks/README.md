# Attack scripts

The scripts used to exercise both detection channels. These are the same operations the dashboard's
Attack Console launches. They resolve the target pod and `kubectl exec` into it, so they need access
to the same cluster that runs the testbed.

## `behavioural/` — Falco (kernel) attacks

One script per Falco rule, per xApp target (`hw-go`, `hw-python`, `kpimon-go`, `qos-optimizer`,
`resource-optimizer`, `security-observer`, `telemetry-monitor`, `traffic-analyzer`, `trafficxapp`).
Each performs a single forbidden action so the matching rule fires: unexpected shell, sensitive file
access, ServiceAccount token access, external egress, SVID material access, config tamper, package
manager execution, binary drop, permission tamper, Kubernetes API contact, privileged container
escape, and more.

```bash
cd behavioural/traffic-analyzer
./ZTX-A1_unexpected_shell.sh
```

## `dos/` — resource-exhaustion (DoS, T1499)

`stress-ng`-based load against **kpimon-go** (the xApp the T² detector watches). Four scenarios plus
a benign control:

| Script | Shape |
|--------|-------|
| `r1_sustained_cpu_flood.sh` | sustained CPU load — the obvious attack |
| `a_burst_pulse_train.sh` | repeated CPU bursts vs the 6-of-8 confirmation gate |
| `a_stealth_staircase.sh` | low-and-slow step-wise CPU escalation |
| `r6_stealth_combined.sh` | combined CPU + memory + disk pressure |
| `a5_legitimate_control.sh` | benign control — must **not** trigger (false-positive check) |

The `run_*_trials.py` harnesses run these repeatedly and capture timelines for the evaluation.

```bash
cd dos
./r1_sustained_cpu_flood.sh
```

> Intensity/shape for the DoS scripts is frozen to match the detector's calibrated thresholds — don't
> change the `--cpu-load` values. Durations were shortened from the original 15-minute captures for
> live demos.
