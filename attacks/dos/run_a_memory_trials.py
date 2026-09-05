#!/usr/bin/env python3
"""A_Memory - gradual memory ramp then sustained hold, N-trial evaluation
of the T2 detector against a real attack the model's own frozen gate
manifest predicts it will NOT confirm as COMPROMISED: decision_gates=["cpu"]
only (v5_frozen_gate_manifest.json) - m4/memory was excluded after the
underlying instrumentation was found to produce physically-inconsistent
values on both benign and attack data, with no quality flag raised. A pure
memory stressor doesn't reliably drive CPU over the 56.638 mCPU floor the
CPU gate requires.

IMPORTANT semantic note (different from A5's true benign control):
expected_to_detect=False here does NOT mean "this is benign, a detection
would be a false positive" - this IS a real resource-exhaustion attack.
"pass" in this scenario's results means "the model behaved exactly as its
own documentation predicts" (T2 score elevated, decision never confirmed) -
a validated, citable negative result confirming a known, honestly-
documented model limitation, not a true-negative security outcome. If a
trial ever DOES confirm COMPROMISED, that's flagged as "false_positive" by
the shared harness's outcome labeling for bookkeeping purposes, but treat
it as "unexpectedly detected, worth investigating" rather than a genuine
false alarm.

Ramp/hold durations copied unchanged from a_memory_ramp_hold.sh. Fewer
trials than the other scenarios by design - the expected outcome (score
climbs, decision never confirmed) doesn't need as large an N to document
reliably, and this scenario's own total runtime is long.

Run with: python3 run_a_memory_trials.py [N_TRIALS]
"""
import sys
import time

import trial_harness_common as h

SCENARIO = "A_Memory_ramp_hold"
TARGET_MEMORY_MB = 32
RAMP_SECONDS = 60
RAMP_STEPS = 6
STEP_DURATION = RAMP_SECONDS // RAMP_STEPS
STEP_SIZE = TARGET_MEMORY_MB // RAMP_STEPS
HOLD_SECONDS = 360
N_TRIALS_DEFAULT = 6


def attack_fn(pod: str, stop_event) -> None:
    # 2026-07-25: checks stop_event between phases - the harness's poll
    # loop runs concurrently with this thread now, so an early COMPROMISED
    # confirmation (the "worth investigating" case per this scenario's own
    # docs above) needs to stop the ramp/hold rather than keep escalating
    # in the background after the trial has moved on.
    for step in range(1, RAMP_STEPS + 1):
        if stop_event.is_set():
            return
        current_mb = STEP_SIZE * step
        print(f"[t2-harness]     ramp step {step}/{RAMP_STEPS}: {current_mb}MB for {STEP_DURATION}s", flush=True)
        h.run_stress_ng(pod, ["--vm", "1", "--vm-bytes", f"{current_mb}M", "--timeout", f"{STEP_DURATION}s"])
        stop_event.wait(STEP_DURATION)
    if stop_event.is_set():
        return
    print(f"[t2-harness]     sustained hold: {TARGET_MEMORY_MB}MB for {HOLD_SECONDS}s", flush=True)
    h.run_stress_ng(pod, ["--vm", "1", "--vm-bytes", f"{TARGET_MEMORY_MB}M", "--timeout", f"{HOLD_SECONDS}s"])
    stop_event.wait(HOLD_SECONDS)


def main() -> None:
    n_trials = int(sys.argv[1]) if len(sys.argv) > 1 else N_TRIALS_DEFAULT
    h.ensure_csv_headers()
    if not h.check_t2_service_active():
        print("[t2-harness] ERROR: ztx-t2-collector.service is not active. Enable it first.")
        sys.exit(1)

    already_done = h.load_completed_count(SCENARIO)
    print(f"[t2-harness] {SCENARIO}: {already_done}/{n_trials} done, running remaining trials")
    print(f"[t2-harness] NOTE: decision_gates=['cpu'] only - this scenario is expected to "
          f"show elevated T2 score but NOT confirm COMPROMISED, per the model's own documentation.")
    for trial_number in range(already_done + 1, n_trials + 1):
        print(f"[t2-harness]   trial {trial_number}/{n_trials} for {SCENARIO} "
              f"(target={TARGET_MEMORY_MB}MB ramp={RAMP_SECONDS}s hold={HOLD_SECONDS}s) ...", flush=True)
        row = h.run_trial(SCENARIO, trial_number, attack_fn, expected_to_detect=False)
        h.append_summary_row(row)
        h.print_trial_result(row)
    print(f"[t2-harness] {SCENARIO} complete.")


if __name__ == "__main__":
    main()
