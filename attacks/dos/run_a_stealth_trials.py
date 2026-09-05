#!/usr/bin/env python3
"""A_Stealth - low-intensity CPU staircase, N-trial evaluation of the T2
detector against the "hardest to catch" scenario in the suite (deliberately
staying close to the boundary of normal). Steps, durations (105s x4), and
calibrated cpu-load values (20/28/36/40, against a measured 56.638 mCPU
floor) copied unchanged from a_stealth_staircase.sh - operator decision
2026-07-24: use already-vetted durations, not further-compressed ones
(compressing this scenario specifically risks turning a deliberately
gradual/boundary-hugging test into just another obvious spike).

Run with: python3 run_a_stealth_trials.py [N_TRIALS]
"""
import sys
import time

import trial_harness_common as h

SCENARIO = "A_Stealth_staircase"
STEP_DURATION_SECONDS = 105
STEP_LOADS = [20, 28, 36, 40]
STEP_NAMES = ["0.7x_floor", "1.0x_floor", "1.3x_floor", "1.6x_floor"]
N_TRIALS_DEFAULT = 10


def attack_fn(pod: str, stop_event) -> None:
    # 2026-07-25: checks stop_event between steps - the harness's poll loop
    # runs concurrently with this thread now, so isolation can genuinely
    # happen mid-staircase; without this check the remaining steps would
    # keep escalating in the background after the trial has moved on.
    for i, (load, name) in enumerate(zip(STEP_LOADS, STEP_NAMES), start=1):
        if stop_event.is_set():
            return
        print(f"[t2-harness]     step {i}/{len(STEP_LOADS)} ({name}): "
              f"cpu-load={load}% for {STEP_DURATION_SECONDS}s", flush=True)
        h.run_stress_ng(pod, ["--cpu", "1", "--cpu-load", str(load), "--timeout", f"{STEP_DURATION_SECONDS}s"])
        stop_event.wait(STEP_DURATION_SECONDS)


def main() -> None:
    n_trials = int(sys.argv[1]) if len(sys.argv) > 1 else N_TRIALS_DEFAULT
    h.ensure_csv_headers()
    if not h.check_t2_service_active():
        print("[t2-harness] ERROR: ztx-t2-collector.service is not active. Enable it first.")
        sys.exit(1)

    already_done = h.load_completed_count(SCENARIO)
    print(f"[t2-harness] {SCENARIO}: {already_done}/{n_trials} done, running remaining trials")
    for trial_number in range(already_done + 1, n_trials + 1):
        print(f"[t2-harness]   trial {trial_number}/{n_trials} for {SCENARIO} "
              f"(4 steps x {STEP_DURATION_SECONDS}s, loads={STEP_LOADS}) ...", flush=True)
        row = h.run_trial(SCENARIO, trial_number, attack_fn, expected_to_detect=True)
        h.append_summary_row(row)
        h.print_trial_result(row)
    print(f"[t2-harness] {SCENARIO} complete.")


if __name__ == "__main__":
    main()
