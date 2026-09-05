#!/usr/bin/env python3
"""A_Burst - pulse-train of 5 increasing-duration CPU bursts, N-trial
evaluation of the T2 resource-anomaly detector's evasion resistance
(duty-cycled/bursty attacker vs. an occasional benign burst - the exact
failure mode the v5 rate-of-exceedance CPU gate was redesigned to catch).
Pulse durations (5/10/20/40/60s) and cpu-load copied unchanged from
a_burst_pulse_train.sh - these ARE the scenario, not compressible.
Cooldown between pulses also kept unchanged (45s) - operator decision
2026-07-24: use already-vetted durations, not further-compressed ones.

Run with: python3 run_a_burst_trials.py [N_TRIALS]
"""
import sys
import time

import trial_harness_common as h

SCENARIO = "A_Burst_pulse_train"
BURST_CPU_LOAD = 100
PULSES = [5, 10, 20, 40, 60]
COOLDOWN_SECONDS = 45
N_TRIALS_DEFAULT = 10


def attack_fn(pod: str, stop_event) -> None:
    # 2026-07-25: checks stop_event between AND during phases now - the
    # harness's poll loop runs concurrently with this thread (not after
    # it), so isolation can genuinely happen mid-pulse-train. Without this
    # check, a stopped/isolated trial would keep firing later pulses in
    # the background after the harness has already moved on to restore/
    # the next trial - real cross-trial contamination, not just wasted work.
    for i, burst_s in enumerate(PULSES, start=1):
        if stop_event.is_set():
            return
        print(f"[t2-harness]     pulse {i}/{len(PULSES)}: {burst_s}s @ {BURST_CPU_LOAD}% load", flush=True)
        h.run_stress_ng(pod, ["--cpu", "1", "--cpu-load", str(BURST_CPU_LOAD), "--timeout", f"{burst_s}s"])
        stop_event.wait(burst_s)
        h.cleanup_stress_ng(pod)
        if stop_event.is_set():
            return
        if i < len(PULSES):
            stop_event.wait(COOLDOWN_SECONDS)


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
              f"(pulses={PULSES}s cooldown={COOLDOWN_SECONDS}s) ...", flush=True)
        row = h.run_trial(SCENARIO, trial_number, attack_fn, expected_to_detect=True)
        h.append_summary_row(row)
        h.print_trial_result(row)
    print(f"[t2-harness] {SCENARIO} complete.")


if __name__ == "__main__":
    main()
