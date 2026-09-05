#!/usr/bin/env python3
"""R6 - combined low-and-slow CPU + memory + disk stress, N-trial
evaluation of the T2 detector against a multi-resource-vector stealth
attack. Intensity values (cpu-load/vm-bytes/hdd-bytes) and duration (360s)
copied unchanged from r6_stealth_combined.sh (itself a reconstruction of
the recorded frozen-calibration invocation - no standalone original script
survived, see that script's own header). Operator decision 2026-07-24: use
already-vetted duration, not a further-compressed one - one of the three
"low and slow" scenarios, duration-sensitive.

Run with: python3 run_r6_trials.py [N_TRIALS]
"""
import sys
import time

import trial_harness_common as h

SCENARIO = "R6_stealth_combined"
DURATION_SECONDS = 360
CPU_LOAD = 10
VM_BYTES = "16M"
HDD_BYTES = "16M"
N_TRIALS_DEFAULT = 10


def attack_fn(pod: str, stop_event) -> None:
    h.run_stress_ng(
        pod,
        ["--cpu", "1", "--cpu-load", str(CPU_LOAD),
         "--vm", "1", "--vm-bytes", VM_BYTES,
         "--hdd", "1", "--hdd-bytes", HDD_BYTES,
         "--timeout", f"{DURATION_SECONDS}s"],
    )
    stop_event.wait(DURATION_SECONDS)


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
              f"(cpu={CPU_LOAD}% vm={VM_BYTES} hdd={HDD_BYTES} duration={DURATION_SECONDS}s) ...", flush=True)
        row = h.run_trial(SCENARIO, trial_number, attack_fn, expected_to_detect=True)
        h.append_summary_row(row)
        h.print_trial_result(row)
    print(f"[t2-harness] {SCENARIO} complete.")


if __name__ == "__main__":
    main()
