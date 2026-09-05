#!/usr/bin/env python3
"""R1 - Sustained CPU flood, N-trial evaluation of the T2 resource-anomaly
detector. Intensity/duration copied unchanged from r1_sustained_cpu_flood.sh
(itself unchanged from the frozen calibration script) - operator decision
2026-07-24: use the already-vetted demo duration, not a further-compressed
one, for a real publication's worth of data.

Run with: python3 run_r1_trials.py [N_TRIALS]
"""
import sys
import time

import trial_harness_common as h

SCENARIO = "R1_sustained_cpu_flood"
ATTACK_SECONDS = 120
CPU_LOAD = 20
N_TRIALS_DEFAULT = 10


def attack_fn(pod: str, stop_event) -> None:
    h.run_stress_ng(pod, ["--cpu", "1", "--cpu-load", str(CPU_LOAD), "--timeout", f"{ATTACK_SECONDS}s"])
    stop_event.wait(ATTACK_SECONDS)


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
              f"(cpu-load={CPU_LOAD}% duration={ATTACK_SECONDS}s) ...", flush=True)
        row = h.run_trial(SCENARIO, trial_number, attack_fn, expected_to_detect=True)
        h.append_summary_row(row)
        h.print_trial_result(row)
    print(f"[t2-harness] {SCENARIO} complete.")


if __name__ == "__main__":
    main()
