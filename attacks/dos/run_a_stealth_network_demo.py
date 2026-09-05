#!/usr/bin/env python3
"""A_Stealth staircase, rigorously-instrumented network-isolation
demonstration run. Same attack_fn as run_a_stealth_trials.py (unchanged
steps/durations), routed through the same upgraded trial_harness_common.
run_trial() used by run_r1_network_demo.py, appending to the SAME demo
output files alongside R1's and A_Burst's already-collected trials -- the
canonical N=51 statistical dataset is never touched.

Run with: python3 run_a_stealth_network_demo.py [N_TRIALS]
"""
import sys

import trial_harness_common as h

h.SUMMARY_CSV = h.RESULTS_DIR / "kpimon_t2_trials_network_demo.csv"
h.TIMESERIES_CSV = h.RESULTS_DIR / "kpimon_t2_timeseries_network_demo.csv"

SCENARIO = "A_Stealth_staircase"
STEP_DURATION_SECONDS = 105
STEP_LOADS = [20, 28, 36, 40]
STEP_NAMES = ["0.7x_floor", "1.0x_floor", "1.3x_floor", "1.6x_floor"]
N_TRIALS_DEFAULT = 10


def attack_fn(pod: str, stop_event) -> None:
    for i, (load, name) in enumerate(zip(STEP_LOADS, STEP_NAMES), start=1):
        if stop_event.is_set():
            return
        print(f"[network-demo]     step {i}/{len(STEP_LOADS)} ({name}): "
              f"cpu-load={load}% for {STEP_DURATION_SECONDS}s", flush=True)
        h.run_stress_ng(pod, ["--cpu", "1", "--cpu-load", str(load), "--timeout", f"{STEP_DURATION_SECONDS}s"])
        stop_event.wait(STEP_DURATION_SECONDS)


def main() -> None:
    n_trials = int(sys.argv[1]) if len(sys.argv) > 1 else N_TRIALS_DEFAULT
    h.ensure_csv_headers()
    if not h.check_t2_service_active():
        print("[network-demo] ERROR: ztx-t2-collector.service is not active. Enable it first.")
        sys.exit(1)

    already_done = h.load_completed_count(SCENARIO)
    print(f"[network-demo] writing to {h.SUMMARY_CSV.name} / {h.TIMESERIES_CSV.name} "
          f"(canonical N=51 dataset untouched)")
    print(f"[network-demo] {SCENARIO}: {already_done}/{n_trials} done, running remaining trials")
    for trial_number in range(already_done + 1, n_trials + 1):
        print(f"[network-demo]   trial {trial_number}/{n_trials} for {SCENARIO} "
              f"(4 steps x {STEP_DURATION_SECONDS}s, loads={STEP_LOADS}) ...", flush=True)
        row = h.run_trial(SCENARIO, trial_number, attack_fn, expected_to_detect=True)
        h.append_summary_row(row)
        h.print_trial_result(row)
        print(f"[network-demo]   -> baseline_reachable={row['network_baseline_reachable']} "
              f"network_unreachable_ms={row['network_unreachable_latency_ms']} "
              f"svid_disabled={row['svid_disabled_at_isolation']} "
              f"quarantine={row['quarantine_marked_at_isolation']} "
              f"service_isolated={row['service_isolated_at_isolation']} "
              f"direct_iptables={row['direct_network_isolated_at_isolation']} "
              f"(rechecks={row['direct_network_isolated_recheck_attempts']})", flush=True)
    print(f"[network-demo] {SCENARIO} network demo complete.")


if __name__ == "__main__":
    main()
