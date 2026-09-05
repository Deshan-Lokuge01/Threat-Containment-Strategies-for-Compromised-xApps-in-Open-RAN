#!/usr/bin/env python3
"""A_Burst pulse-train, rigorously-instrumented network-isolation
demonstration run. Same attack_fn as run_a_burst_trials.py (unchanged
pulses/cooldown), routed through the same upgraded trial_harness_common.
run_trial() used by run_r1_network_demo.py, appending to the SAME demo
output files (kpimon_t2_trials_network_demo.csv / kpimon_t2_timeseries_
network_demo.csv) alongside R1's already-collected 10 trials -- the
canonical N=51 statistical dataset is never touched.

Run with: python3 run_a_burst_network_demo.py [N_TRIALS]
"""
import sys

import trial_harness_common as h

h.SUMMARY_CSV = h.RESULTS_DIR / "kpimon_t2_trials_network_demo.csv"
h.TIMESERIES_CSV = h.RESULTS_DIR / "kpimon_t2_timeseries_network_demo.csv"

SCENARIO = "A_Burst_pulse_train"
BURST_CPU_LOAD = 100
PULSES = [5, 10, 20, 40, 60]
COOLDOWN_SECONDS = 45
N_TRIALS_DEFAULT = 10


def attack_fn(pod: str, stop_event) -> None:
    for i, burst_s in enumerate(PULSES, start=1):
        if stop_event.is_set():
            return
        print(f"[network-demo]     pulse {i}/{len(PULSES)}: {burst_s}s @ {BURST_CPU_LOAD}% load", flush=True)
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
        print("[network-demo] ERROR: ztx-t2-collector.service is not active. Enable it first.")
        sys.exit(1)

    already_done = h.load_completed_count(SCENARIO)
    print(f"[network-demo] writing to {h.SUMMARY_CSV.name} / {h.TIMESERIES_CSV.name} "
          f"(canonical N=51 dataset untouched)")
    print(f"[network-demo] {SCENARIO}: {already_done}/{n_trials} done, running remaining trials")
    for trial_number in range(already_done + 1, n_trials + 1):
        print(f"[network-demo]   trial {trial_number}/{n_trials} for {SCENARIO} "
              f"(pulses={PULSES}s cooldown={COOLDOWN_SECONDS}s) ...", flush=True)
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
