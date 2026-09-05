#!/usr/bin/env python3
"""R1 sustained-CPU-flood, rigorously-instrumented network-isolation
demonstration run. Same attack_fn as run_r1_trials.py (unchanged intensity/
duration), routed through the same upgraded trial_harness_common.run_trial()
used by the real scenario scripts, but writes to SEPARATE output files so
the canonical, already-published N=51 statistical dataset
(kpimon_t2_trials_clean.csv / kpimon_t2_timeseries.csv) is never touched.

Captures, for each trial: SVID/identity revocation, retry-verified direct-
iptables blocking, an active TCP reachability probe (baseline + post-
isolation), paired RX/TX byte counters, and an extended ~90s post-isolation
observation hold so sustained near-zero throughput is actually visible in
the time series, not just the transition instant.

Run with: python3 run_r1_network_demo.py [N_TRIALS]
"""
import sys

import trial_harness_common as h

# Redirect output BEFORE any trial runs -- keeps the canonical N=51
# dataset files completely untouched.
h.SUMMARY_CSV = h.RESULTS_DIR / "kpimon_t2_trials_network_demo.csv"
h.TIMESERIES_CSV = h.RESULTS_DIR / "kpimon_t2_timeseries_network_demo.csv"

SCENARIO = "R1_sustained_cpu_flood"
ATTACK_SECONDS = 120
CPU_LOAD = 20
N_TRIALS_DEFAULT = 3


def attack_fn(pod: str, stop_event) -> None:
    h.run_stress_ng(pod, ["--cpu", "1", "--cpu-load", str(CPU_LOAD), "--timeout", f"{ATTACK_SECONDS}s"])
    stop_event.wait(ATTACK_SECONDS)


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
              f"(cpu-load={CPU_LOAD}% duration={ATTACK_SECONDS}s) ...", flush=True)
        row = h.run_trial(SCENARIO, trial_number, attack_fn, expected_to_detect=True)
        h.append_summary_row(row)
        h.print_trial_result(row)
        print(f"[network-demo]   -> baseline_reachable={row['network_baseline_reachable']} "
              f"network_unreachable_ms={row['network_unreachable_latency_ms']} "
              f"svid_disabled={row['svid_disabled_at_isolation']} "
              f"quarantine={row['quarantine_marked_at_isolation']} "
              f"service_isolated={row['service_isolated_at_isolation']} "
              f"direct_iptables={row['direct_network_isolated_at_isolation']} "
              f"(rechecks={row['direct_network_isolated_recheck_attempts']}) "
              f"rx_baseline={row['net_rx_bytes_baseline']} rx_at_isolated={row['net_rx_bytes_at_isolated']}",
              flush=True)
    print(f"[network-demo] {SCENARIO} network demo complete.")


if __name__ == "__main__":
    main()
