#!/usr/bin/env bash
# A_Burst - pulse-train of 5 increasing-duration CPU bursts, against
# kpimon-go only.
#
# Mechanism, pulse durations, and cpu-load copied unchanged from the frozen
# evaluation script (Attacks scripts/A_Burst_pulse_train/
# ztx-step81-a-burst-pulse-train-blind.sh): 5 pulses of 5/10/20/40/60
# seconds, at cpu-load=100% (calibrated to measure ~200 mCPU average,
# matching R1's intensity - only the duration/shape differs between R1 and
# A_Burst, not the intensity). The pulse durations themselves are the whole
# point of this scenario (testing whether brief spikes get caught) so they
# are NOT compressed. Only the cooldown between pulses was cut, from 300s
# to 45s, on 2026-07-16 for live demo use (5 cooldowns x 45s + 135s of
# pulses = 6 min total, down from ~27 min). Override BURST_CPU_LOAD=<n>
# before calling this script if a different load is ever needed, matching
# the original's env-var override pattern.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

BURST_CPU_LOAD=${BURST_CPU_LOAD:-100}
PULSES=(5 10 20 40 60)
COOLDOWN_SECONDS=45

POD=$(ztx_resolve_kpimon_pod)
ztx_preflight "$POD"
trap 'ztx_cleanup_stress_ng "$POD"' EXIT

echo "=== A_Burst pulse train: pod=$POD load=${BURST_CPU_LOAD}% pulses=${PULSES[*]}s cooldown=${COOLDOWN_SECONDS}s ==="

pulse_num=1
for burst_s in "${PULSES[@]}"; do
  echo "--- Pulse $pulse_num/5: ${burst_s}s burst at cpu-load=${BURST_CPU_LOAD}% ---"
  ztx_run_stress_ng "$POD" "--cpu 1 --cpu-load $BURST_CPU_LOAD --timeout ${burst_s}s"
  sleep "$burst_s"
  ztx_cleanup_stress_ng "$POD"
  echo "--- Cooldown: ${COOLDOWN_SECONDS}s ---"
  sleep "$COOLDOWN_SECONDS"
  pulse_num=$((pulse_num + 1))
done
echo "=== A_Burst pulse train complete ==="
