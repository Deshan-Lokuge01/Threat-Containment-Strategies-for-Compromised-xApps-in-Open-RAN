#!/usr/bin/env bash
# A_Memory - gradual memory ramp then sustained hold, against kpimon-go only.
#
# Mechanism/target memory copied unchanged from the frozen evaluation script
# (Attacks scripts/A_Memory_ramp_hold/ztx-step79-a-memory-exhaustion-blind.sh):
# 6-step ramp-up, allocating 1/6, 2/6, ... 6/6 of the target memory each
# step, then a sustained hold of the full target. Target memory defaults to
# 32MB (override with TARGET_MEMORY_MB=<n> before calling this script),
# matching the original's default. Durations cut on 2026-07-16 for live
# demo use: ramp 300s -> 60s (10s/step), hold 1200s -> 360s, since this is
# one of the three "low and slow" scenarios in the suite - kept at the
# longer end (~7 min total) of the demo-length range rather than cut as
# aggressively as R1/A5, to still read as gradual/sustained rather than
# instant.
#
# IMPORTANT, not a bug: the live v5 decision gate is CPU-only
# (v5_frozen_gate_manifest.json: decision_gates=["cpu"], m4/memory
# explicitly excluded - "m4_memory_growth_bytes_per_s spikes to values
# physically inconsistent... treated as an unreliable feature, not tuned
# around"). This scenario will likely show an elevated T2 score but may
# never reach public_state=SUSPICIOUS regardless of duration, since a pure
# memory stressor doesn't reliably drive CPU over the 56.638 mCPU floor the
# CPU gate requires. Worth watching the score climb; don't expect the same
# SUSPICIOUS flip R1/A_Stealth/A_Burst/R6 can produce.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

TARGET_MEMORY_MB=${TARGET_MEMORY_MB:-32}
RAMP_SECONDS=60
RAMP_STEPS=6
STEP_DURATION=$((RAMP_SECONDS / RAMP_STEPS))
STEP_SIZE=$((TARGET_MEMORY_MB / RAMP_STEPS))
HOLD_SECONDS=360

POD=$(ztx_resolve_kpimon_pod)
ztx_preflight "$POD"
trap 'ztx_cleanup_stress_ng "$POD"' EXIT

echo "=== A_Memory ramp+hold: pod=$POD target=${TARGET_MEMORY_MB}MB ramp=${RAMP_SECONDS}s(${RAMP_STEPS} steps) hold=${HOLD_SECONDS}s ==="

for step in $(seq 1 $RAMP_STEPS); do
  CURRENT_MB=$((STEP_SIZE * step))
  echo "--- Ramp step $step/$RAMP_STEPS: allocating ${CURRENT_MB}MB for ${STEP_DURATION}s ---"
  ztx_run_stress_ng "$POD" "--vm 1 --vm-bytes ${CURRENT_MB}M --timeout ${STEP_DURATION}s"
  sleep "$STEP_DURATION"
done
echo "=== Ramp-up complete ==="

echo "=== Sustained hold: ${TARGET_MEMORY_MB}MB for ${HOLD_SECONDS}s ==="
ztx_run_stress_ng "$POD" "--vm 1 --vm-bytes ${TARGET_MEMORY_MB}M --timeout ${HOLD_SECONDS}s"
sleep "$HOLD_SECONDS"
echo "=== A_Memory attack window complete, cleaning up ==="
