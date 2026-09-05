#!/usr/bin/env bash
# A_Stealth - low-intensity CPU staircase, against kpimon-go only.
#
# Mechanism, steps, and calibrated cpu-load values copied unchanged from the
# frozen evaluation script (Attacks scripts/A_Stealth_staircase/
# ztx-step80-a-stealth-boundary-blind.sh, "full" variant), which were
# themselves calibrated against this exact testbed on 2026-07-04
# (calibrate_a_stealth_cpu_loads_v3.sh) against a measured CPU floor of
# 56.638 mCPU. 4 steps: 0.7x/1.0x/1.3x/1.6x the floor, realized via
# cpu-load 20/28/36/40 respectively (the container's CFS quota ceiling
# makes achieved mCPU ~= 2x the cpu-load percentage for loads >=20). This is
# the "hardest to catch" scenario in the six-scenario suite - deliberately
# staying close to the boundary of normal. Step duration cut from 900s to
# 105s (4 steps = ~7 min total) on 2026-07-16 for live demo use - one of the
# three "low and slow" scenarios, kept at the longer end of the demo-length
# range since compressing it too far would turn a deliberately gradual/
# boundary-hugging scenario into just another obvious spike.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

STEP_DURATION_SECONDS=105
STEP_LOADS=(20 28 36 40)
STEP_NAMES=("0.7x_floor" "1.0x_floor" "1.3x_floor" "1.6x_floor")

POD=$(ztx_resolve_kpimon_pod)
ztx_preflight "$POD"
trap 'ztx_cleanup_stress_ng "$POD"' EXIT

echo "=== A_Stealth staircase: pod=$POD 4 steps x ${STEP_DURATION_SECONDS}s, loads=${STEP_LOADS[*]} ==="

for i in 0 1 2 3; do
  step=$((i + 1))
  load=${STEP_LOADS[$i]}
  name=${STEP_NAMES[$i]}
  echo "--- Step $step/4 (${name}): cpu-load=${load}% for ${STEP_DURATION_SECONDS}s ---"
  ztx_run_stress_ng "$POD" "--cpu 1 --cpu-load $load --timeout ${STEP_DURATION_SECONDS}s"
  sleep "$STEP_DURATION_SECONDS"
done
echo "=== A_Stealth staircase complete, cleaning up ==="
