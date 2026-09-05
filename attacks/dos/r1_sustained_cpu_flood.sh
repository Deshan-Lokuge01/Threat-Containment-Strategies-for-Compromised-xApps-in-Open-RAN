#!/usr/bin/env bash
# R1 - Sustained CPU flood, against kpimon-go only.
#
# Mechanism/intensity copied unchanged from the frozen evaluation script
# (Attacks scripts/R1_sustained_CPU_flood/ztx-step77-r1-fresh-blind.sh):
# stress-ng --cpu 1 --cpu-load 20 - cpu-load% is what the detector's frozen
# thresholds were calibrated against, so that value is never touched here.
# Duration is NOT calibration-sensitive (only intensity/shape is) and was
# cut from the original 900s (15 min) to 120s (2 min) on 2026-07-16 for live
# demo use - this script is explicitly for repeatable interactive
# triggering, not for regenerating the frozen dataset (see _common.sh's
# header). 120s comfortably clears the CPU-rate gate's own minimum (>=15%
# of a rolling 60-sample/60s window over the 56.638 mCPU floor, i.e. >=9s
# of the last 60 need to be over-floor) with margin for a live audience to
# watch it happen, without a 15-minute wait. This is the "obvious" attack
# in the six-scenario suite, meant to be easy for the detector to catch.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

ATTACK_SECONDS=120
CPU_LOAD=20

POD=$(ztx_resolve_kpimon_pod)
ztx_preflight "$POD"
trap 'ztx_cleanup_stress_ng "$POD"' EXIT

echo "=== R1 sustained CPU flood: pod=$POD cpu-load=${CPU_LOAD}% duration=${ATTACK_SECONDS}s ==="
ztx_run_stress_ng "$POD" "--cpu 1 --cpu-load $CPU_LOAD --timeout ${ATTACK_SECONDS}s"
echo "Attack running. Waiting ${ATTACK_SECONDS}s..."
sleep "$ATTACK_SECONDS"
echo "=== R1 attack window complete, cleaning up ==="
