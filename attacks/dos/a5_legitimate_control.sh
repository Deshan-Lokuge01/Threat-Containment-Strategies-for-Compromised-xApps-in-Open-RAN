#!/usr/bin/env bash
# A5 - legitimate elevated-CPU control, against kpimon-go only.
#
# NOT AN ATTACK. This is the hard-negative false-positive control: a real,
# low/moderate CPU-bound workload that should stay classified NORMAL/not-
# compromised, never escalated. Intensity copied unchanged from the frozen
# evaluation script (Attacks scripts/A5_benign_control/
# ztx-step77-a5-fresh-blind.sh): stress-ng --cpu 1 --cpu-load 5 - a much
# lower load than any of the 5 real attack scenarios (lowest attack-side
# load elsewhere in this suite is A_Stealth's 20%). Duration cut from the
# original 900s (15 min) to 120s (2 min) on 2026-07-16, matching R1's same
# demo-length reduction - this is R1's direct benign counterpart, so they
# should stay comparable in length. In the dashboard, this option should be
# presented and labeled as a benign baseline/control run, not grouped in
# with the 5 attacks as if it were one.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

ELEVATED_SECONDS=120
CPU_LOAD=5

POD=$(ztx_resolve_kpimon_pod)
ztx_preflight "$POD"
trap 'ztx_cleanup_stress_ng "$POD"' EXIT

echo "=== A5 legitimate elevated-CPU control (NOT an attack): pod=$POD cpu-load=${CPU_LOAD}% duration=${ELEVATED_SECONDS}s ==="
ztx_run_stress_ng "$POD" "--cpu 1 --cpu-load $CPU_LOAD --timeout ${ELEVATED_SECONDS}s"
echo "Benign workload running. Waiting ${ELEVATED_SECONDS}s..."
sleep "$ELEVATED_SECONDS"
echo "=== A5 control window complete, cleaning up ==="
