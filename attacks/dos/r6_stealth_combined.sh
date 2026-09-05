#!/usr/bin/env bash
# R6 - combined low-and-slow CPU + memory + disk stress, against kpimon-go
# only.
#
# RECONSTRUCTED SCRIPT, CLEARLY LABELED AS SUCH: unlike the other 5
# scenarios, R6 never had its own saved launch script in this project - only
# the *result* of how it was run survived, recorded in its own
# attack_timeline.csv as the combined stress-ng invocation
# "R6_STEALTH_CPU10_VM16M_HDD16M_3600S" (see Attacks scripts/README.md,
# "R6 - no standalone script exists"). This script reproduces that exact
# recorded invocation as a runnable driver, modeled on
# a_stealth_staircase.sh's structure. If you have the actual original
# command used, prefer that over this reconstruction. Intensity values
# (cpu-load/vm-bytes/hdd-bytes) left unchanged from the recorded
# invocation; duration cut from 3600s (60 min) to 360s (6 min) on
# 2026-07-16 for live demo use - one of the three "low and slow" scenarios,
# kept at the longer end of the demo-length range.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_common.sh"

DURATION_SECONDS=360
CPU_LOAD=10
VM_BYTES="16M"
HDD_BYTES="16M"

POD=$(ztx_resolve_kpimon_pod)
ztx_preflight "$POD"
trap 'ztx_cleanup_stress_ng "$POD"' EXIT

echo "=== R6 combined stealth stress (RECONSTRUCTED): pod=$POD cpu-load=${CPU_LOAD}% vm-bytes=${VM_BYTES} hdd-bytes=${HDD_BYTES} duration=${DURATION_SECONDS}s ==="
ztx_run_stress_ng "$POD" "--cpu 1 --cpu-load $CPU_LOAD --vm 1 --vm-bytes $VM_BYTES --hdd 1 --hdd-bytes $HDD_BYTES --timeout ${DURATION_SECONDS}s"
echo "Attack running. Waiting ${DURATION_SECONDS}s (60 minutes)..."
sleep "$DURATION_SECONDS"
echo "=== R6 attack window complete, cleaning up ==="
