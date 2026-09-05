#!/usr/bin/env bash
# Unexpected Shell (ZTX-A1, CRITICAL)
# xApp: kpimon-go
#
# Spawns a shell (sh) inside the main container - one of the 6 exact programs the rule watches (sh, bash, dash, zsh, ksh, ash).
#
# 2026-07-22: live-confirmed real miss - "sh -c true" exits so close to
# instantly (true is a shell builtin, so sh forks/execs/exits with no real
# work in between) that on this cluster's overloaded node Falco's kernel
# event capture missed it outright, twice in a row, with zero trace in its
# own log (not a rule-matching bug - the execve event itself never showed
# up). Every other attack script in this suite does enough real work
# (a file read, a version check, etc.) to stay alive long enough to be
# captured reliably. Using "sleep 0.5" instead of "true" keeps the shell
# alive just long enough to fix that, without changing what's being tested
# (an unexpected shell spawn inside the container).
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "ricxapp-kpimon-go")
ztx_trigger "$POD" "kpimon-go" sh -c "sleep 0.5"
