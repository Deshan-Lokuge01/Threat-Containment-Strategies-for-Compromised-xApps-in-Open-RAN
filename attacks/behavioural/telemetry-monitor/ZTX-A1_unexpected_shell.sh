#!/usr/bin/env bash
# Unexpected Shell (ZTX-A1, CRITICAL)
# xApp: telemetry-monitor
#
# Spawns a shell (sh) inside the main container - one of the 6 exact programs the rule watches (sh, bash, dash, zsh, ksh, ash).
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "telemetry-monitor")
ztx_trigger "$POD" "telemetry-monitor" sh -c true
