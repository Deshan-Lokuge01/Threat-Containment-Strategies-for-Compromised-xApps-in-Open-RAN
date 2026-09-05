#!/usr/bin/env bash
# Unexpected Shell (ZTX-A1, CRITICAL)
# xApp: qos-optimizer
#
# Spawns a shell (sh) inside the main container - one of the 6 exact programs the rule watches (sh, bash, dash, zsh, ksh, ash).
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "qos-optimizer")
ztx_trigger "$POD" "qos-optimizer" sh -c true
