#!/usr/bin/env bash
# SVID Or SPIFFE Material Access (ZTX-A11, CRITICAL)
# xApp: hw-go
#
# Reads SVID certificate material directly from the MAIN container (not the renew-svid sidecar, which is the only place this is expected) - one of the 16 listed read tools (cat) on a path under /etc/svid.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "ricxapp-hw-go")
ztx_trigger "$POD" "hw-go" cat /etc/svid/svid.0.pem
