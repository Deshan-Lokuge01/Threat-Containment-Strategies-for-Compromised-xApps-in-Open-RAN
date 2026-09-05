#!/usr/bin/env bash
# Suspicious Tool Execution (ZTX-A6, WARNING)
# xApp: trafficxapp
#
# Executes python3 - one of the 12 exact programs the rule watches (curl, wget, nc, ncat, netcat, socat, ssh, scp, python, python3, perl, ruby). This is also the family of invocation Peirates itself uses.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "ricxapp-trafficxapp")
ztx_trigger "$POD" "trafficxapp" python3 --version
