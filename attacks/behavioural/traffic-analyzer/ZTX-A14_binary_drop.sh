#!/usr/bin/env bash
# Binary Drop In Writable Path (ZTX-A14, WARNING)
# xApp: traffic-analyzer
#
# Writes a file ending in .sh into /tmp/ - matches both conditions the rule requires (one of the 3 writable locations, one of the 8 watched extensions).
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "traffic-analyzer")
ztx_trigger "$POD" "traffic-analyzer" sh -c 'echo demo > /tmp/ztx_demo_drop.sh'
