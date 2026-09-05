#!/usr/bin/env bash
# Binary Drop In Writable Path (ZTX-A14, WARNING)
# xApp: qos-optimizer
#
# Writes a file ending in .sh into /tmp/ - matches both conditions the rule requires (one of the 3 writable locations, one of the 8 watched extensions).
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "qos-optimizer")
ztx_trigger "$POD" "qos-optimizer" sh -c 'echo demo > /tmp/ztx_demo_drop.sh'
