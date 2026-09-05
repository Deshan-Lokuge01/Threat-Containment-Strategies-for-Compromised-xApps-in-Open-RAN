#!/usr/bin/env bash
# Profile Or Config Tamper (ZTX-A12, CRITICAL)
# xApp: qos-optimizer
#
# Changes permissions on the mounted xApp profile file - chmod is one of the write/metadata-tamper operations the rule watches, on a path under /etc/xapp-profile.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "qos-optimizer")
ztx_trigger "$POD" "qos-optimizer" chmod 644 /etc/xapp-profile/profile.json
