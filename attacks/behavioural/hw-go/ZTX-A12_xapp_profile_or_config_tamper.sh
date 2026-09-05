#!/usr/bin/env bash
# Profile Or Config Tamper (ZTX-A12, CRITICAL)
# xApp: hw-go
#
# Changes permissions on the mounted xApp profile file - chmod is one of the write/metadata-tamper operations the rule watches, on a path under /etc/xapp-profile.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "ricxapp-hw-go")
ztx_trigger "$POD" "hw-go" chmod 644 /etc/xapp-profile/profile.json
