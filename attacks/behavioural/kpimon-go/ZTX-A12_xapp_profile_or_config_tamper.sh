#!/usr/bin/env bash
# Profile Or Config Tamper (ZTX-A12, CRITICAL)
# xApp: kpimon-go
#
# Changes permissions on kpimon-go's own mounted config file - chmod is one
# of the write/metadata-tamper operations the rule watches, on a path under
# /opt/ric/config (kpimon-go's real mounted config path - confirmed live,
# /etc/xapp-profile does not exist in this xApp's filesystem at all; that
# path only applies to the 5 synthetic demo xApps' own profile mounts).
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "ricxapp-kpimon-go")
ztx_trigger "$POD" "kpimon-go" chmod 644 /opt/ric/config/config-file.json
