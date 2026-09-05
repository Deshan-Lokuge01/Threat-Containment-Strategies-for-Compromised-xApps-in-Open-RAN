#!/usr/bin/env bash
# Unexpected Peer xApp Contact (ZTX-A7, WARNING)
# xApp: resource-optimizer
#
# Connects to telemetry-monitor.ricxapp.svc.cluster.local:8080, a peer xApp NOT on resource-optimizer's own declared allow-list (any peer is unexpected - allowed_peers is empty). Matches the rule's per-xApp profile check exactly, not a generic probe.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "resource-optimizer")
ztx_trigger "$POD" "resource-optimizer" python3 -c 'import urllib.request; urllib.request.urlopen('\''http://telemetry-monitor.ricxapp.svc.cluster.local:8080/'\'', timeout=3)'
