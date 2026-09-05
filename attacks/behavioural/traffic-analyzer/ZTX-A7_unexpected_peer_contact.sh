#!/usr/bin/env bash
# Unexpected Peer xApp Contact (ZTX-A7, WARNING)
# xApp: traffic-analyzer
#
# Connects to qos-optimizer.ricxapp.svc.cluster.local:8080, a peer xApp NOT on traffic-analyzer's own declared allow-list (only telemetry-monitor is allowed, qos-optimizer is not). Matches the rule's per-xApp profile check exactly, not a generic probe.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "traffic-analyzer")
ztx_trigger "$POD" "traffic-analyzer" python3 -c 'import urllib.request; urllib.request.urlopen('\''http://qos-optimizer.ricxapp.svc.cluster.local:8080/'\'', timeout=3)'
