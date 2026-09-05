#!/usr/bin/env bash
# Unexpected Peer xApp Contact (ZTX-A7, WARNING)
# xApp: qos-optimizer
#
# Connects to telemetry-monitor.ricxapp.svc.cluster.local:8080, a peer xApp NOT on qos-optimizer's own declared allow-list (only traffic-analyzer is allowed, telemetry-monitor is not). Matches the rule's per-xApp profile check exactly, not a generic probe.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "qos-optimizer")
ztx_trigger "$POD" "qos-optimizer" python3 -c 'import urllib.request; urllib.request.urlopen('\''http://telemetry-monitor.ricxapp.svc.cluster.local:8080/'\'', timeout=3)'
