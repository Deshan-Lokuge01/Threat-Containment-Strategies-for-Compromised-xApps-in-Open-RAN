#!/usr/bin/env bash
# Unexpected RIC Service Contact (ZTX-A17, WARNING)
# xApp: telemetry-monitor
#
# Connects to service-ricplt-appmgr-http.ricplt.svc.cluster.local:8080, a RIC platform service NOT on telemetry-monitor's own declared allow-list (only e2mgr is allowed, appmgr is not). Matches the rule's per-xApp profile check exactly.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "telemetry-monitor")
ztx_trigger "$POD" "telemetry-monitor" python3 -c 'import urllib.request; urllib.request.urlopen('\''http://service-ricplt-appmgr-http.ricplt.svc.cluster.local:8080/'\'', timeout=3)'
