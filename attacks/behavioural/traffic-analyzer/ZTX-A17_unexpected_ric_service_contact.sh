#!/usr/bin/env bash
# Unexpected RIC Service Contact (ZTX-A17, WARNING)
# xApp: traffic-analyzer
#
# Connects to service-ricplt-e2mgr-http.ricplt.svc.cluster.local:3800, a RIC platform service NOT on traffic-analyzer's own declared allow-list (any RIC service is unexpected - allowed_ric_services is empty). Matches the rule's per-xApp profile check exactly.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "traffic-analyzer")
ztx_trigger "$POD" "traffic-analyzer" python3 -c 'import urllib.request; urllib.request.urlopen('\''http://service-ricplt-e2mgr-http.ricplt.svc.cluster.local:3800/'\'', timeout=3)'
