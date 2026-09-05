#!/usr/bin/env bash
# Unexpected RIC Service Contact (ZTX-A17, WARNING)
# xApp: resource-optimizer
#
# Connects to service-ricplt-e2mgr-http.ricplt.svc.cluster.local:3800, a RIC platform service NOT on resource-optimizer's own declared allow-list (only prometheus is allowed, e2mgr is not). Matches the rule's per-xApp profile check exactly.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "resource-optimizer")
ztx_trigger "$POD" "resource-optimizer" python3 -c 'import urllib.request; urllib.request.urlopen('\''http://service-ricplt-e2mgr-http.ricplt.svc.cluster.local:3800/'\'', timeout=3)'
