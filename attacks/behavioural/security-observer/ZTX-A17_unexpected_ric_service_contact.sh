#!/usr/bin/env bash
# Unexpected RIC Service Contact (ZTX-A17, WARNING)
# xApp: security-observer
#
# Connects to service-ricplt-e2mgr-http.ricplt.svc.cluster.local:3800, a RIC platform service NOT on security-observer's own declared allow-list (any RIC service is unexpected - allowed_ric_services is empty). Matches the rule's per-xApp profile check exactly.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "security-observer")
ztx_trigger "$POD" "security-observer" python3 -c 'import urllib.request; urllib.request.urlopen('\''http://service-ricplt-e2mgr-http.ricplt.svc.cluster.local:3800/'\'', timeout=3)'
