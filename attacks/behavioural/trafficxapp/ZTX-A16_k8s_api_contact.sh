#!/usr/bin/env bash
# Kubernetes API Contact (ZTX-A16, WARNING)
# xApp: trafficxapp
#
# Connects to the Kubernetes API server on port 443 via its in-cluster DNS name - matches the rule's hostname check. No ServiceAccount token is presented, so the API call itself will likely be rejected (401/403) - that's fine, the rule fires on the network connection attempt, not on successful authentication.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "ricxapp-trafficxapp")
ztx_trigger "$POD" "trafficxapp" python3 -c 'import ssl,urllib.request; ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE; urllib.request.urlopen('\''https://kubernetes.default.svc.cluster.local'\'', timeout=3, context=ctx)'
