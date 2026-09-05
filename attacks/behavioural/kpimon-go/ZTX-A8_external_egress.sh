#!/usr/bin/env bash
# External Egress Attempt (ZTX-A8, CRITICAL)
# xApp: kpimon-go
#
# Connects to a public internet address (8.8.8.8) - fails every destination check in ztx_known_internal_dest (not a RIC-platform service, not a peer xApp, not the Kubernetes API, not CoreDNS), so it is genuinely outside every destination this xApp is ever expected to reach. curl is not installed in these images, so the trigger uses python3's urllib the same way this project's own verification steps have throughout.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "ricxapp-kpimon-go")
ztx_trigger "$POD" "kpimon-go" python3 -c 'import urllib.request; urllib.request.urlopen('\''http://8.8.8.8'\'', timeout=3)'
