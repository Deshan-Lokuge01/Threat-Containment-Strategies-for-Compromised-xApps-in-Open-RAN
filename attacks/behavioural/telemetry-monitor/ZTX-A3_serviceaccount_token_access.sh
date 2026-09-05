#!/usr/bin/env bash
# ServiceAccount Token Access (ZTX-A3, CRITICAL)
# xApp: telemetry-monitor
#
# Opens the Kubernetes-mounted ServiceAccount token file - the exact path prefix the rule watches (/var/run/secrets/kubernetes.io/serviceaccount).
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "telemetry-monitor")
ztx_trigger "$POD" "telemetry-monitor" cat /var/run/secrets/kubernetes.io/serviceaccount/token
