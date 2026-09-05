#!/usr/bin/env bash
# ServiceAccount Token Access (ZTX-A3, CRITICAL)
# xApp: hw-python
#
# Opens the Kubernetes-mounted ServiceAccount token file - the exact path prefix the rule watches (/var/run/secrets/kubernetes.io/serviceaccount).
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "ricxapp-hw-python")
ztx_trigger "$POD" "hw-python" cat /var/run/secrets/kubernetes.io/serviceaccount/token
