#!/usr/bin/env bash
# Sensitive File Access (ZTX-A2, CRITICAL)
# xApp: hw-python
#
# Opens /etc/passwd - one of the 3 named sensitive files the rule watches (/etc/shadow, /etc/sudoers, /etc/passwd), chosen because it's world-readable everywhere so the demo doesn't depend on container UID/permissions.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "ricxapp-hw-python")
ztx_trigger "$POD" "hw-python" cat /etc/passwd
