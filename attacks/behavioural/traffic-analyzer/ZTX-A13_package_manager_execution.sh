#!/usr/bin/env bash
# Package Manager Execution (ZTX-A13, WARNING)
# xApp: traffic-analyzer
#
# Executes pip3 - one of the 9 exact package-manager programs the rule watches (apt, apt-get, apk, yum, dnf, rpm, dpkg, pip, pip3).
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "traffic-analyzer")
ztx_trigger "$POD" "traffic-analyzer" pip3 --version
