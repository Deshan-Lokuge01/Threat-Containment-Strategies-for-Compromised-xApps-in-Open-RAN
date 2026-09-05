#!/usr/bin/env bash
# Permission Tamper (ZTX-A15, WARNING)
# xApp: telemetry-monitor
#
# Executes chmod - one of the 3 exact programs the rule watches (chmod, chown, setcap). Creates a throwaway file first so the chmod itself succeeds cleanly.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "telemetry-monitor")
ztx_trigger "$POD" "telemetry-monitor" sh -c 'touch /tmp/ztx_demo_perm_test && chmod 644 /tmp/ztx_demo_perm_test'
