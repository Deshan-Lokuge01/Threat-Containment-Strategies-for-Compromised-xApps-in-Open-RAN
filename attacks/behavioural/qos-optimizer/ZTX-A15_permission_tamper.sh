#!/usr/bin/env bash
# Permission Tamper (ZTX-A15, WARNING)
# xApp: qos-optimizer
#
# Executes chmod - one of the 3 exact programs the rule watches (chmod, chown, setcap). Creates a throwaway file first so the chmod itself succeeds cleanly.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "qos-optimizer")
ztx_trigger "$POD" "qos-optimizer" sh -c 'touch /tmp/ztx_demo_perm_test && chmod 644 /tmp/ztx_demo_perm_test'
