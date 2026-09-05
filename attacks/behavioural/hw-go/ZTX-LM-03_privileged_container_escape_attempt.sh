#!/usr/bin/env bash
# Privileged Container Escape Attempt (ZTX-LM-03, CRITICAL)
# xApp: hw-go
#
# Attempts to open two of the 6 watched container-runtime socket paths (Docker and containerd variants) - a real container-escape probing technique (MITRE ATT&CK T1611), and the same kind of candidate-path probing Peirates itself performs. Expected to fail (socket not present/not permitted) - the rule fires on the open attempt itself, not on success.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "ricxapp-hw-go")
ztx_trigger "$POD" "hw-go" sh -c 'cat /var/run/docker.sock 2>/dev/null; cat /run/containerd/containerd.sock 2>/dev/null; true'
