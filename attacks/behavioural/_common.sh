#!/usr/bin/env bash
# Shared pod-resolution helper for the per-xApp rule-violation trigger
# scripts under this folder. Each xApp's own subfolder has one script per
# applicable rule; every one of those scripts sources this file.
#
# Called "Falco" as a folder name only for internal organization - the
# dashboard/UI built on top of these should present this as a runtime
# policy/rule-violation trigger suite (matching the project's IEEE CCNC
# framing), not reference the underlying tool by name in user-facing text.
set -Eeuo pipefail

NS="ricxapp"

# $1 = pod-name prefix to match (e.g. "telemetry-monitor" or "ricxapp-kpimon-go")
ztx_resolve_pod() {
  local pattern="$1"
  local pod
  pod=$(kubectl get pods -n "$NS" --field-selector=status.phase=Running -o name \
        | grep -i "^pod/${pattern}" | head -n 1 | cut -d/ -f2)
  if [ -z "$pod" ]; then
    echo "ERROR: no Running pod matching '${pattern}*' found in namespace $NS" >&2
    exit 1
  fi
  echo "$pod"
}

# $1 = pod, $2 = container, $3.. = command to exec inside it
ztx_trigger() {
  local pod="$1" container="$2"
  shift 2
  echo "--- kubectl exec -n $NS $pod -c $container -- $* ---"
  kubectl exec -n "$NS" "$pod" -c "$container" -- "$@" || true
}
