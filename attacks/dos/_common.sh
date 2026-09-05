#!/usr/bin/env bash
# Shared helpers for the 6 kpimon-go resource-attack scripts in this folder.
#
# These scripts are for repeatable, interactive demo triggering (e.g. from a
# dashboard/TUI), not for regenerating the frozen paper dataset - that data
# collection is already done and lives under zt-xguard/data/attacks/*. The
# stress-ng parameters here are copied unchanged from the original frozen
# scripts (Attacks scripts/*, kept as-is elsewhere in this project) because
# the resource-anomaly detector was calibrated against those exact numbers -
# changing them would make live demo results not scientifically comparable
# to the paper's reported figures. What's dropped compared to the originals:
# the per-run collect_resources.py CSV harness, SHA256SUMS, CALDERA
# scale-down, and the "press ENTER, this is the ONE AND ONLY run" one-shot
# framing - none of that applies to a script meant to be run many times
# during a live demo. What's added: a cleanup trap, so an interrupted run
# (e.g. the dashboard's "cancel" button) always leaves the pod's stress-ng
# processes killed rather than orphaned.
#
# Resource attacks are intentionally scoped to kpimon-go ONLY (not
# generalized to the other 8 xApps) - kpimon-go is the one and only xApp the
# frozen MEWMA/Hotelling-T^2 statistical model was built and calibrated
# against.

set -Eeuo pipefail

NS="ricxapp"
CONTAINER="kpimon-go"
EXPECTED_IMAGE="127.0.0.1:80/kpimon-ocudu-cell:ztx-experiment-v1"

ztx_resolve_kpimon_pod() {
  local pod
  pod=$(kubectl get pods -n "$NS" --field-selector=status.phase=Running -o name | grep -i kpimon | head -n 1 | cut -d/ -f2)
  if [ -z "$pod" ]; then
    echo "ERROR: no Running kpimon-go pod found in namespace $NS" >&2
    exit 1
  fi
  echo "$pod"
}

ztx_preflight() {
  local pod="$1"
  local image
  image=$(kubectl get pod "$pod" -n "$NS" -o jsonpath="{.spec.containers[?(@.name==\"$CONTAINER\")].image}")
  if [ "$image" != "$EXPECTED_IMAGE" ]; then
    echo "WARNING: kpimon-go image is '$image', expected '$EXPECTED_IMAGE' - continuing anyway (informational only, not a hard stop for demo runs)."
  fi

  kubectl exec -n "$NS" "$pod" -c "$CONTAINER" -- sh -lc 'command -v stress-ng' >/dev/null \
    || { echo "ERROR: stress-ng not available in $CONTAINER" >&2; exit 1; }

  if kubectl exec -n "$NS" "$pod" -c "$CONTAINER" -- sh -lc 'ps aux | grep -E "stress-ng" | grep -v grep' >/dev/null 2>&1; then
    echo "ERROR: stress-ng is already running in $pod/$CONTAINER - stop it before starting a new attack." >&2
    exit 10
  fi

  echo "Preflight OK - pod=$pod container=$CONTAINER image=$image"
}

ztx_cleanup_stress_ng() {
  local pod="$1"
  kubectl exec -n "$NS" "$pod" -c "$CONTAINER" -- sh -lc \
    'pkill -TERM stress-ng >/dev/null 2>&1 || true; sleep 1; pkill -KILL stress-ng >/dev/null 2>&1 || true' \
    2>/dev/null || true
}

ztx_run_stress_ng() {
  # $1=pod, $2=full stress-ng argument string (already includes --timeout)
  local pod="$1"
  local args="$2"
  kubectl exec -n "$NS" "$pod" -c "$CONTAINER" -- sh -lc \
    "nohup stress-ng $args --metrics-brief >/tmp/ztx_attack_last.log 2>&1 & echo \$!; ps aux | grep stress-ng | grep -v grep"
}
