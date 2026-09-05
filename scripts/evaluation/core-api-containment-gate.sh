#!/usr/bin/env bash
set -euo pipefail

cd "${ZTX_ROOT:-$HOME/Desktop/FYP/zt-xguard}"
ENGINE="${ZTX_ENGINE:-http://127.0.0.1:15000}"
NS="${ZTX_XAPP_NS:-ricxapp}"

RUN_ID="core-logic-gate-$(date -u +%Y%m%dT%H%M%SZ)"
OUT="evidence/core-logic-gates/$RUN_ID"
mkdir -p "$OUT"

XAPPS=(telemetry-monitor qos-optimizer traffic-analyzer resource-optimizer security-observer)

log() {
  echo "[$(date -u +%H:%M:%S)] $*"
}

endpoint_count() {
  local xapp="$1"
  kubectl get endpoints "$xapp" -n "$NS" -o json 2>/dev/null \
    | jq '[.subsets[]?.addresses[]?] | length'
}

selector_json() {
  local xapp="$1"
  kubectl get svc "$xapp" -n "$NS" -o json 2>/dev/null \
    | jq -c '.spec.selector // {}'
}

restore_all() {
  for x in "${XAPPS[@]}"; do
    curl -sS -X POST "$ENGINE/csm/containment/restore" \
      -H "Content-Type: application/json" \
      -d "{\"xapp\":\"$x\"}" \
      > "$OUT/restore-$x.json" || true
  done
  sleep 4
}

assert_endpoint_one() {
  local xapp="$1"
  local ep
  ep="$(endpoint_count "$xapp")"
  if [ "$ep" != "1" ]; then
    echo "[FAIL] $xapp endpoint_count expected 1, got $ep"
    kubectl get svc,endpoints "$xapp" -n "$NS" -o yaml || true
    exit 1
  fi
  echo "[ OK ] $xapp endpoint_count=1"
}

assert_endpoint_zero() {
  local xapp="$1"
  local ep
  ep="$(endpoint_count "$xapp")"
  if [ "$ep" != "0" ]; then
    echo "[FAIL] $xapp endpoint_count expected 0, got $ep"
    kubectl get svc,endpoints "$xapp" -n "$NS" -o yaml || true
    exit 1
  fi
  echo "[ OK ] $xapp endpoint_count=0"
}

post_eval() {
  local name="$1"
  local xapp="$2"
  local signal="$3"
  local evidence="$4"
  local expected_state="$5"
  local expected_contain="$6"

  local file="$OUT/evaluate-$name.json"

  jq -n \
    --arg xapp "$xapp" \
    --arg signal "$signal" \
    --argjson evidence "$evidence" \
    '{xapp:$xapp, signal:$signal, evidence:$evidence}' \
    | curl -sS -X POST "$ENGINE/csm/intent/evaluate" \
        -H "Content-Type: application/json" \
        -d @- \
    | tee "$file" >/dev/null

  local state contain
  state="$(jq -r '.result.detection_state // .result.decision_state // .result.state // "UNKNOWN"' "$file")"
  contain="$(jq -r '.result.containment_required // false' "$file")"

  if [ "$state" != "$expected_state" ]; then
    echo "[FAIL] evaluate $name expected state=$expected_state got=$state"
    cat "$file" | jq
    exit 1
  fi

  if [ "$contain" != "$expected_contain" ]; then
    echo "[FAIL] evaluate $name expected containment_required=$expected_contain got=$contain"
    cat "$file" | jq
    exit 1
  fi

  jq -e '.result.rule_ids and .result.reasons and .result.layers and .result.evidence_sources' "$file" >/dev/null || {
    echo "[FAIL] evaluate $name missing explainability fields"
    cat "$file" | jq
    exit 1
  }

  echo "[ OK ] evaluate $name => $state containment=$contain"
}

post_ingest_no_containment() {
  local name="$1"
  local xapp="$2"
  local signal="$3"
  local evidence="$4"
  local expected_state="$5"

  local before after file
  before="$(endpoint_count "$xapp")"
  file="$OUT/ingest-$name.json"

  jq -n \
    --arg xapp "$xapp" \
    --arg signal "$signal" \
    --arg source "core_logic_gate" \
    --argjson evidence "$evidence" \
    '{xapp:$xapp, signal:$signal, source:$source, evidence:$evidence}' \
    | curl -sS -X POST "$ENGINE/csm/intent/ingest" \
        -H "Content-Type: application/json" \
        -d @- \
    | tee "$file" >/dev/null

  sleep 2
  after="$(endpoint_count "$xapp")"

  local state contain
  state="$(jq -r '.detection_state // .decision_state // .state // "UNKNOWN"' "$file")"
  contain="$(jq -r '.containment_required // false' "$file")"

  if [ "$state" != "$expected_state" ]; then
    echo "[FAIL] ingest $name expected state=$expected_state got=$state"
    cat "$file" | jq
    exit 1
  fi

  if [ "$contain" != "false" ]; then
    echo "[FAIL] ingest $name should not require containment"
    cat "$file" | jq
    exit 1
  fi

  if [ "$before" != "1" ] || [ "$after" != "1" ]; then
    echo "[FAIL] ingest $name changed endpoints before=$before after=$after"
    kubectl get svc,endpoints "$xapp" -n "$NS" -o yaml || true
    exit 1
  fi

  echo "[ OK ] ingest $name => $state no containment, endpoint_count stayed 1"
}

log "Health"
curl -sS "$ENGINE/health" | tee "$OUT/health.json" | jq '{status,state_engine_version,state_engine_import_error}'

jq -e '.status=="ok" and .state_engine_version=="5.3-state-machine" and .state_engine_import_error==null' "$OUT/health.json" >/dev/null || {
  echo "[FAIL] policy engine health is not clean"
  exit 1
}

log "Restore all xApps to clean baseline"
restore_all

log "Baseline endpoints"
for x in "${XAPPS[@]}"; do
  assert_endpoint_one "$x"
  selector_json "$x" > "$OUT/baseline-selector-$x.json"
done

log "Decision-only API tests"
post_eval "A5-legitimate-high-cpu" "traffic-analyzer" "high_cpu" '{"valid_activity":true}' "OBSERVED" "false"
post_eval "A4-bad-cpu" "resource-optimizer" "high_cpu" '{"valid_activity":false,"stale_heartbeat":true}' "SUSPICIOUS" "false"
post_eval "A7-peer" "security-observer" "unexpected_peer_contact" '{"peer":"qos-optimizer"}' "SUSPICIOUS" "false"
post_eval "A8-egress" "security-observer" "external_egress" '{"destination":"8.8.8.8"}' "COMPROMISED" "true"
post_eval "A1-shell" "telemetry-monitor" "unexpected_shell" '{"source":"synthetic_falco_unit"}' "COMPROMISED" "true"

log "No-containment ingest tests"
post_ingest_no_containment "A5-legitimate-high-cpu" "traffic-analyzer" "high_cpu" '{"valid_activity":true}' "OBSERVED"
post_ingest_no_containment "A4-bad-cpu" "resource-optimizer" "high_cpu" '{"valid_activity":false,"stale_heartbeat":true}' "SUSPICIOUS"
post_ingest_no_containment "A7-peer" "security-observer" "unexpected_peer_contact" '{"peer":"qos-optimizer"}' "SUSPICIOUS"

log "Critical containment test: A8 external egress"
A8_FILE="$OUT/ingest-A8-external-egress.json"

jq -n \
  --arg xapp "security-observer" \
  --arg signal "external_egress" \
  --arg source "core_logic_gate" \
  --argjson evidence '{"destination":"8.8.8.8","attempt":"curl_external"}' \
  '{xapp:$xapp, signal:$signal, source:$source, evidence:$evidence}' \
  | curl -sS -X POST "$ENGINE/csm/intent/ingest" \
      -H "Content-Type: application/json" \
      -d @- \
  | tee "$A8_FILE" >/dev/null

sleep 4

cat "$A8_FILE" | jq '{
  xapp,
  signal,
  state,
  detection_state,
  containment_required,
  containment_action,
  trust_score,
  risk_score,
  score,
  score_type,
  rule_ids,
  reasons,
  quarantine,
  verification,
  timing
}'

A8_STATE="$(jq -r '.state // "UNKNOWN"' "$A8_FILE")"
A8_DET="$(jq -r '.detection_state // "UNKNOWN"' "$A8_FILE")"
A8_CONTAIN="$(jq -r '.containment_required // false' "$A8_FILE")"

if [ "$A8_STATE" != "QUARANTINED" ] && [ "$A8_STATE" != "COMPROMISED" ]; then
  echo "[FAIL] A8 state expected QUARANTINED/COMPROMISED got $A8_STATE"
  exit 1
fi

if [ "$A8_DET" != "COMPROMISED" ]; then
  echo "[FAIL] A8 detection_state expected COMPROMISED got $A8_DET"
  exit 1
fi

if [ "$A8_CONTAIN" != "true" ]; then
  echo "[FAIL] A8 containment_required expected true got $A8_CONTAIN"
  exit 1
fi

assert_endpoint_zero "security-observer"

kubectl get svc security-observer -n "$NS" -o yaml > "$OUT/security-observer-service-after-A8.yaml"
kubectl get endpoints security-observer -n "$NS" -o yaml > "$OUT/security-observer-endpoints-after-A8.yaml"

if ! selector_json security-observer | grep -q 'zt-xguard.io/service-isolated'; then
  echo "[FAIL] security-observer service selector does not contain zt-xguard.io/service-isolated"
  selector_json security-observer
  exit 1
fi

echo "[ OK ] A8 service selector isolation confirmed"

log "Restore after A8"
curl -sS -X POST "$ENGINE/csm/containment/restore" \
  -H "Content-Type: application/json" \
  -d '{"xapp":"security-observer"}' \
  | tee "$OUT/restore-security-observer-after-A8.json" \
  | jq

sleep 5

assert_endpoint_one "security-observer"

if selector_json security-observer | grep -q 'zt-xguard.io/service-isolated'; then
  echo "[FAIL] restore left stale zt-xguard.io/service-isolated selector"
  selector_json security-observer
  exit 1
fi

kubectl get svc security-observer -n "$NS" -o yaml > "$OUT/security-observer-service-after-restore.yaml"
kubectl get endpoints security-observer -n "$NS" -o yaml > "$OUT/security-observer-endpoints-after-restore.yaml"

log "Final API state"
curl -sS "$ENGINE/csm/state" > "$OUT/final-csm-state.json"
curl -sS "$ENGINE/csm/xapps/runtime" > "$OUT/final-runtime.json"
curl -sS "$ENGINE/metrics" > "$OUT/final-metrics.txt"

(
  cd "$OUT"
  find . -type f -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256
)

echo
echo "CORE_API_CONTAINMENT_GATE_PASS"
echo "Evidence: $OUT"
