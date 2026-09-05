#!/usr/bin/env bash
set -euo pipefail

cd "${ZTX_ROOT:-$HOME/Desktop/FYP/zt-xguard}"
export ZTX_ENGINE="${ZTX_ENGINE:-http://127.0.0.1:15000}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT="evidence/runtime-evaluation/${RUN_ID}"
mkdir -p "$OUT"

python3 ztx-control-plane/policy-engine/scripts/evaluation/attack-orchestrator.py \
  --run-id "$RUN_ID" \
  --mode "${ZTX_MODE:-assisted}" \
  --repeats "${ZTX_REPEATS:-1}" \
  --scenarios "${ZTX_SCENARIOS:-A5,A4,A7,A8}" \
  --timeout "${ZTX_TIMEOUT:-45}" \
  --out "$OUT"

echo "Evidence: $OUT"
echo "CSV: $OUT/results.csv"
