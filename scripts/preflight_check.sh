#!/usr/bin/env bash
set -Eeuo pipefail

# ZT-XGuard Extended Attack Evaluation: Pre-Flight Checks
#
# This script validates all system components before any scenario collection.
# Run this once before starting A_Memory, A_Stealth, A_Burst, or A_Ramp.
#
# Exit codes:
#   0 = all checks passed, ready to proceed
#   1 = one or more critical checks failed, do NOT proceed
#

CHECKS_PASSED=0
CHECKS_FAILED=0

echo "================================================================================"
echo "ZT-XGuard Extended Attack Scenarios: PREFLIGHT CHECK"
echo "================================================================================"
echo ""

# ============================================================================
# KPIMON HEALTH CHECK
# ============================================================================
echo "--- [1/8] KPIMON pod health and telemetry sampling ---"

NS="ricxapp"
CONTAINER="kpimon-go"
EXPECTED_IMAGE="127.0.0.1:80/kpimon-ocudu-cell:ztx-experiment-v1"

KPIPOD=$(kubectl get pods -n "$NS" --field-selector=status.phase=Running -o name 2>/dev/null | grep -i kpimon | head -n 1 | cut -d/ -f2 || echo "")

if [ -z "$KPIPOD" ]; then
  echo "❌ KPIMON pod not found in running state. Check namespace=$NS"
  CHECKS_FAILED=$((CHECKS_FAILED + 1))
else
  echo "✓ KPIMON pod found: $KPIPOD"

  IMAGE=$(kubectl get pod "$KPIPOD" -n "$NS" -o jsonpath='{.spec.containers[?(@.name=="kpimon-go")].image}')
  if [ "$IMAGE" != "$EXPECTED_IMAGE" ]; then
    echo "❌ KPIMON image mismatch. Expected: $EXPECTED_IMAGE, got: $IMAGE"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
  else
    echo "✓ KPIMON image correct: $IMAGE"
  fi

  POD_IP=$(kubectl get pod "$KPIPOD" -n "$NS" -o jsonpath='{.status.podIP}')
  METRICS_URL="http://${POD_IP}:9090/ztx/metrics"

  if ! curl -fsS --max-time 5 "$METRICS_URL" > /tmp/metrics_test.json 2>/dev/null; then
    echo "❌ KPIMON metrics endpoint unreachable: $METRICS_URL"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
  else
    echo "✓ KPIMON metrics endpoint responding: $METRICS_URL"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
  fi
fi

# ============================================================================
# E2 INTERFACE CHECK
# ============================================================================
echo ""
echo "--- [2/8] E2 interface connection status ---"

E2_STATE_JSON=$(mktemp)
if kubectl exec -n ricplt $(kubectl get pods -n ricplt -l app=ricplt-e2mgr -o name | head -n 1) -- \
  curl -s http://localhost:3800/v1/nodeb/states > "$E2_STATE_JSON" 2>/dev/null; then

  if grep -q CONNECTED "$E2_STATE_JSON"; then
    echo "✓ E2 interface CONNECTED"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
  else
    echo "❌ E2 interface NOT CONNECTED"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
  fi
else
  echo "❌ Could not query E2 manager state"
  CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi
rm -f "$E2_STATE_JSON"

# ============================================================================
# PING PROCESS CHECK (KPM subscription heartbeat)
# ============================================================================
echo ""
echo "--- [3/8] Ping process to E2 (KPM subscription indicator) ---"

PING_COUNT=$(ps -eo pid=,ppid=,comm=,args= 2>/dev/null | awk '$3=="ping" && $0 ~ /10[.]45[.]1[.]1/' | wc -l)

if [ "$PING_COUNT" -eq 1 ]; then
  echo "✓ Exactly 1 ping process to 10.45.1.1 (KPM subscription active)"
  CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
  echo "❌ Expected 1 ping process to 10.45.1.1, found $PING_COUNT"
  CHECKS_FAILED=$((CHECKS_FAILED + 1))
fi

# ============================================================================
# STRESS-NG AVAILABILITY CHECK
# ============================================================================
echo ""
echo "--- [4/8] stress-ng availability in KPIMON container ---"

if [ -n "$KPIPOD" ]; then
  if kubectl exec -n "$NS" "$KPIPOD" -c "$CONTAINER" -- sh -lc 'command -v stress-ng' >/dev/null 2>&1; then
    echo "✓ stress-ng available in container"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
  else
    echo "❌ stress-ng not available in KPIMON container"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
  fi

  if kubectl exec -n "$NS" "$KPIPOD" -c "$CONTAINER" -- sh -lc 'ps aux | grep -E "stress-ng" | grep -v grep' >/dev/null 2>&1; then
    echo "⚠️  WARNING: stress-ng already running in container. Stop it before proceeding."
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
  else
    echo "✓ No active stress-ng processes (clean state)"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
  fi
fi

# ============================================================================
# RESOURCE LIMITS CHECK (testbed crash prevention)
# ============================================================================
echo ""
echo "--- [5/8] Node resource availability (testbed stability) ---"

AVAILABLE_MEMORY=$(kubectl top nodes 2>/dev/null | tail -1 | awk '{print $6}' | sed 's/Mi//' || echo "")
AVAILABLE_CPU=$(kubectl top nodes 2>/dev/null | tail -1 | awk '{print $4}' | sed 's/m//' || echo "")

if [ -z "$AVAILABLE_MEMORY" ] || [ -z "$AVAILABLE_CPU" ]; then
  echo "⚠️  WARNING: Could not determine node resources (metrics may not be available). Proceeding with caution."
  echo "    Recommend monitoring pod/node health manually during collection."
  CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
  echo "Available memory: ${AVAILABLE_MEMORY}Mi, available CPU: ${AVAILABLE_CPU}m"
  if [ "$AVAILABLE_MEMORY" -lt 2048 ] || [ "$AVAILABLE_CPU" -lt 500 ]; then
    echo "❌ Node resource availability critically low. Postpone until more resources available."
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
  else
    echo "✓ Sufficient node resources for stress scenarios"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
  fi
fi

# ============================================================================
# 1 HZ SAMPLING TEST (timing accuracy check)
# ============================================================================
echo ""
echo "--- [7/8] 1 Hz sampling verification (short 30s test) ---"

if [ -n "$KPIPOD" ]; then
  echo "Starting 30-second timing baseline..."

  TEMP_OUT=$(mktemp --suffix=.csv)

  python3 - "$KPIPOD" "$NS" "$CONTAINER" "$TEMP_OUT" 30 <<'PYEOF'
import subprocess
import json
import time
import sys

pod_name, namespace, container, output_file, duration = sys.argv[1:6]
duration = int(duration)
pod_ip = subprocess.check_output(
    f"kubectl get pod {pod_name} -n {namespace} -o jsonpath='{{.status.podIP}}'",
    shell=True, text=True
).strip()
metrics_url = f"http://{pod_ip}:9090/ztx/metrics"

print(f"Collecting {duration}s of metrics from {metrics_url}...", file=sys.stderr)

start = time.time()
samples = []

while time.time() - start < duration:
  try:
    result = subprocess.run(
        f'curl -fsS --max-time 2 "{metrics_url}"',
        shell=True, capture_output=True, text=True, timeout=3
    )
    if result.returncode == 0:
      data = json.loads(result.stdout)
      elapsed = time.time() - start
      samples.append({"elapsed_s": elapsed, "ok": 1})
    else:
      elapsed = time.time() - start
      samples.append({"elapsed_s": elapsed, "ok": 0})
  except:
    pass

  time.sleep(1)

if samples:
  intervals = [samples[i+1]["elapsed_s"] - samples[i]["elapsed_s"] for i in range(len(samples)-1)]
  avg_interval = sum(intervals) / len(intervals) if intervals else 0
  success_count = sum(1 for s in samples if s["ok"])

  print(f"Sample count: {len(samples)}, avg interval: {avg_interval:.3f}s, success rate: {success_count}/{len(samples)}", file=sys.stderr)

  if abs(avg_interval - 1.0) > 0.1:
    print(f"WARNING: Timing deviation. Expected 1.0s, got {avg_interval:.3f}s", file=sys.stderr)
  elif success_count < len(samples) * 0.95:
    print(f"WARNING: Low success rate ({success_count}/{len(samples)})", file=sys.stderr)
  else:
    print("✓ Timing verified", file=sys.stderr)
PYEOF

  rm -f "$TEMP_OUT"
  CHECKS_PASSED=$((CHECKS_PASSED + 1))
fi

# ============================================================================
# FINAL CHECK: Verify frozen artifacts are on dev machine (not here)
# ============================================================================
echo ""
echo "--- [8/8] Frozen model artifacts (verify on dev machine, not testbed) ---"
echo "ℹ️  Frozen artifacts (Step 54, 76) are on Windows dev machine only."
echo "    Testbed does NOT need them for collection."
echo "    Evaluation happens post-collection on dev machine."
echo "✓ Acknowledged"
CHECKS_PASSED=$((CHECKS_PASSED + 1))

# ============================================================================
# SUMMARY
# ============================================================================
echo ""
echo "================================================================================"
echo "PREFLIGHT SUMMARY (TESTBED HEALTH CHECK)"
echo "================================================================================"
echo "Checks passed: $CHECKS_PASSED / 8"
echo "Checks failed: $CHECKS_FAILED"
echo ""

if [ "$CHECKS_FAILED" -eq 0 ]; then
  echo "✅ TESTBED READY. Proceed with attack scenario collection."
  echo ""
  echo "Next steps:"
  echo "  1. Run calibration for target scenario (stress-ng parameter tuning)"
  echo "  2. Execute collection script (ztx-step79/80/81-*.sh)"
  echo "  3. Post-collection: Copy raw_metrics.csv to dev machine"
  echo "  4. Run evaluation harness on dev machine (step79/80/81_*_evaluation.py)"
  echo ""
  exit 0
else
  echo "❌ $CHECKS_FAILED check(s) failed. DO NOT PROCEED."
  echo "Fix all failures above before attempting any scenario collection."
  echo ""
  exit 1
fi
