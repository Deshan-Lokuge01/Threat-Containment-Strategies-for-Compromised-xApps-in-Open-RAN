#!/usr/bin/env bash
set -Eeuo pipefail

POLICY_DIR="$HOME/Desktop/FYP/zt-xguard/ztx-control-plane/policy-engine"
NAMESPACE="zt-xguard"
DEPLOYMENT="zt-xguard-policy-engine"
CONTAINER="policy-engine"
IMAGE_REPO="docker.io/library/zt-xguard-policy-engine"

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
TAG="laptop-observe-v1-${STAMP}"
IMAGE="${IMAGE_REPO}:${TAG}"
TAR="/tmp/zt-xguard-policy-engine-${TAG}.tar"

cd "$POLICY_DIR"

echo "=================================================="
echo " ZT-XGuard Policy Engine Redeployment"
echo " Image: $IMAGE"
echo "=================================================="

echo
echo "===== 1. VALIDATE SOURCE ====="

python3 -m py_compile app.py ztx_state_engine.py

if command -v node >/dev/null 2>&1; then
    node --check static/dashboard.js
else
    echo "WARNING: node is unavailable; dashboard.js syntax check skipped"
fi

if grep -nE '/home/agent' app.py; then
    echo "ERROR: app.py still contains /home/agent."
    echo "Use /evidence/forensics instead."
    exit 1
fi

test -f templates/dashboard.html
test -f static/dashboard.js
test -f static/dashboard.css

echo "SOURCE_VALIDATION_OK"

echo
echo "===== 2. BUILD IMAGE ====="

docker build     --no-cache     --pull     -t "$IMAGE"     .

echo
echo "===== 3. VERIFY IMAGE CONTENT ====="

docker run --rm     --entrypoint sh     "$IMAGE"     -c '
        python3 -m py_compile /app/app.py /app/ztx_state_engine.py
        test -f /app/templates/dashboard.html
        test -f /app/static/dashboard.js
        test -f /app/static/dashboard.css
        echo IMAGE_CONTENT_OK
    '

echo
echo "===== 4. IMPORT INTO CONTAINERD ====="

rm -f "$TAR"
docker save "$IMAGE" -o "$TAR"

sudo ctr -n k8s.io images import "$TAR"

sudo ctr -n k8s.io images list -q |
    grep -Fx "$IMAGE" >/dev/null

echo "CONTAINERD_IMAGE_IMPORTED"

echo
echo "===== 5. ENFORCEMENT SETTINGS (REAL ISOLATION ENABLED) ====="

# 2026-08-23: real-isolation demo build. AUTO_QUARANTINE is inert on the
# live Falco path in this refactor (containment fires on ISOLATED state
# regardless), but set true for clarity. REVOKE_SPIRE MUST be true -
# revoke_workload_identity() (containment_orchestrator.py) short-circuits
# when it is false, silently dropping the SVID/identity-revocation lock.
kubectl set env     deployment/"$DEPLOYMENT"     -n "$NAMESPACE"     AUTO_QUARANTINE=true     REVOKE_SPIRE=true     ALLOW_DESTRUCTIVE_ACTIONS=true     T2_AUTO_CONTAIN=true     CONTAINMENT_MODE=service     TRUST_DOMAIN=oran.fyp.local     SPIRE_NAMESPACE=spire-server     MY_FORENSICS_DIR=/evidence/forensics

echo
echo "===== 6. UPDATE DEPLOYMENT IMAGE ====="

kubectl set image     deployment/"$DEPLOYMENT"     -n "$NAMESPACE"     "$CONTAINER=$IMAGE"

echo
echo "===== 7. WAIT FOR ROLLOUT ====="

kubectl rollout status     deployment/"$DEPLOYMENT"     -n "$NAMESPACE"     --timeout=300s

kubectl wait     --for=condition=Ready     pod     -n "$NAMESPACE"     -l app=zt-xguard-policy-engine     --timeout=180s

echo
echo "===== 8. VERIFY POD AND IMAGE ====="

kubectl get pods     -n "$NAMESPACE"     -l app=zt-xguard-policy-engine     -o custom-columns='POD:.metadata.name,READY:.status.containerStatuses[0].ready,STATUS:.status.phase,IMAGE:.spec.containers[0].image,RESTARTS:.status.containerStatuses[0].restartCount'

echo
echo "===== 9. VERIFY STARTUP LOGS ====="

LOGS=$(
    kubectl logs         -n "$NAMESPACE"         deployment/"$DEPLOYMENT"         --tail=160
)

printf '%s\n' "$LOGS" |
    grep -E     'ZTX_DESTRUCTIVE_ACTION_GUARD|Running on|PermissionError|Traceback|ERROR|Exception'     || true

if printf '%s\n' "$LOGS" |
    grep -Eq 'PermissionError|Traceback'; then
    echo "ERROR: Policy engine startup failed."
    exit 1
fi

echo
echo "===== 10. VERIFY SERVICE AND DASHBOARD ====="

kubectl get service "$DEPLOYMENT"     -n "$NAMESPACE"     -o wide

IP=$(
    ip route get 1.1.1.1 2>/dev/null |
    awk '{
        for (i=1; i<=NF; i++) {
            if ($i=="src") {
                print $(i+1)
                exit
            }
        }
    }'
)

if [ -z "${IP:-}" ]; then
    IP=$(hostname -I | awk '{print $1}')
fi

DASHBOARD_URL="http://${IP}:30500/dashboard?build=${TAG}"
STATE_URL="http://${IP}:30500/csm/state"

for attempt in $(seq 1 20); do
    HTTP_CODE=$(
        curl -sS             --max-time 5             -o /dev/null             -w '%{http_code}'             "$DASHBOARD_URL"             || true
    )

    if [ "$HTTP_CODE" = "200" ]; then
        break
    fi

    sleep 2
done

echo "dashboard_http=${HTTP_CODE}"

if [ "$HTTP_CODE" != "200" ]; then
    echo "ERROR: Dashboard did not return HTTP 200."
    exit 1
fi

echo
echo "===== 11. VERIFY ENFORCEMENT MODE ====="

# There is no /csm/safety route in this codebase (the old script curled it
# and aborted every deploy under `set -e`). Verify a real API endpoint is
# up, then read the enforcement flags from the deployment itself - the
# authoritative source of truth.
STATE_HTTP=$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "$STATE_URL" || true)
echo "csm_state_http=${STATE_HTTP}"
if [ "$STATE_HTTP" != "200" ]; then
    echo "ERROR: /csm/state did not return HTTP 200."
    exit 1
fi

echo "enforcement_env:"
kubectl get deployment/"$DEPLOYMENT"     -n "$NAMESPACE"     -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}'     | grep -E 'AUTO_QUARANTINE|REVOKE_SPIRE|ALLOW_DESTRUCTIVE_ACTIONS|T2_AUTO_CONTAIN|CONTAINMENT_MODE' || true

echo
echo "=================================================="
echo " REDEPLOYMENT COMPLETE"
echo " Image:     $IMAGE"
echo " Dashboard: http://${IP}:30500/dashboard"
echo "=================================================="

rm -f "$TAR"
