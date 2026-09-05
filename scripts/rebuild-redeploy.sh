#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# PERMANENT redeploy — bake edited image files (soc.js, soc.css,
# dashboard.html, ztx_dashboard_api.py, templates/*, static/*) into a fresh
# policy-engine image and roll it out. Survives pod restarts.
#
# These files live in the IMAGE (NOT the ConfigMap), so a real rebuild is
# required. app.py / containment_orchestrator.py etc. come from the ConfigMap
# instead - use a `kubectl patch cm ...` for those, not this script.
#
# Requires sudo (for `ctr import`) - it will prompt for your password.
# Run it directly in your terminal:   ./scripts/rebuild-redeploy.sh
# ---------------------------------------------------------------------------
set -euo pipefail
NS=zt-xguard
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ztx-control-plane/policy-engine"
cd "$DIR"

TAG="soc-dash-manual-$(date -u +%Y%m%dT%H%M%SZ)"
IMG="docker.io/library/zt-xguard-policy-engine:$TAG"
TAR="/tmp/zt-xguard-$TAG.tar"

echo "[1/5] node --check soc.js (catch JS syntax errors before shipping)"
command -v node >/dev/null && node --check static/soc.js && echo "  JS OK" || echo "  (node not found - skipping JS check)"

echo "[2/5] docker build -> $IMG"
docker build -t "$IMG" .

echo "[3/5] docker save -> $TAR"
docker save "$IMG" -o "$TAR"

echo "[4/5] sudo ctr -n k8s.io images import $TAR   (enter password if prompted)"
sudo ctr -n k8s.io images import "$TAR"

echo "[5/5] kubectl set image + rollout"
kubectl set image deployment/zt-xguard-policy-engine -n "$NS" policy-engine="$IMG"
kubectl rollout status deployment/zt-xguard-policy-engine -n "$NS" --timeout=180s

rm -f "$TAR"
echo "DONE. Deployed $IMG"
echo "Verify: curl -s -o /dev/null -w '%{http_code}\\n' http://192.168.8.159:30500/dashboard"
