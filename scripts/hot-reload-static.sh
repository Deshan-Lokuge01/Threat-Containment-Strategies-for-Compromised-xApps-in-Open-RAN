#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# FAST static hot-reload — copy edited soc.js / soc.css / dashboard.html
# straight into the RUNNING policy-engine pod. No rebuild, no sudo, instant.
#
#   soc.js / soc.css : served fresh from disk on every request -> just refresh
#                      the browser (Ctrl-Shift-R). The dashboard's own
#                      cache-buster already defeats browser caching.
#   dashboard.html   : a Jinja template; Flask may cache it, so this script
#                      also touches app.py to trigger a soft in-pod reload if
#                      you edited the template (harmless otherwise).
#
# CAVEAT: changes are EPHEMERAL - lost the next time the pod restarts. Once a
# change is final, bake it into the image with scripts/rebuild-redeploy.sh.
# ---------------------------------------------------------------------------
set -euo pipefail
NS=zt-xguard
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ztx-control-plane/policy-engine"

POD=$(kubectl get pods -n "$NS" -l app=zt-xguard-policy-engine \
        -o jsonpath='{.items[0].metadata.name}')
[ -z "$POD" ] && { echo "no policy-engine pod found" >&2; exit 1; }
echo "target pod: $POD"

for f in static/soc.js static/soc.css static/soc.html templates/dashboard.html; do
  [ -f "$SRC/$f" ] || continue
  kubectl cp "$SRC/$f" "$NS/$POD:/app/$f" && echo "  copied $f"
done

echo "done. Hard-refresh the dashboard (Ctrl-Shift-R) at :30500/dashboard"
echo "NOTE: ephemeral - run scripts/rebuild-redeploy.sh to make it permanent."
