#!/usr/bin/env bash
set -Eeuo pipefail

if [ -z "${ZTX_ACTUATOR_TOKEN:-}" ]; then
  echo "ERROR: ZTX_ACTUATOR_TOKEN is required" >&2
  exit 1
fi

/opt/ztx/ztx-kpimon-actuator >> /tmp/ztx-kpimon-actuator.log 2>&1 &

exec /bin/bash ./entripoint.sh
