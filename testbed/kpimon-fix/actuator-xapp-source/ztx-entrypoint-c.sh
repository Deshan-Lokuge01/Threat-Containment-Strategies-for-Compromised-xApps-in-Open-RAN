#!/usr/bin/env bash
set -Eeuo pipefail

/opt/ztx/ztx-kpimon-actuator-c >> /tmp/ztx-kpimon-actuator-c.log 2>&1 &

exec /bin/bash ./entripoint.sh
