#!/bin/bash
set -euo pipefail
ROOT_DIR="${HOME}/Desktop/FYP/zt-xguard"
XAPPS=(
  "telemetry-monitor:zt-telemetry-monitor:1.0"
  "qos-optimizer:zt-qos-optimizer:1.0"
  "traffic-analyzer:zt-traffic-analyzer:1.0"
  "resource-optimizer:zt-resource-optimizer:1.0"
  "security-observer:zt-security-observer:1.0"
)
cd "${ROOT_DIR}/xapps"
for ITEM in "${XAPPS[@]}"; do
  APP_DIR=$(echo "$ITEM" | cut -d: -f1)
  IMAGE=$(echo "$ITEM" | cut -d: -f2)
  TAG=$(echo "$ITEM" | cut -d: -f3)
  echo "Building ${APP_DIR} -> ${IMAGE}:${TAG}"
  docker build -f "${APP_DIR}/Dockerfile" -t "${IMAGE}:${TAG}" .
  docker save "${IMAGE}:${TAG}" -o "/tmp/${IMAGE}-${TAG}.tar"
  sudo ctr -n k8s.io images import "/tmp/${IMAGE}-${TAG}.tar"
  sudo ctr -n k8s.io images list | grep "${IMAGE}"
done
echo "All final xApp images built and imported into containerd."
