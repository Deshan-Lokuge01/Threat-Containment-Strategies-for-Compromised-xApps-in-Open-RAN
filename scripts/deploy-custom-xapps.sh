#!/bin/bash
set -euo pipefail

NAMESPACE="ricxapp"
IMAGE="zt-xguard-xapp-base:1.0"
ROOT_DIR="${HOME}/Desktop/FYP/zt-xguard"

XAPPS=(
  "telemetry-monitor"
  "qos-optimizer"
  "traffic-analyzer"
  "resource-optimizer"
  "security-observer"
)

echo "[ZT-XGuard] Deploying custom legitimate xApps into namespace: ${NAMESPACE}"

kubectl get ns "${NAMESPACE}" >/dev/null

for XAPP in "${XAPPS[@]}"; do
  echo ""
  echo "================================================"
  echo "Deploying ${XAPP}"
  echo "================================================"

  PROFILE_FILE="${ROOT_DIR}/k8s/profiles/${XAPP}-profile.json"

  if [ ! -f "${PROFILE_FILE}" ]; then
    echo "Missing profile file: ${PROFILE_FILE}"
    exit 1
  fi

  kubectl create serviceaccount "${XAPP}" -n "${NAMESPACE}" \
    --dry-run=client -o yaml | kubectl apply -f -

  kubectl create configmap "${XAPP}-profile" \
    -n "${NAMESPACE}" \
    --from-file=profile.json="${PROFILE_FILE}" \
    --dry-run=client -o yaml | kubectl apply -f -

  cat <<YAML | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${XAPP}
  namespace: ${NAMESPACE}
  labels:
    app: ${XAPP}
    zt-xguard/component: custom-xapp
    zt-xguard/profile: ${XAPP}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${XAPP}
  template:
    metadata:
      labels:
        app: ${XAPP}
        zt-xguard/component: custom-xapp
        zt-xguard/profile: ${XAPP}
        security-status: trusted
    spec:
      serviceAccountName: ${XAPP}
      containers:
      - name: ${XAPP}
        image: ${IMAGE}
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 8080
          name: http
        env:
        - name: XAPP_NAME
          value: "${XAPP}"
        - name: XAPP_PORT
          value: "8080"
        - name: XAPP_PROFILE_PATH
          value: "/etc/xapp-profile/profile.json"
        volumeMounts:
        - name: xapp-profile
          mountPath: /etc/xapp-profile
          readOnly: true
        - name: spire-socket
          mountPath: /run/spire/sockets
          readOnly: true
        resources:
          requests:
            cpu: "50m"
            memory: "64Mi"
          limits:
            cpu: "1000m"
            memory: "256Mi"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: false
          runAsNonRoot: true
          runAsUser: 10001
          capabilities:
            drop:
            - ALL
      volumes:
      - name: xapp-profile
        configMap:
          name: ${XAPP}-profile
      - name: spire-socket
        csi:
          driver: csi.spiffe.io
          readOnly: true
---
apiVersion: v1
kind: Service
metadata:
  name: ${XAPP}
  namespace: ${NAMESPACE}
  labels:
    app: ${XAPP}
spec:
  selector:
    app: ${XAPP}
  ports:
  - name: http
    port: 8080
    targetPort: 8080
YAML

done

echo ""
echo "[ZT-XGuard] Waiting for custom xApps to become ready..."
kubectl wait --for=condition=Available deployment \
  -n "${NAMESPACE}" \
  -l zt-xguard/component=custom-xapp \
  --timeout=180s || true

echo ""
kubectl get pods -n "${NAMESPACE}" -l zt-xguard/component=custom-xapp -o wide
