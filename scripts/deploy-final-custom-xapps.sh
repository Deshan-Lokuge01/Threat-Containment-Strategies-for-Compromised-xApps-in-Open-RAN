#!/bin/bash
set -euo pipefail

ROOT_DIR="${HOME}/Desktop/FYP/zt-xguard"
NAMESPACE="ricxapp"
FETCHER_IMAGE="docker.io/library/zt-spire-fetcher:1.0"

XAPPS=(
  "telemetry-monitor"
  "qos-optimizer"
  "traffic-analyzer"
  "resource-optimizer"
  "security-observer"
)

kubectl get namespace "$NAMESPACE" >/dev/null

for XAPP in "${XAPPS[@]}"; do
  echo
  echo "=================================================="
  echo "Deploying: $XAPP"
  echo "=================================================="

  PROFILE="${ROOT_DIR}/k8s/profiles/${XAPP}-profile.json"
  IMAGE="docker.io/library/zt-${XAPP}:1.0"

  if [ ! -f "$PROFILE" ]; then
    echo "Missing profile: $PROFILE"
    exit 1
  fi

  kubectl create serviceaccount "$XAPP" \
    -n "$NAMESPACE" \
    --dry-run=client -o yaml |
  kubectl apply -f -

  kubectl create configmap "${XAPP}-profile" \
    -n "$NAMESPACE" \
    --from-file=profile.json="$PROFILE" \
    --dry-run=client -o yaml |
  kubectl apply -f -

  cat <<YAML | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${XAPP}
  namespace: ${NAMESPACE}
  labels:
    app: ${XAPP}
    zt-xguard/component: custom-xapp
spec:
  replicas: 1

  strategy:
    type: Recreate

  selector:
    matchLabels:
      app: ${XAPP}

  template:
    metadata:
      labels:
        app: ${XAPP}
        zt-xguard/component: custom-xapp
        zt-xguard/profile: ${XAPP}
        zt-xguard.io/svid-enabled: "true"
        security-status: trusted
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/path: "/metrics"
        prometheus.io/port: "8080"

    spec:
      serviceAccountName: ${XAPP}
      automountServiceAccountToken: false
      terminationGracePeriodSeconds: 5

      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        fsGroupChangePolicy: OnRootMismatch
        seccompProfile:
          type: RuntimeDefault

      volumes:
        - name: spiffe-socket
          csi:
            driver: csi.spiffe.io
            readOnly: true

        - name: svid-data
          emptyDir: {}

        - name: xapp-profile
          configMap:
            name: ${XAPP}-profile

      initContainers:
        - name: fetch-svid
          image: ${FETCHER_IMAGE}
          imagePullPolicy: IfNotPresent

          command:
            - /bin/sh
            - -ec

          args:
            - |
              SOCKET=/run/spire/sockets/spire-agent.sock
              OUTPUT=/etc/svid

              echo "Waiting for SPIRE socket..."

              for i in \$(seq 1 60); do
                [ -S "\$SOCKET" ] && break
                echo "Socket not ready: \$i/60"
                sleep 2
              done

              test -S "\$SOCKET"
              mkdir -p "\$OUTPUT"

              echo "Waiting for workload identity..."

              for i in \$(seq 1 60); do
                if /opt/spire/bin/spire-agent api fetch x509 \
                     -socketPath "\$SOCKET" \
                     -write "\$OUTPUT"
                then
                  chmod 0644 "\$OUTPUT/svid.0.pem"
                  chmod 0600 "\$OUTPUT/svid.0.key"
                  chmod 0644 "\$OUTPUT/bundle.0.pem"

                  echo "SVID_FETCH_OK"
                  exit 0
                fi

                echo "Identity not ready: \$i/60"
                sleep 2
              done

              echo "SVID_FETCH_FAILED"
              exit 1

          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            runAsUser: 10001
            runAsGroup: 10001
            capabilities:
              drop:
                - ALL

          resources:
            requests:
              cpu: 5m
              memory: 16Mi
            limits:
              cpu: 50m
              memory: 64Mi

          volumeMounts:
            - name: spiffe-socket
              mountPath: /run/spire/sockets
              readOnly: true

            - name: svid-data
              mountPath: /etc/svid

      containers:
        - name: ${XAPP}
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent

          ports:
            - name: http
              containerPort: 8080
              protocol: TCP

          env:
            - name: XAPP_NAME
              value: "${XAPP}"

            - name: XAPP_PORT
              value: "8080"

            - name: XAPP_PROFILE_PATH
              value: /etc/xapp-profile/profile.json

            - name: XAPP_SVID_CERT
              value: /etc/svid/svid.0.pem

            - name: XAPP_SVID_KEY
              value: /etc/svid/svid.0.key

            - name: XAPP_SVID_BUNDLE
              value: /etc/svid/bundle.0.pem

          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: false
            runAsNonRoot: true
            runAsUser: 10001
            runAsGroup: 10001
            capabilities:
              drop:
                - ALL

          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 1000m
              memory: 256Mi

          volumeMounts:
            - name: xapp-profile
              mountPath: /etc/xapp-profile
              readOnly: true

            - name: svid-data
              mountPath: /etc/svid
              readOnly: true

          readinessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 6

          livenessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 15
            periodSeconds: 15
            timeoutSeconds: 3
            failureThreshold: 4

        - name: renew-svid
          image: ${FETCHER_IMAGE}
          imagePullPolicy: IfNotPresent

          command:
            - /bin/sh
            - -ec

          args:
            - |
              SOCKET=/run/spire/sockets/spire-agent.sock
              OUTPUT=/etc/svid
              TMP=/tmp/svid-next

              while true; do
                rm -rf "\$TMP"
                mkdir -p "\$TMP"

                if /opt/spire/bin/spire-agent api fetch x509 \
                     -silent \
                     -socketPath "\$SOCKET" \
                     -write "\$TMP"
                then
                  cp "\$TMP/svid.0.pem" "\$OUTPUT/svid.0.pem.new"
                  cp "\$TMP/svid.0.key" "\$OUTPUT/svid.0.key.new"
                  cp "\$TMP/bundle.0.pem" "\$OUTPUT/bundle.0.pem.new"

                  chmod 0644 "\$OUTPUT/svid.0.pem.new"
                  chmod 0600 "\$OUTPUT/svid.0.key.new"
                  chmod 0644 "\$OUTPUT/bundle.0.pem.new"

                  mv "\$OUTPUT/svid.0.pem.new" "\$OUTPUT/svid.0.pem"
                  mv "\$OUTPUT/svid.0.key.new" "\$OUTPUT/svid.0.key"
                  mv "\$OUTPUT/bundle.0.pem.new" "\$OUTPUT/bundle.0.pem"

                  echo "\$(date -u +%FT%TZ) SVID_RENEW_OK"
                else
                  echo "\$(date -u +%FT%TZ) SVID_RENEW_FAILED"
                fi

                sleep 60
              done

          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            runAsUser: 10001
            runAsGroup: 10001
            capabilities:
              drop:
                - ALL

          resources:
            requests:
              cpu: 5m
              memory: 16Mi
            limits:
              cpu: 50m
              memory: 64Mi

          volumeMounts:
            - name: spiffe-socket
              mountPath: /run/spire/sockets
              readOnly: true

            - name: svid-data
              mountPath: /etc/svid

---
apiVersion: v1
kind: Service
metadata:
  name: ${XAPP}
  namespace: ${NAMESPACE}
  labels:
    app: ${XAPP}
    zt-xguard/component: custom-xapp
spec:
  type: ClusterIP

  selector:
    app: ${XAPP}

  ports:
    - name: http
      port: 8080
      targetPort: http
      protocol: TCP
YAML

done

echo
echo "Waiting for all five deployments..."

for XAPP in "${XAPPS[@]}"; do
  kubectl rollout status \
    deployment/"$XAPP" \
    -n "$NAMESPACE" \
    --timeout=240s
done

echo
echo "All custom xApps deployed."
kubectl get pods \
  -n "$NAMESPACE" \
  -l zt-xguard/component=custom-xapp \
  -o wide
