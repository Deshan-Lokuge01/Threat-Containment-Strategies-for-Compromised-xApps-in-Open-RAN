# Create a configmap from app.py and mount it into the deployment to override the baked-in file
kubectl create configmap zt-xguard-policy-engine-app -n zt-xguard --from-file=app.py=app.py --dry-run=client -o yaml | kubectl apply -f -

kubectl patch deployment zt-xguard-policy-engine -n zt-xguard --patch '
spec:
  template:
    spec:
      containers:
      - name: policy-engine
        volumeMounts:
        - name: app-script
          mountPath: /app/app.py
          subPath: app.py
      volumes:
      - name: app-script
        configMap:
          name: zt-xguard-policy-engine-app
'

# restart the pod
kubectl rollout restart deployment zt-xguard-policy-engine -n zt-xguard
kubectl rollout status deployment zt-xguard-policy-engine -n zt-xguard --timeout=60s
