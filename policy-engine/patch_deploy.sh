# Patch the policy engine deployment to rollout the new code
kubectl cp app.py zt-xguard/$(kubectl get pod -n zt-xguard -l app=zt-xguard-policy-engine -o jsonpath='{.items[0].metadata.name}'):/app/app.py
# restart the pod
kubectl delete pod -n zt-xguard -l app=zt-xguard-policy-engine
sleep 5
# Wait for pod to be ready
kubectl wait --for=condition=Ready pod -n zt-xguard -l app=zt-xguard-policy-engine --timeout=60s
