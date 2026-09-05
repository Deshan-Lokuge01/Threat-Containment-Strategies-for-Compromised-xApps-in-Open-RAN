# Deployment

Kubernetes manifests and platform configuration for running ZT-XGuard on the Near-RT RIC cluster.

- `k8s/` — deployments, RBAC, the SPIRE setup, xApp security profiles, and the NetworkPolicies used
  for containment.
- `ric-dep/` — RIC deployment helpers (CRDs, Helm values) used when bringing the platform up.
- `policies/` — admission / Kyverno policies applied to the cluster.

Containment relies on Calico (canal) enforcing NetworkPolicies, SPIRE issuing SVIDs to labelled xApp
pods, and the policy engine having RBAC to patch pods/services and to exec into `calico-node` for the
node-level iptables lock.
