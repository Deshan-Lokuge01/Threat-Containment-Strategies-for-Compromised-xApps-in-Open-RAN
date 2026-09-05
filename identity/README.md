# Workload identity — SPIRE / SPIFFE

Every guarded xApp is issued a short-lived, cryptographically verifiable identity (an **SVID**) by
SPIRE, based on its SPIFFE ID. This is the fourth containment lock's foundation: when an xApp is
compromised, revoking its identity means it can no longer authenticate to any RIC peer, even if it
somehow keeps a network path.

## How it works

- **ClusterSPIFFEID** `zt-xguard-ricxapp-identity` selects pods that carry the label
  `zt-xguard.io/svid-enabled=true` in the `ricxapp` namespace, trust domain `oran.fyp.local`.
- SPIRE attests each workload and issues an X.509 SVID, renewed continuously by a sidecar.
- **On isolation**, the policy engine sets `zt-xguard.io/svid-enabled=false`. The pod stops matching
  the ClusterSPIFFEID, the SPIRE controller reconciles, and the registration entry is removed — the
  workload can no longer fetch or renew an SVID. Full withdrawal takes ~3–5 s and is measured live.

## Files

- `spire/` — SPIRE server/agent deployment and ClusterSPIFFEID configuration.
- `clusterspiffeid*.txt` — the live ClusterSPIFFEID definition and describe output from the cluster.

> The revocation code path is in [`../containment/`](../containment/) (`revoke_workload_identity`).
