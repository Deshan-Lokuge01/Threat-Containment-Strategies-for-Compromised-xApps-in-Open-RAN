# Containment — four concurrent locks + automated isolation

This is the core of ZT-XGuard. When the policy engine confirms an xApp is **COMPROMISED**, one call —
`apply_quarantine()` — fans out to four independent mechanisms at the same time and revokes the
workload's identity. Any one of them would slow an attacker down; together they leave no reachable
path and no usable identity.

The exact code, with file and line references, is in
[`CONTAINMENT-CODE.md`](CONTAINMENT-CODE.md).

## The four locks

| # | Lock | Layer | How it works | Time-to-effect (measured) |
|---|------|-------|--------------|---------------------------|
| 1 | Calico deny-all **NetworkPolicy** | CNI / pod network | The pod is labelled `zt-xguard.io/quarantine=true`; a NetworkPolicy selecting that label denies all ingress and egress. Calico/Felix compiles it to `iptables-nft` on the node. | ~0.1 s (control-plane apply) |
| 2 | **Service-selector isolation** | Kubernetes service | The Service selector is rewritten to a token no pod carries, so the endpoints controller empties the service endpoints — traffic to the service DNS/ClusterIP has nowhere to land. | ~0.4–1 s (real endpoint drain) |
| 3 | Node **iptables DROP** | host kernel, CNI-independent | The engine execs `iptables` inside the privileged `calico-node` container and adds DROP rules for the pod IP in the `raw/PREROUTING` table — before NAT/routing, catching same-node hairpin traffic. | ~0.8–1.3 s (rule + verify) |
| 4 | **SPIFFE/SVID revocation** | zero-trust identity | The pod's `zt-xguard.io/svid-enabled` label is set to `false`; the SPIRE controller reconciles and removes the registration entry, so the workload can no longer fetch or renew an SVID. | ~3–5 s (full withdrawal) |

Because the locks run in parallel, wall-clock containment equals the slowest one — the SVID
withdrawal. That is the honest containment latency the dashboard reports.

## Automated isolation and the 30-second dwell

- **Behavioural (Falco) incidents** are treated as immediate, high-confidence compromises and isolate
  right away.
- **Resource / DoS (T²) incidents** start a **30-second dwell** at COMPROMISED before auto-isolation,
  so an operator can intervene (or force it early from the dashboard). The dwell is implemented in
  [`ztx_isolation_manager.py`](ztx_isolation_manager.py) (`DWELL_SECONDS = 30.0`) and is guaranteed by
  a background checker even if no further signal arrives. Isolation is only displayed and applied once
  the dwell actually elapses.

## Live verification

Isolation is proven empirically, not assumed. The dashboard's "Verify Isolation" runs a real
three-way check: it reads the node iptables to confirm the DROP rules exist, launches a throwaway
probe pod and tries to reach the isolated pod, and (for a compromised xApp) tries to egress from
inside the xApp to a RIC platform peer. The verdict is `blocked AND not reachable`.

## Files

- `CONTAINMENT-CODE.md` — the actual code behind each mechanism, with triggers and behind-the-scenes notes.
- `containment_orchestrator.py` — `apply_quarantine()` and the four mechanism functions.
- `ztx_isolation_manager.py` — the COMPROMISED→ISOLATED transition manager and 30 s dwell.

> The full policy engine that calls this code lives in [`../policy-engine/`](../policy-engine/).
