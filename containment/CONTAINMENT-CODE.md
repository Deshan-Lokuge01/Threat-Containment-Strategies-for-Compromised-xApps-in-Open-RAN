# ZT-XGuard — Containment Mechanisms (the actual code)

How a detection becomes containment, and the exact code behind each of the four
concurrent "locks" + the live isolation verification. All paths are under
`ztx-control-plane/policy-engine/` (mirrored in `codes/01-policy-engine/`).

---

## 0) Trigger — detection → decision → containment
A Falco (behavioural) or T² (resource) signal is scored by the state engine. If the
verdict is **COMPROMISED** and the signal is containment-capable and auto-quarantine is
armed, the **single entry point** `apply_quarantine()` is called. `app.py:1431`:

```python
decision_state = str(result.get("state") or "").upper()
containment_required = (
    decision_state == "COMPROMISED"
    and (normalized_signal in ZTX_QUARANTINE_CAPABLE_SIGNALS
         or normalized_signal in {"svid_material_access", "unexpected_shell"}))
...
if (result.get("state") == "COMPROMISED" or containment_required) and xapp in XAPP_LIST and pod_name != "unknown":
    if AUTO_QUARANTINE:
        quarantine = apply_quarantine(pod_name, namespace, reason, incident_id, ...)   # app.py:1464
```
Behaviour, resource (T² `_ztx_force_containment_for_xapp`) and the operator's *Isolate
Now* all converge on the same `apply_quarantine()` (`containment_orchestrator.py:1051`),
which fans the four mechanisms out and records each one's real latency (shown live in the
dashboard's Detection & Containment panel).

---

## ① Calico NetworkPolicy — deny-all  (CNI / pod network, ~0.1–0.2 s)
**Trigger:** the pod is stamped with a label; a NetworkPolicy selecting that label blocks it.
`containment_orchestrator.py:437` and `:259`:
```python
# stamp the pod
patch = {"metadata": {"labels": {"zt-xguard.io/quarantine": "true",
                                 "security-status": "quarantined", ...}}}
ztx_guarded_patch_namespaced_pod(name=pod_name, namespace=namespace, body=patch, ...)
ensure_quarantine_network_policy(namespace)

# the deny-all object
netpol = client.V1NetworkPolicy(
    metadata=client.V1ObjectMeta(name="zt-xguard-quarantine-deny-all", namespace=namespace),
    spec=client.V1NetworkPolicySpec(
        pod_selector=client.V1LabelSelector(match_labels={"zt-xguard.io/quarantine": "true"}),
        policy_types=["Ingress", "Egress"], ingress=[], egress=[]))   # empty rules = deny ALL
NET.create_namespaced_network_policy(namespace=namespace, body=netpol)  # 409 -> patch
```
**Behind the scenes:** empty `ingress`/`egress` = deny everything both directions; the
policy targets `zt-xguard.io/quarantine=true`, so labelling the pod pulls it under the
policy. **Calico/Felix** compiles it to `iptables-nft` on the node (verified real —
measurably blocks a raw TCP connect). Stops pod-to-pod / lateral movement in `ricxapp`.

---

## ② Service-selector isolation  (Kubernetes service layer, ~0.8 s)
**Trigger:** `apply_quarantine` → `apply_service_isolation(xapp, …)`. `containment_orchestrator.py:674`:
```python
patch = {
  "metadata": {"annotations": {ORIGINAL_SELECTOR_ANNOTATION: original_selector,  # saved for restore
                               SERVICE_ISOLATED_ANNOTATION: "true", ...}},
  "spec": {"selector": {"zt-xguard.io/service-isolated": selector_token}}}        # a label NO pod has
CORE.patch_namespaced_service(name=svc_name, namespace=namespace, body=patch)
time.sleep(0.2)                                     # let the endpoints controller update
ep_summary = service_endpoints_summary(svc_name, namespace)
```
**Behind the scenes:** a Service routes to pods matching its `selector`. Swapping it to a
token **no pod carries** makes the endpoints controller **empty the Service endpoints** —
traffic to the Service DNS/ClusterIP has nowhere to land. Original selector kept in an
annotation for restore.

---

## ③ Node-level iptables DROP  (host kernel, CNI-independent, ~1.3 s)
**Trigger:** `apply_quarantine` → `apply_direct_network_isolation(pod_ip, …)`. `containment_orchestrator.py:1822`:
```python
ensure_direct_quarantine_chain()   # create ZTX-DIRECT-QUARANTINE + jump from raw/PREROUTING
for direction, rule_args in (("egress",  ["-s", pod_ip, "-j", "DROP"]),
                             ("ingress", ["-d", pod_ip, "-j", "DROP"])):
    if not _ztx_exec_iptables(["-t","raw","-C", DIRECT_IPTABLES_CHAIN]+rule_args).get("ok"):
        _ztx_exec_iptables(["-t","raw","-A", DIRECT_IPTABLES_CHAIN]+rule_args)   # add DROP
verification = verify_direct_network_isolation(pod_ip)
```
**How it runs on the node** (`containment_orchestrator.py:1736`): the policy-engine has no
host root, so it **execs `iptables` inside the privileged `calico-node` container**
(`NET_ADMIN` / `hostNetwork`) via the Kubernetes exec API:
```python
resp = stream(EXEC_CORE.connect_get_namespaced_pod_exec,
    name=pod_name, namespace=DIRECT_IPTABLES_NAMESPACE, container="calico-node",
    command=["iptables"] + args, _preload_content=False, ...)
```
**Behind the scenes:** rules live in the **`raw`/`PREROUTING`** table — chosen after
testing, because it runs *before* NAT/routing and catches even same-node "hairpin" service
traffic that `FORWARD` missed. A second, independent block that works even if the CNI is
bypassed.

---

## ④ SPIFFE/SVID revocation — identity withdrawal  (zero-trust identity, ~3–5 s)
**Trigger:** once containment is applied, `apply_quarantine` → `revoke_workload_identity(pod_name, …)`.
`containment_orchestrator.py:1634`:
```python
if not REVOKE_SPIRE: return {"attempted": False, "revoked": False, "reason": "REVOKE_SPIRE=false"}
patch = {"metadata": {"labels": {"zt-xguard.io/svid-enabled": "false"}}}
ztx_guarded_patch_namespaced_pod(name=pod_name, namespace=namespace, body=patch, ...)
```
**Behind the scenes:** `ClusterSPIFFEID zt-xguard-ricxapp-identity` selects pods with
`zt-xguard.io/svid-enabled=true`. Setting it **false** makes the pod stop matching, so
**spire-controller-manager reconciles and removes the pod's SPIRE registration entry** —
the workload can no longer fetch/renew an SVID (the ~3–5 s withdrawal is measured live by
`_measure_svid_withdrawal`). This revokes the *identity itself*, so even a network escape
can't authenticate to any mTLS peer. Network **and** identity are both revoked.

---

## Live 3-way verification — "Verify Isolation"
`verify_isolation()` in `ztx_dashboard_api.py:913` proves it empirically (not a flag):
1. **Control-plane** — `verify_direct_network_isolation(pod_ip)` reads the node iptables and
   confirms the `ZTX-DIRECT-QUARANTINE` DROP rules exist (ingress **and** egress).
2. **Active ingress** — creates a throwaway unlabeled probe pod and does a real
   `nc -z -w3 <pod_ip> <port>`; timeout ⇒ blocked; then deletes the probe pod.
3. **Active egress** (only if COMPROMISED/ISOLATED) — execs inside the xApp and tries
   `nc`/`wget → 8.8.8.8`; fail ⇒ egress blocked.

**Verdict:** `overall_isolated = control_plane.blocked AND NOT ingress_reachable`. The
command-by-command transcript streams into the dashboard's verification terminal and sets
the three check rows + the ISOLATED/REACHABLE badge.

---

### One-line summary
One decision (`apply_quarantine`) fans out to four API-driven actions — a **pod label** that
triggers a **deny-all NetworkPolicy** (Calico), a **Service-selector rewrite** that empties
the endpoints, an **`iptables -A … DROP` exec'd inside calico-node** at raw/PREROUTING, and a
**`svid-enabled=false` label** that makes SPIRE withdraw the identity — then it *proves*
isolation live with a fresh probe pod.
