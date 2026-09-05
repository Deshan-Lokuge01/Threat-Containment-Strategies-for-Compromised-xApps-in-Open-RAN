# The research journey — including the wrong turns

A project report usually presents the final design as if it were obvious from the start. It
wasn't. Several parts of ZT-XGuard exist in their current shape because an earlier attempt
failed and taught us something. This page records those detours honestly, since the final
choices only make sense once you know what we ruled out.

## 1. Detecting resource attacks: a machine-learning model first

Our first plan for catching resource-exhaustion (DoS) attacks on kpimon-go was a machine-learning
model. We collected CPU/memory/network features from clean runs and attack runs and trained a
classifier / anomaly model to flag "abnormal" behaviour.

**Why we moved away from it:**

- **It was hard to justify.** For a security control that automatically isolates a workload, "the
  model said so" is a weak answer. We could not cleanly explain, for an arbitrary decision, *which*
  feature crossed *what* boundary.
- **Non-determinism and drift.** Retraining on slightly different captures moved the decision
  boundary. The same attack could be caught one day and missed the next, which is unacceptable for a
  containment trigger.
- **False positives on benign bursts.** Legitimate load spikes (a burst of E2 indications, a busy
  UE) looked "anomalous" to the model and would have isolated a perfectly healthy xApp.
- **Calibration was opaque.** We could not point at a single, frozen threshold and say "this is the
  line, and here is why".

**What we built instead:** a deterministic **MEWMA (Multivariate EWMA) T² detector** with a frozen,
calibrated CPU-rate gate. It accumulates evidence over a rolling window and only declares
COMPROMISED after a **6-of-8 corroboration** plus a CPU rate-of-exceedance gate — roughly a minute of
sustained, corroborated evidence rather than a single spike. Every decision reduces to explicit,
frozen numbers we can show and defend. The calibration is locked in a manifest and never retrained
at runtime. See [`../detection/statistical-model/`](../detection/statistical-model/).

The ML idea did not go to waste — it survives as a *future work* direction in the design section of
the main README, but it is not what guards the live system.

## 2. Containment: network policy alone was not enough

The first containment design relied on a single mechanism: a Calico **deny-all NetworkPolicy** applied
to the compromised pod. On paper this blocks all traffic.

**The problem we found:** relying on one enforcement path is fragile. NetworkPolicy enforcement
depends on the CNI actually programming the rule, and same-node "hairpin" service traffic could slip
through paths the policy did not cover. A containment control that can be bypassed is not a
containment control.

**What we did instead:** we made containment defence-in-depth — **four independent locks applied in
parallel**, so no single failure leaves the xApp reachable:

1. Calico deny-all NetworkPolicy (CNI layer)
2. Kubernetes Service-selector isolation (empties the service endpoints)
3. A node-level **iptables DROP** in the `raw/PREROUTING` table, exec'd inside the privileged
   `calico-node` container — independent of the CNI, and chosen specifically because `raw/PREROUTING`
   runs before NAT/routing and catches the same-node hairpin traffic that `FORWARD` missed
4. SPIFFE/**SVID revocation**, so even a network escape cannot authenticate to any peer

Details and the exact code are in [`../containment/`](../containment/).

## 3. The dwell-to-isolation timing bug

Resource incidents use a deliberate **30-second dwell** between COMPROMISED and automatic isolation,
to give an operator a chance to intervene. For a while the measured dwell was wrong — sometimes the
xApp isolated almost immediately, sometimes after 30 s, with no obvious pattern.

We traced it to two things: the evaluation harness's attack function was blocking the poll loop, and
the `isolation_timing` tag ("DWELL_30S" vs "IMMEDIATE") was not always propagating to the isolation
manager, so a preserved-but-not-fresh COMPROMISED tick could bypass the dwell. Once both were fixed,
the dwell is exactly 30 s, confirmed in the isolation-manager logs. This is why the dwell logic lives
in its own small, single-purpose module ([`../containment/ztx_isolation_manager.py`](../containment/ztx_isolation_manager.py))
rather than inside the decision glue.

## 4. The Falco state race

Early on, attack escalations would occasionally "revert" on their own — an xApp would reach
COMPROMISED and then silently drop back. The cause was a state race where a later, lower-severity
signal could overwrite a higher-severity decision. The fix was sticky-state protection: once an xApp
is at or above COMPROMISED, a lower classification cannot downgrade it except through an explicit
restore.

## 5. Attack tooling: from Caldera to a scripted suite

We initially drove attacks with MITRE Caldera. It was useful for exploration, but for a repeatable
evaluation we needed attacks that were deterministic, versioned, and easy to launch during a live
demo. We replaced the Caldera flows with a plain, auditable script suite — one script per Falco rule
per xApp for the behavioural side, and a small set of `stress-ng`-based scenarios for the DoS side.
See [`../attacks/`](../attacks/).

## 6. Deployment discipline: the ConfigMap drift trap

The policy-engine's Python modules are mounted from a Kubernetes ConfigMap, not baked only into the
image. More than once, pushing a new `app.py` without syncing its sibling modules produced an import
mismatch and a crash-loop. The lesson — sync all modules together, and treat the ConfigMap as the
source of truth for the running code — shaped how we deploy changes.

---

None of these detours are failures to hide. They are the reason the final system is deterministic,
layered, and defensible — which, for a security control that acts on its own, matters more than
looking clever.
