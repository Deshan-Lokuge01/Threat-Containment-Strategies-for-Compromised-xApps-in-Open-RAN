# Architecture

ZT-XGuard sits on top of the Near-RT RIC and turns "an xApp misbehaved" into "the xApp is contained"
without a human in the loop.

```
        RAN                         Near-RT RIC (Kubernetes)                 ZT-XGuard control plane
 ┌───────────────┐          ┌────────────────────────────────┐        ┌──────────────────────────────┐
 │ OAI 5G core   │          │ ricplt: e2term, e2mgr, submgr, │        │  Policy Engine (Flask)       │
 │ gNB (CU/DU)   │──E2────► │ rtmgr, appmgr, a1med, dbaas... │        │   • trust state machine      │
 │ UE (ZMQ)      │          │ ricxapp: kpimon-go, traffic,   │◄──────►│   • decisions                │
 └───────────────┘          │          hw-go, hw-python      │        │   • containment orchestrator │
                            └───────────────┬────────────────┘        │   • SOC dashboard            │
                                            │                          └───────────────┬──────────────┘
                    ┌───────────────────────┼───────────────────────┐                  │
                    ▼                       ▼                        ▼                  │
              Falco (kernel)        T² collector (stats)       SPIRE / SPIFFE          │
              behavioural           resource / DoS             workload identity ◄──────┘
                    │                       │                        │
                    └───────── signals ─────┴───────── issue/revoke SVID ────────►
```

## Detection → decision → containment

1. **Detect.** Two independent channels feed the policy engine: Falco (behavioural, kernel-level) and
   the T² collector (statistical, resource/DoS).
2. **Decide.** The trust state machine classifies each xApp: NORMAL → SUSPICIOUS → COMPROMISED →
   ISOLATED, with a confidence and an isolation timing (immediate for Falco, 30-second dwell for T²).
3. **Contain.** On COMPROMISED, the containment orchestrator applies four locks in parallel and
   revokes the workload's SVID.
4. **Verify.** Isolation is confirmed empirically (node iptables read-back + live probes).
5. **Record.** Every incident is sealed in the forensic evidence vault.

## Trust states

| State | Meaning |
|-------|---------|
| NORMAL | behaving within its profile |
| SUSPICIOUS | one anomalous signal; watched, not contained |
| COMPROMISED | confirmed malicious; containment required (immediate, or after the dwell) |
| ISOLATED | contained by the four locks; identity revoked |

## Where things live

- Control plane and dashboard: [`../policy-engine/`](../policy-engine/)
- Detection: [`../detection/`](../detection/)
- Containment: [`../containment/`](../containment/)
- Identity: [`../identity/`](../identity/)
- Deployment manifests: [`../deploy/`](../deploy/)
