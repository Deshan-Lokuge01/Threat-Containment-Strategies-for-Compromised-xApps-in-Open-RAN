# Policy engine (control plane)

The brain of ZT-XGuard. A Flask service that ingests detection signals, runs the trust state machine,
decides when an xApp is compromised, drives the four-lock containment, and serves the live SOC
dashboard.

## Key modules

| File | Role |
|------|------|
| `app.py` | HTTP service, signal ingestion, decision glue, restore, dwell-checker wiring |
| `ztx_state_engine.py` | the trust state machine — maps signals to NORMAL / SUSPICIOUS / COMPROMISED / ISOLATED with confidence and isolation timing |
| `containment_orchestrator.py` | `apply_quarantine()` and the four containment mechanisms (see [`../containment/`](../containment/)) |
| `ztx_isolation_manager.py` | COMPROMISED→ISOLATED transition and the 30-second dwell |
| `ztx_t2_collector.py` | the T² statistical resource/DoS detector (see [`../detection/statistical-model/`](../detection/statistical-model/)) |
| `ztx_dashboard_api.py` | dashboard API: state, metrics, timing, incidents, isolation verification |
| `static/`, `templates/` | the live Zero-Trust SOC dashboard UI |

## The trust state machine

```
NORMAL ──(suspicious signal)──► SUSPICIOUS ──(confirmed)──► COMPROMISED ──(immediate | 30s dwell)──► ISOLATED
   ▲                                                                                                     │
   └─────────────────────────────────  operator restore  ◄──────────────────────────────────────────────┘
```

Behavioural (Falco) compromises isolate immediately. Resource (T²/DoS) compromises isolate after the
30-second dwell. State is sticky — a lower-severity signal cannot downgrade a compromised xApp except
through an explicit restore.

## Dashboard

The dashboard renders the live RIC topology, per-xApp state, the dual detection channels, the four
containment mechanism latencies, identity (SPIFFE/SVID) health, the incident timeline, a threat feed,
and an Investigation Center backed by a forensic evidence vault. Screenshots are in
[`../images/dashboard/`](../images/dashboard/).

## Deployment note

The Python modules run from a Kubernetes ConfigMap (mounted via `subPath`), not only from the image.
When changing backend modules, sync all of them together — a mismatched `app.py` and sibling module
will crash-loop on import. See [`../docs/research-journey.md`](../docs/research-journey.md) §6.
