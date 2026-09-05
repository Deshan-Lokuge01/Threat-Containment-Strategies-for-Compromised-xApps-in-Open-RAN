# ZT-XGuard Demo Stable Snapshot

Date: 2026-06-15T07:53:00Z

Current deployed image:
```
localhost:5000/zt-xguard-policy-engine:eval-dedupe-fix-20260615T074202Z
```

Stable fixes included:
- Public trust-state vocabulary: NORMAL, OBSERVED, SUSPICIOUS, COMPROMISED
- Removed public QUARANTINED state
- COMPROMISED state is sticky until explicit restore
- COMPROMISED xApps trigger service-level containment
- Containment is verified using service isolation and endpoint count
- Restore resets xApp state to NORMAL and restores service selector
- Scenario target fix: A6/A7 use security-observer by default instead of always using telemetry-monitor
- Dashboard uses backend truth for state and containment display

Demo-ready behavior:
- A1: telemetry-monitor -> COMPROMISED, containment YES, endpoint_count 0
- A6/A7: security-observer -> SUSPICIOUS, containment NO
- Suspicious signal after COMPROMISED does not downgrade the xApp
