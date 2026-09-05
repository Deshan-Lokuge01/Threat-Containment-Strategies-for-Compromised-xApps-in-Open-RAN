# Behavioural detection — Falco

Falco watches the Linux kernel and fires the instant an xApp does something its security profile
forbids. Because these are direct observations of forbidden actions (not statistical inference), they
are treated as immediate, high-confidence compromises and trigger containment right away.

## The rules

`ztx-xapp-rules.yaml` defines the ZT-XGuard rule set. Each rule maps to a MITRE technique and a
concrete forbidden action:

| Rule | Action | Example technique |
|------|--------|-------------------|
| ZTX-A1 | Unexpected shell spawned in the container (CRITICAL) | T1059 |
| ZTX-A2 | Sensitive file access | T1552 |
| ZTX-A3 | ServiceAccount token access | T1552.007 |
| ZTX-A6 | Malicious tool execution | — |
| ZTX-A7 | Unexpected peer contact | — |
| ZTX-A8 | External egress | T1048 |
| ZTX-A11 | SVID material access | T1552 |
| ZTX-A12 | xApp profile / config tamper | T1565 |
| ZTX-A13 | Package-manager execution | — |
| ZTX-A14 | Binary drop | — |
| ZTX-A15 | Permission tamper | — |
| ZTX-A16 | Kubernetes API contact | — |
| ZTX-A17 | Unexpected RIC service contact | — |
| ZTX-LM-03 | Privileged container-escape attempt | T1611 |

## Per-xApp profiles

Not every action is forbidden for every xApp — a telemetry xApp legitimately talks to different
services than a traffic-steering one. Each xApp has a declarative profile (see
[`../../xapps/security-profiles/`](../../xapps/security-profiles/)) that tells the rule set what is
normal for that workload, so the same rule can be strict on one xApp and permissive on another.

## Flow

```
xApp does a forbidden syscall ──► Falco matches a rule ──► webhook to the Policy Engine
        ──► state engine marks the xApp COMPROMISED ──► containment (four locks)
```

The attack scripts that exercise every rule are in
[`../../attacks/behavioural/`](../../attacks/behavioural/).

- `ztx-xapp-rules.yaml` — the rule set.
- `live-config/` — the deployed Falco configuration (if present).
