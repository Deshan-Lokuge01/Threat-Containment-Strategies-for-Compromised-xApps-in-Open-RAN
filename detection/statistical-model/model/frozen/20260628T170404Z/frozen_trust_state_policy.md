# Frozen Trust-State Policy

Public states are exactly: NORMAL, SUSPICIOUS, COMPROMISED.

NORMAL:
Resource behavior is below the frozen warning threshold for the selected MEWMA/T2 detector.

SUSPICIOUS:
Resource behavior crosses the frozen warning threshold or satisfies the frozen upper-threshold persistence rule.
This is a resource-behavior alert, not proof of compromise.

COMPROMISED:
The xApp is marked COMPROMISED only when SUSPICIOUS resource evidence is corroborated by labelled attack ground truth, CALDERA/stress-ng operation evidence, operator review, or another preserved security artifact.
The resource detector alone must not assign COMPROMISED in live operation.

Frozen selected rule:
- warning: T2 >= warning_limit
- upper evidence: T2 >= upper_limit
- sustained upper evidence: at least 8 upper-threshold states within the last 10 scored states
