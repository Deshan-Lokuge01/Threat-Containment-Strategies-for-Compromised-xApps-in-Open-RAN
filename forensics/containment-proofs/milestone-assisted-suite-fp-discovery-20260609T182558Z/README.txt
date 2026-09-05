Milestone: Assisted suite false-positive discovery

Run:
20260609T181720Z

Result:
A5 expected OBSERVED/no containment but got QUARANTINED => FP
A4 expected SUSPICIOUS/no containment but got QUARANTINED => FP
A7 expected SUSPICIOUS/no containment but got QUARANTINED => FP
A8 expected QUARANTINED/containment and got QUARANTINED => TP

Interpretation:
ZT-XGuard containment works, but assisted/semi-real scenario path currently over-quarantines non-critical behavior.
Root cause must be inspected before final evaluation.
