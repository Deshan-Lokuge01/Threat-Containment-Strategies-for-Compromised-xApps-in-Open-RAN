#!/usr/bin/env python3
import csv
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
ENGINE_PATH = ROOT / "ztx-control-plane" / "policy-engine"
sys.path.insert(0, str(ENGINE_PATH))

from ztx_state_engine import evaluate_state, STATE_ENGINE_VERSION

RUN_ID = datetime.now(timezone.utc).strftime("state-transition-audit-%Y%m%dT%H%M%SZ")
OUT = ROOT / "evidence" / "framework-implementation" / "phase2-state-transitions" / RUN_ID
OUT.mkdir(parents=True, exist_ok=True)

STEPS = [
    {
        "step": 1,
        "case_id": "T1_clean_baseline_to_trusted",
        "xapp": "traffic-analyzer",
        "signal": "clean_baseline",
        "previous_state": "UNKNOWN",
        "profile": {"role": "traffic_analysis", "expected_high_workload": True},
        "evidence": {},
        "snapshot": {"activity": {"heartbeat_ok": True}},
        "expected_state": "TRUSTED",
        "expected_containment": False,
        "purpose": "A clean baseline should initialize the xApp as trusted.",
    },
    {
        "step": 2,
        "case_id": "T2_trusted_to_observed_valid_high_cpu",
        "xapp": "traffic-analyzer",
        "signal": "high_cpu",
        "previous_state": "TRUSTED",
        "profile": {"role": "traffic_analysis", "expected_high_workload": True},
        "evidence": {"valid_activity": True},
        "snapshot": {
            "activity": {"heartbeat_ok": True, "work_units_processed": 8000},
            "metrics": {"cpu_usage_percent": 91},
        },
        "expected_state": "OBSERVED",
        "expected_containment": False,
        "purpose": "Profile-consistent high CPU should move TRUSTED to OBSERVED, not quarantine.",
    },
    {
        "step": 3,
        "case_id": "T3_observed_to_suspicious_peer_drift",
        "xapp": "traffic-analyzer",
        "signal": "unexpected_peer_contact",
        "previous_state": "OBSERVED",
        "profile": {"role": "traffic_analysis", "allowed_peers": []},
        "evidence": {"peer": "qos-optimizer"},
        "snapshot": {"activity": {"heartbeat_ok": True}},
        "expected_state": "SUSPICIOUS",
        "expected_containment": False,
        "purpose": "Unexpected peer contact should escalate OBSERVED to SUSPICIOUS.",
    },
    {
        "step": 4,
        "case_id": "T4_suspicious_to_compromised_by_correlation",
        "xapp": "traffic-analyzer",
        "signal": "high_cpu",
        "previous_state": "SUSPICIOUS",
        "profile": {"role": "traffic_analysis", "expected_high_workload": False},
        "evidence": {
            "valid_activity": False,
            "stale_heartbeat": True,
            "unknown_process": True,
            "correlated_signals": ["unexpected_peer_contact"],
        },
        "snapshot": {
            "activity": {"heartbeat_ok": False, "work_units_processed": 0},
            "metrics": {"cpu_usage_percent": 97},
        },
        "expected_state": "COMPROMISED",
        "expected_containment": True,
        "purpose": "Multiple suspicious indicators within the correlation window should escalate to COMPROMISED.",
    },
    {
        "step": 5,
        "case_id": "T5_any_state_to_compromised_by_critical_signal",
        "xapp": "telemetry-monitor",
        "signal": "unexpected_shell",
        "previous_state": "OBSERVED",
        "profile": {"role": "telemetry_monitor", "expected_shell": False},
        "evidence": {"source": "falco", "raw_event": {"rule": "Terminal shell in container"}},
        "snapshot": {"activity": {"heartbeat_ok": True}},
        "expected_state": "COMPROMISED",
        "expected_containment": True,
        "purpose": "Critical deterministic evidence should override previous state.",
    },
    {
        "step": 6,
        "case_id": "T6_out_of_scope_event_ignored",
        "xapp": "kube-system-pod",
        "signal": "out_of_scope",
        "previous_state": "UNKNOWN",
        "profile": {},
        "evidence": {"namespace": "kube-system"},
        "snapshot": {},
        "expected_state": "IGNORED",
        "expected_containment": False,
        "purpose": "Out-of-scope non-xApp events should be ignored.",
    },
    {
        "step": 7,
        "case_id": "T7_identity_issue_before_runtime_is_suspicious",
        "xapp": "qos-optimizer",
        "signal": "svid_missing",
        "previous_state": "UNKNOWN",
        "profile": {"role": "qos_optimizer"},
        "evidence": {"running": False},
        "snapshot": {"identity": {"svid_certificate_present": False, "svid_key_present": False}},
        "expected_state": "SUSPICIOUS",
        "expected_containment": False,
        "purpose": "Identity issue before runtime should be suspicious, not immediate runtime containment.",
    },
    {
        "step": 8,
        "case_id": "T8_identity_issue_while_running_is_compromised",
        "xapp": "qos-optimizer",
        "signal": "svid_invalid",
        "previous_state": "TRUSTED",
        "profile": {"role": "qos_optimizer"},
        "evidence": {"running": True, "svid_invalid": True},
        "snapshot": {"identity": {"svid_certificate_present": False, "svid_key_present": False}},
        "expected_state": "COMPROMISED",
        "expected_containment": True,
        "purpose": "Invalid SVID on a running xApp should trigger compromised state and containment.",
    },
]

rows = []
failures = []

print("ZT-XGuard Phase 2A State Transition Audit")
print(f"state_engine_version={STATE_ENGINE_VERSION}")
print(f"OUT={OUT}")
print()

for s in STEPS:
    d = evaluate_state(
        xapp=s["xapp"],
        signal=s["signal"],
        profile=s["profile"],
        evidence=s["evidence"],
        snapshot=s["snapshot"],
        previous_state=s["previous_state"],
    )

    actual_state = d.get("detection_state") or d.get("decision_state") or d.get("state")
    actual_containment = bool(d.get("containment_required"))
    transition = d.get("transition", {})

    state_pass = actual_state == s["expected_state"]
    containment_pass = actual_containment == s["expected_containment"]
    transition_from_pass = transition.get("from") == s["previous_state"]
    transition_to_pass = transition.get("to") == actual_state

    passed = state_pass and containment_pass and transition_from_pass and transition_to_pass

    row = {
        "step": s["step"],
        "case_id": s["case_id"],
        "xapp": s["xapp"],
        "signal": s["signal"],
        "expected_from": s["previous_state"],
        "actual_from": transition.get("from"),
        "expected_to": s["expected_state"],
        "actual_to": transition.get("to"),
        "actual_state": actual_state,
        "expected_containment": s["expected_containment"],
        "actual_containment": actual_containment,
        "trust_score": d.get("trust_score"),
        "risk_score": d.get("risk_score"),
        "score": d.get("score"),
        "score_type": d.get("score_type"),
        "rule_ids": ";".join(map(str, d.get("rule_ids", []))),
        "reasons": ";".join(map(str, d.get("reasons", []))),
        "purpose": s["purpose"],
        "pass": passed,
    }

    rows.append(row)

    status = "OK" if passed else "FAIL"
    print(
        f"[{status:4}] {s['case_id']}: "
        f"{transition.get('from')} -> {transition.get('to')} "
        f"containment={actual_containment} "
        f"trust={d.get('trust_score')} risk={d.get('risk_score')} "
        f"rules={d.get('rule_ids')}"
    )

    with open(OUT / f"{s['step']:02d}-{s['case_id']}.decision.json", "w") as f:
        json.dump(d, f, indent=2, sort_keys=True)

    if not passed:
        failures.append(row)

csv_path = OUT / "state-transition-audit.csv"
with open(csv_path, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)

summary = {
    "run_id": RUN_ID,
    "state_engine_version": STATE_ENGINE_VERSION,
    "steps": len(rows),
    "passed": sum(1 for r in rows if r["pass"]),
    "failed": len(failures),
    "csv": str(csv_path),
    "failures": failures,
    "note": "This is a pure state-engine audit. QUARANTINED and RESTORED are verified in Phase 2B using live policy-engine and Kubernetes containment APIs.",
}

with open(OUT / "summary.json", "w") as f:
    json.dump(summary, f, indent=2, sort_keys=True)

with open(OUT / "PHASE2A_VERDICT.txt", "w") as f:
    f.write("PHASE2A_STATE_TRANSITION_AUDIT_PASS\n" if not failures else "PHASE2A_STATE_TRANSITION_AUDIT_FAIL\n")

print()
print(json.dumps(summary, indent=2, sort_keys=True))

if failures:
    print()
    print("PHASE2A_STATE_TRANSITION_AUDIT_FAIL")
    sys.exit(1)

print()
print("PHASE2A_STATE_TRANSITION_AUDIT_PASS")
