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

RUN_ID = datetime.now(timezone.utc).strftime("detection-logic-audit-%Y%m%dT%H%M%SZ")
OUT = ROOT / "evidence" / "framework-implementation" / "phase1-detection-logic" / RUN_ID
OUT.mkdir(parents=True, exist_ok=True)

CASES = [
    {
        "case_id": "A5_benign_high_cpu_valid_activity",
        "xapp": "traffic-analyzer",
        "signal": "high_cpu",
        "profile": {"role": "traffic_analysis", "expected_high_workload": True},
        "evidence": {"valid_activity": True},
        "snapshot": {
            "activity": {"heartbeat_ok": True, "work_units_processed": 5000},
            "metrics": {"cpu_usage_percent": 92},
        },
        "previous_state": "TRUSTED",
        "expected_state": "OBSERVED",
        "expected_containment": False,
        "purpose": "High CPU is legitimate for traffic-analyzer when activity is valid.",
    },
    {
        "case_id": "A4_cpu_bad_activity",
        "xapp": "resource-optimizer",
        "signal": "high_cpu",
        "profile": {"role": "resource_optimization", "expected_high_workload": False},
        "evidence": {"valid_activity": False, "stale_heartbeat": True},
        "snapshot": {
            "activity": {"heartbeat_ok": False, "work_units_processed": 0},
            "metrics": {"cpu_usage_percent": 95},
        },
        "previous_state": "TRUSTED",
        "expected_state": "SUSPICIOUS",
        "expected_containment": False,
        "purpose": "Bad CPU/activity correlation should be suspicious but not immediately quarantined.",
    },
    {
        "case_id": "A7_unexpected_peer_contact",
        "xapp": "security-observer",
        "signal": "unexpected_peer_contact",
        "profile": {"role": "security_observer", "allowed_peers": []},
        "evidence": {"peer": "qos-optimizer"},
        "snapshot": {"activity": {"heartbeat_ok": True}},
        "previous_state": "TRUSTED",
        "expected_state": "SUSPICIOUS",
        "expected_containment": False,
        "purpose": "Unexpected peer contact is suspicious, not automatically compromised.",
    },
    {
        "case_id": "B_allowed_peer_contact",
        "xapp": "security-observer",
        "signal": "unexpected_peer_contact",
        "profile": {"role": "security_observer", "allowed_peers": ["qos-optimizer"]},
        "evidence": {"peer": "qos-optimizer"},
        "snapshot": {"activity": {"heartbeat_ok": True}},
        "previous_state": "TRUSTED",
        "expected_state": "OBSERVED",
        "expected_containment": False,
        "purpose": "Allowed peer communication must not false-positive.",
    },
    {
        "case_id": "A8_external_egress_forbidden",
        "xapp": "security-observer",
        "signal": "external_egress",
        "profile": {"role": "security_observer", "expected_external_egress": False},
        "evidence": {"destination": "8.8.8.8"},
        "snapshot": {"activity": {"heartbeat_ok": True}},
        "previous_state": "TRUSTED",
        "expected_state": "COMPROMISED",
        "expected_containment": True,
        "purpose": "Forbidden external egress is deterministic compromise.",
    },
    {
        "case_id": "B_external_egress_allowed",
        "xapp": "egress-test-xapp",
        "signal": "external_egress",
        "profile": {"role": "allowed_egress_test", "expected_external_egress": True},
        "evidence": {"destination": "allowed.example"},
        "snapshot": {"activity": {"heartbeat_ok": True}},
        "previous_state": "TRUSTED",
        "expected_state": "OBSERVED",
        "expected_containment": False,
        "purpose": "Allowed external egress must not false-positive.",
    },
    {
        "case_id": "A1_unexpected_shell",
        "xapp": "telemetry-monitor",
        "signal": "unexpected_shell",
        "profile": {"role": "telemetry_monitor", "expected_shell": False},
        "evidence": {"source": "falco", "raw_event": {"rule": "Terminal shell in xApp container"}},
        "snapshot": {"activity": {"heartbeat_ok": True}},
        "previous_state": "TRUSTED",
        "expected_state": "COMPROMISED",
        "expected_containment": True,
        "purpose": "Shell in xApp is deterministic compromise.",
    },
    {
        "case_id": "A2_sensitive_file_access",
        "xapp": "telemetry-monitor",
        "signal": "sensitive_file_access",
        "profile": {"role": "telemetry_monitor"},
        "evidence": {"source": "falco", "path": "/etc/shadow"},
        "snapshot": {},
        "previous_state": "TRUSTED",
        "expected_state": "COMPROMISED",
        "expected_containment": True,
        "purpose": "Sensitive file access is deterministic compromise.",
    },
    {
        "case_id": "A3_serviceaccount_token_access",
        "xapp": "telemetry-monitor",
        "signal": "serviceaccount_token_access",
        "profile": {"role": "telemetry_monitor"},
        "evidence": {"source": "falco", "path": "/var/run/secrets/kubernetes.io/serviceaccount/token"},
        "snapshot": {},
        "previous_state": "TRUSTED",
        "expected_state": "COMPROMISED",
        "expected_containment": True,
        "purpose": "ServiceAccount token access is deterministic compromise.",
    },
    {
        "case_id": "SVID_invalid_running_xapp",
        "xapp": "qos-optimizer",
        "signal": "svid_invalid",
        "profile": {"role": "qos_optimizer"},
        "evidence": {"running": True, "svid_invalid": True},
        "snapshot": {"identity": {"svid_certificate_present": False, "svid_key_present": False}},
        "previous_state": "TRUSTED",
        "expected_state": "COMPROMISED",
        "expected_containment": True,
        "purpose": "Running xApp with invalid SVID should become compromised.",
    },
    {
        "case_id": "profile_hash_mismatch",
        "xapp": "telemetry-monitor",
        "signal": "profile_hash_mismatch",
        "profile": {"role": "telemetry_monitor"},
        "evidence": {"profile_drift": True},
        "snapshot": {"integrity": {"profile_hash_match": False}},
        "previous_state": "TRUSTED",
        "expected_state": "COMPROMISED",
        "expected_containment": True,
        "purpose": "Profile integrity drift should trigger compromise.",
    },
]

rows = []
failures = []

print("ZT-XGuard Phase 1 Detection Logic Audit")
print(f"state_engine_version={STATE_ENGINE_VERSION}")
print(f"OUT={OUT}")
print()

for c in CASES:
    d = evaluate_state(
        xapp=c["xapp"],
        signal=c["signal"],
        profile=c["profile"],
        evidence=c["evidence"],
        snapshot=c["snapshot"],
        previous_state=c["previous_state"],
    )

    actual_state = d.get("detection_state") or d.get("decision_state") or d.get("state")
    actual_containment = bool(d.get("containment_required"))

    state_pass = actual_state == c["expected_state"]
    containment_pass = actual_containment == c["expected_containment"]
    passed = state_pass and containment_pass

    row = {
        "case_id": c["case_id"],
        "xapp": c["xapp"],
        "signal": c["signal"],
        "previous_state": c["previous_state"],
        "expected_state": c["expected_state"],
        "actual_state": actual_state,
        "expected_containment": c["expected_containment"],
        "actual_containment": actual_containment,
        "trust_score": d.get("trust_score"),
        "risk_score": d.get("risk_score"),
        "score": d.get("score"),
        "score_type": d.get("score_type"),
        "rule_ids": ";".join(map(str, d.get("rule_ids", []))),
        "reasons": ";".join(map(str, d.get("reasons", []))),
        "purpose": c["purpose"],
        "pass": passed,
    }
    rows.append(row)

    status = "OK" if passed else "FAIL"
    print(
        f"[{status:4}] {c['case_id']}: "
        f"expected={c['expected_state']}/{c['expected_containment']} "
        f"actual={actual_state}/{actual_containment} "
        f"trust={d.get('trust_score')} risk={d.get('risk_score')} "
        f"rules={d.get('rule_ids')}"
    )

    with open(OUT / f"{c['case_id']}.decision.json", "w") as f:
        json.dump(d, f, indent=2, sort_keys=True)

    if not passed:
        failures.append(row)

csv_path = OUT / "detection-logic-audit.csv"
with open(csv_path, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)

summary = {
    "run_id": RUN_ID,
    "state_engine_version": STATE_ENGINE_VERSION,
    "cases": len(rows),
    "passed": sum(1 for r in rows if r["pass"]),
    "failed": len(failures),
    "csv": str(csv_path),
    "failures": failures,
}

with open(OUT / "summary.json", "w") as f:
    json.dump(summary, f, indent=2, sort_keys=True)

with open(OUT / "PHASE1_VERDICT.txt", "w") as f:
    f.write("PHASE1_DETECTION_LOGIC_AUDIT_PASS\n" if not failures else "PHASE1_DETECTION_LOGIC_AUDIT_FAIL\n")

print()
print(json.dumps(summary, indent=2, sort_keys=True))

if failures:
    print()
    print("PHASE1_DETECTION_LOGIC_AUDIT_FAIL")
    sys.exit(1)

print()
print("PHASE1_DETECTION_LOGIC_AUDIT_PASS")
