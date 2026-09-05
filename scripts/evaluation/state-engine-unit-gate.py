#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENGINE_PATH = ROOT / "ztx-control-plane" / "policy-engine"
sys.path.insert(0, str(ENGINE_PATH))

from ztx_state_engine import evaluate_state, STATE_ENGINE_VERSION

def fail(msg, obj=None):
    print(f"[FAIL] {msg}")
    if obj is not None:
        print(json.dumps(obj, indent=2, sort_keys=True))
    sys.exit(1)

def ok(msg):
    print(f"[ OK ] {msg}")

def call_eval(name, xapp, signal, expected_state, expected_containment, profile=None, evidence=None, snapshot=None, previous_state="NORMAL", expected_rule=None, expected_reason=None, expected_isolation_timing=None):
    d = evaluate_state(
        xapp=xapp,
        signal=signal,
        profile=profile or {},
        evidence=evidence or {},
        snapshot=snapshot or {},
        previous_state=previous_state,
    )

    actual_state = d.get("detection_state") or d.get("decision_state") or d.get("state")
    actual_containment = bool(d.get("containment_required"))

    if actual_state != expected_state:
        fail(f"{name}: expected state={expected_state}, got {actual_state}", d)

    if actual_containment != expected_containment:
        fail(f"{name}: expected containment_required={expected_containment}, got {actual_containment}", d)

    for key in ["trust_score", "risk_score", "score", "score_type", "rule_ids", "reasons", "layers", "evidence_sources", "isolation_timing"]:
        if key not in d:
            fail(f"{name}: missing explainability/scoring key {key}", d)

    if expected_rule and expected_rule not in d.get("rule_ids", []):
        fail(f"{name}: expected rule_id {expected_rule}, got {d.get('rule_ids')}", d)

    if expected_reason and not any(expected_reason in reason for reason in d.get("reasons", [])):
        fail(f"{name}: expected reason containing {expected_reason!r}, got {d.get('reasons')}", d)

    if expected_isolation_timing and d.get("isolation_timing") != expected_isolation_timing:
        fail(f"{name}: expected isolation_timing={expected_isolation_timing}, got {d.get('isolation_timing')}", d)

    ok(f"{name}: state={actual_state}, containment={actual_containment}, isolation_timing={d.get('isolation_timing')}, trust={d.get('trust_score')}, risk={d.get('risk_score')}, rules={d.get('rule_ids')}")

print(f"ZT-XGuard state engine version: {STATE_ENGINE_VERSION}")

call_eval(
    "A5_legitimate_high_cpu",
    "traffic-analyzer",
    "high_cpu",
    "NORMAL",
    False,
    profile={"role": "traffic_analysis", "expected_high_workload": True},
    evidence={"valid_activity": True},
    snapshot={"activity": {"heartbeat_ok": True}, "metrics": {"cpu_usage_percent": 90}},
)

call_eval(
    "A4_bad_cpu_activity",
    "resource-optimizer",
    "high_cpu",
    "SUSPICIOUS",
    False,
    profile={"role": "resource_optimization", "expected_high_workload": False},
    evidence={"valid_activity": False, "stale_heartbeat": True},
    snapshot={"activity": {"heartbeat_ok": False}, "metrics": {"cpu_usage_percent": 95}},
)

call_eval(
    "metric_driven_high_cpu_invalid_activity",
    "resource-optimizer",
    "normal_heartbeat",
    "SUSPICIOUS",
    False,
    profile={"role": "resource_optimization", "expected_cpu_class": "medium", "expected_high_workload": False},
    evidence={"valid_activity": False},
    snapshot={"activity": {"heartbeat_ok": True}, "metrics": {"cpu_usage_percent": 92, "cpu_cores_2m": 0.92}},
)

call_eval(
    "metric_driven_high_cpu_valid_activity",
    "traffic-analyzer",
    "normal_heartbeat",
    "NORMAL",
    False,
    profile={"role": "traffic_analysis", "expected_cpu_class": "high", "expected_high_workload": True, "workload_intensity": "high"},
    evidence={"valid_activity": True},
    snapshot={"activity": {"heartbeat_ok": True, "work_units_processed": 4800}, "metrics": {"cpu_usage_percent": 90, "cpu_cores_2m": 0.90}},
)

call_eval(
    "normal_cpu_normal_heartbeat",
    "telemetry-monitor",
    "normal_heartbeat",
    "NORMAL",
    False,
    profile={"role": "telemetry_monitor", "expected_cpu_class": "low"},
    evidence={"valid_activity": True},
    snapshot={"activity": {"heartbeat_ok": True, "work_units_processed": 42}, "metrics": {"cpu_usage_percent": 12, "cpu_cores_2m": 0.12}},
)

call_eval(
    "A7_unexpected_peer_contact",
    "security-observer",
    "unexpected_peer_contact",
    "SUSPICIOUS",
    False,
    profile={"role": "security_observer", "allowed_peers": []},
    evidence={"peer": "qos-optimizer"},
    snapshot={"activity": {"heartbeat_ok": True}},
)

call_eval(
    "A8_external_egress",
    "security-observer",
    "external_egress",
    "COMPROMISED",
    True,
    profile={"role": "security_observer", "expected_external_egress": False},
    evidence={"destination": "8.8.8.8"},
    snapshot={"activity": {"heartbeat_ok": True}},
)

call_eval(
    "A1_unexpected_shell",
    "telemetry-monitor",
    "unexpected_shell",
    "COMPROMISED",
    True,
    profile={"role": "telemetry_monitor", "expected_shell": False},
    evidence={"source": "falco", "raw_event": {"rule": "Terminal shell in container"}},
    snapshot={"activity": {"heartbeat_ok": True}},
)

call_eval(
    "A2_sensitive_file_access",
    "telemetry-monitor",
    "sensitive_file_access",
    "COMPROMISED",
    True,
    profile={"role": "telemetry_monitor"},
    evidence={"source": "falco"},
)

call_eval(
    "A3_serviceaccount_token_access_immediate",
    "telemetry-monitor",
    "serviceaccount_token_access",
    "COMPROMISED",
    True,
    profile={"role": "telemetry_monitor"},
    evidence={"source": "falco"},
    expected_rule="ZTX-LM-01",
    expected_reason="serviceaccount_token_accessed",
    expected_isolation_timing="IMMEDIATE",
)

call_eval(
    "LM01_malicious_tool_execution_immediate",
    "resource-optimizer",
    "malicious_tool_execution",
    "COMPROMISED",
    True,
    profile={"role": "resource_optimization"},
    evidence={"source": "falco", "command": "peirates"},
    expected_rule="ZTX-LM-02",
    expected_reason="known_attack_tool",
    expected_isolation_timing="IMMEDIATE",
)

call_eval(
    "LM02_privileged_container_escape_attempt_immediate",
    "resource-optimizer",
    "privileged_container_escape_attempt",
    "COMPROMISED",
    True,
    profile={"role": "resource_optimization"},
    evidence={"source": "falco", "path": "/var/run/docker.sock"},
    expected_rule="ZTX-LM-03",
    expected_reason="attempted_container_escape",
    expected_isolation_timing="IMMEDIATE",
)

call_eval(
    "R1_resource_anomaly_correlated_escalates_same_dwell_rule_as_lateral_movement",
    "resource-optimizer",
    "high_cpu",
    "COMPROMISED",
    True,
    profile={"role": "resource_optimization", "expected_high_workload": False},
    evidence={"valid_activity": False, "stale_heartbeat": True, "unknown_process": True},
    snapshot={"activity": {"heartbeat_ok": False}, "metrics": {"cpu_usage_percent": 95}},
    expected_isolation_timing="DWELL_30S",
)

call_eval(
    "A1_unexpected_shell_still_immediate_no_dwell",
    "telemetry-monitor",
    "unexpected_shell",
    "COMPROMISED",
    True,
    profile={"role": "telemetry_monitor", "expected_shell": False},
    evidence={"source": "falco", "raw_event": {"rule": "Terminal shell in container"}},
    snapshot={"activity": {"heartbeat_ok": True}},
    expected_isolation_timing="IMMEDIATE",
)

call_eval(
    "A11_svid_material_access",
    "telemetry-monitor",
    "svid_material_access",
    "COMPROMISED",
    True,
    profile={"role": "telemetry_monitor"},
    evidence={"source": "falco", "path": "/etc/svid/tls.crt"},
    expected_rule="ZTX-A11",
    expected_reason="SVID/SPIRE identity material",
)

call_eval(
    "A12_xapp_profile_or_config_tamper",
    "telemetry-monitor",
    "xapp_profile_or_config_tamper",
    "COMPROMISED",
    True,
    profile={"role": "telemetry_monitor"},
    evidence={"source": "falco", "path": "/etc/xapp-profile/profile.json"},
    expected_rule="ZTX-A12",
    expected_reason="verified profile/config path",
)

call_eval(
    "A13_package_manager_execution",
    "resource-optimizer",
    "package_manager_execution",
    "SUSPICIOUS",
    False,
    profile={"role": "resource_optimization"},
    evidence={"source": "falco", "command": "apt-get update"},
    expected_rule="ZTX-A13",
    expected_reason="package manager executed inside controlled xApp",
)

call_eval(
    "A14_binary_drop",
    "resource-optimizer",
    "binary_drop",
    "SUSPICIOUS",
    False,
    profile={"role": "resource_optimization"},
    evidence={"source": "falco", "path": "/tmp/loader.sh"},
    expected_rule="ZTX-A14",
    expected_reason="executable-looking artifact written to writable path",
)

call_eval(
    "A15_permission_tamper",
    "resource-optimizer",
    "permission_tamper",
    "SUSPICIOUS",
    False,
    profile={"role": "resource_optimization"},
    evidence={"source": "falco", "command": "chmod 777 /tmp/loader.sh"},
    expected_rule="ZTX-A15",
    expected_reason="chmod/chown/setcap executed inside controlled xApp",
)

call_eval(
    "A16_k8s_api_contact",
    "security-observer",
    "k8s_api_contact",
    "SUSPICIOUS",
    False,
    profile={"role": "security_observer"},
    evidence={"source": "falco", "destination": "kubernetes.default.svc:443"},
    expected_rule="ZTX-A16",
    expected_reason="controlled xApp contacted Kubernetes API",
)

call_eval(
    "identity_svid_invalid",
    "qos-optimizer",
    "svid_invalid",
    "COMPROMISED",
    True,
    profile={"role": "qos_optimizer"},
    evidence={"running": True, "svid_invalid": True},
    snapshot={"identity": {"svid_certificate_present": False, "svid_key_present": False}},
)

call_eval(
    "profile_hash_mismatch",
    "telemetry-monitor",
    "profile_hash_mismatch",
    "COMPROMISED",
    True,
    profile={"role": "telemetry_monitor"},
    evidence={"profile_drift": True},
    snapshot={"integrity": {"profile_hash_match": False}},
)

print()
print("STATE_ENGINE_UNIT_GATE_PASS")
