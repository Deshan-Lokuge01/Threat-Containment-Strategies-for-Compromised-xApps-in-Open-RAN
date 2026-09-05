#!/usr/bin/env python3
"""Falco rule-coverage verification for telemetry-monitor.

Posts one payload per rule directly to /falco-webhook, matching the exact
output/output_fields shape Falco itself produces (confirmed against
ztx-xapp-rules.yaml and a real captured ZTX-A17 alert this session) -
same technique test_bug_fix.py already uses successfully for A11/A13,
extended to all 14 attack rules. Bypasses the live Falco->Falcosidekick
pipeline deliberately for this check: that pipeline is already separately
confirmed working (continuous /falco-webhook traffic observed after the
WEBHOOK_ADDRESS fix), and posting directly here avoids racing against the
~3-5 req/s ambient background traffic from all 9 xApps that made
/csm/state polling unreliable.
"""
import json
import requests

POLICY_URL = "http://10.102.102.184:5000"
POD = "telemetry-monitor-5b644946f6-rl6xq"
NS = "ricxapp"
CONTAINER = "telemetry-monitor"

def falco_event(rule, rule_id, signal, priority, extra_output="", output_fields=None):
    fields = {
        "k8s.pod.name": POD,
        "k8s.ns.name": NS,
        "container.name": CONTAINER,
    }
    if output_fields:
        fields.update(output_fields)
    return {
        "rule": rule,
        "priority": priority,
        "output": f"2026-07-16T00:00:00.000000000+0000: {priority.title()} ztx_signal={signal} rule_id={rule_id} {extra_output}",
        "source": "syscall",
        "output_fields": fields,
    }

CASES = [
    ("ZTX-A1", falco_event("ZTX xApp Unexpected Shell", "ZTX-A1", "unexpected_shell", "Critical",
                            output_fields={"proc.cmdline": "sh -c true"})),
    ("ZTX-A2", falco_event("ZTX xApp Sensitive File Access", "ZTX-A2", "sensitive_file_access", "Critical",
                            output_fields={"fd.name": "/etc/passwd", "proc.cmdline": "cat /etc/passwd"})),
    ("ZTX-A3", falco_event("ZTX xApp ServiceAccount Token Access", "ZTX-A3", "serviceaccount_token_access", "Critical",
                            output_fields={"fd.name": "/var/run/secrets/kubernetes.io/serviceaccount/token"})),
    ("ZTX-A6", falco_event("ZTX xApp Suspicious Tool Execution", "ZTX-A6", "malicious_tool_execution", "Warning",
                            output_fields={"proc.cmdline": "python3 --version"})),
    ("ZTX-A7", falco_event("ZTX xApp Unexpected Peer xApp Contact", "ZTX-A7", "unexpected_peer_contact", "Warning",
                            output_fields={"fd.sip.name": "traffic-analyzer.ricxapp.svc.cluster.local", "fd.sport": 8080})),
    ("ZTX-A8", falco_event("ZTX xApp External Egress Attempt", "ZTX-A8", "external_egress", "Critical",
                            output_fields={"fd.sip.name": "8.8.8.8", "fd.sport": 80})),
    ("ZTX-A11", falco_event("ZTX xApp SVID Or SPIFFE Material Access", "ZTX-A11", "svid_material_access", "Critical",
                             output_fields={"fd.name": "/etc/svid/svid.0.pem"})),
    ("ZTX-A12", falco_event("ZTX xApp Profile Or Config Tamper", "ZTX-A12", "xapp_profile_or_config_tamper", "Critical",
                             output_fields={"fd.name": "/etc/xapp-profile/profile.json", "proc.cmdline": "chmod 644 /etc/xapp-profile/profile.json"})),
    ("ZTX-A13", falco_event("ZTX xApp Package Manager Execution", "ZTX-A13", "package_manager_execution", "Warning",
                             output_fields={"proc.cmdline": "pip3 --version"})),
    ("ZTX-A14", falco_event("ZTX xApp Binary Drop In Writable Path", "ZTX-A14", "binary_drop", "Warning",
                             output_fields={"fd.name": "/tmp/ztx_demo_drop.sh"})),
    ("ZTX-A15", falco_event("ZTX xApp Permission Tamper", "ZTX-A15", "permission_tamper", "Warning",
                             output_fields={"proc.cmdline": "chmod 644 /tmp/ztx_demo_perm_test"})),
    ("ZTX-A16", falco_event("ZTX xApp Kubernetes API Contact", "ZTX-A16", "k8s_api_contact", "Warning",
                             output_fields={"fd.sip.name": "kubernetes.default.svc.cluster.local", "fd.sport": 443})),
    ("ZTX-A17", falco_event("ZTX xApp Unexpected RIC Service Contact", "ZTX-A17", "unexpected_ric_probe", "Warning",
                             output_fields={"fd.sip.name": "service-ricplt-appmgr-http.ricplt.svc.cluster.local", "fd.sport": 8080})),
    ("ZTX-LM-03", falco_event("ZTX xApp Privileged Container Escape Attempt", "ZTX-LM-03", "privileged_container_escape_attempt", "Critical",
                               output_fields={"fd.name": "/var/run/docker.sock"})),
]

print(f"{'RULE':<10} {'HTTP':<5} {'fresh_state':<12} {'sticky_state':<13} {'signal':<32} reasons")
print("-" * 110)
for name, payload in CASES:
    try:
        r = requests.post(f"{POLICY_URL}/falco-webhook", json=payload, timeout=15)
        body = r.json()
        # csm_update_from_result() in app.py implements a deliberate "sticky
        # compromised" rule (a lower-severity signal can never downgrade an
        # already-COMPROMISED xApp's cached state without an explicit
        # /csm/containment/restore) - the top-level "state" field reflects
        # that sticky cache, not this specific call's own fresh decision.
        # decision.decision_state is the real, un-ratcheted output of
        # evaluate_state() for THIS payload - that's what we want here.
        decision = body.get("decision") or {}
        fresh_state = decision.get("decision_state") or body.get("raw_state") or "?"
        sticky_state = body.get("state") or "?"
        signal = body.get("normalized_signal") or body.get("signal") or "?"
        reasons = decision.get("reasons") or body.get("reasons") or []
        print(f"{name:<10} {r.status_code:<5} {fresh_state:<12} {sticky_state:<13} {signal:<32} {reasons}")
    except Exception as exc:
        print(f"{name:<10} ERROR: {exc!r}")
