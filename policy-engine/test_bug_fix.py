import sys
import json
import requests

# Test A13 (Suspicious only)
payload_a13 = {
    "rule": "ZTX xApp Package Manager Execution",
    "priority": "Warning",
    "output": "14:42:01.000000000: Warning ztx_signal=package_manager_execution rule_id=ZTX-A13 package manager executed",
    "source": "syscall",
    "output_fields": {
        "k8s.pod.name": "resource-optimizer-5d5b74686-abcde",
        "k8s.ns.name": "ricxapp",
        "container.name": "resource-optimizer",
        "proc.cmdline": "apt-get update"
    }
}

# Test A11 (Quarantine capable)
payload_a11 = {
    "rule": "ZTX xApp SVID Material Access",
    "priority": "Critical",
    "output": "14:42:01.000000000: Critical ztx_signal=svid_material_access rule_id=ZTX-A11 svid accessed",
    "source": "syscall",
    "output_fields": {
        "k8s.pod.name": "telemetry-monitor-7b875df699-xyz",
        "k8s.ns.name": "ricxapp",
        "container.name": "telemetry-monitor",
        "proc.cmdline": "cat /etc/svid/tls.crt"
    }
}

try:
    # 30s, not 5s: A11 triggers a COMPROMISED decision, whose containment-attempt
    # code retries against a known, deliberately-unfixed RBAC gap before
    # returning - the same pre-existing slow path already documented for
    # ztx_t2_collector.py's report_suspicious(), unrelated to this session's
    # T2 4-state mapping change.
    r_a13 = requests.post("http://localhost:5000/falco-webhook", json=payload_a13, timeout=30)
    r_a11 = requests.post("http://localhost:5000/falco-webhook", json=payload_a11, timeout=30)
    
    print("A13 Response:", json.dumps(r_a13.json(), indent=2))
    print("A11 Response:", json.dumps(r_a11.json(), indent=2))

    a13_json = r_a13.json()
    assert a13_json.get("state") == "SUSPICIOUS", f"A13 state was {a13_json.get('state')}"
    assert a13_json.get("quarantine", {}).get("applied") == False, "A13 applied quarantine"

    a11_json = r_a11.json()
    # 2026-07-16: was "QUARANTINED" - that pre-4-state-model label never
    # actually gets set anywhere live (confirmed way back in Step A). The
    # real, correct terminology is ISOLATED (the new 5th tier, added
    # today) - a CRITICAL/IMMEDIATE-timing signal like this one now
    # correctly transitions straight to it. The quarantine.applied
    # assertion below is deliberately left expecting True and will keep
    # failing until the RBAC gap is granted - that's intentional, a
    # canary for when containment starts actually taking effect.
    assert a11_json.get("state") == "ISOLATED", f"A11 state was {a11_json.get('state')}"
    assert a11_json.get("quarantine", {}).get("applied") == True, "A11 failed to apply quarantine"
    
    print("\nSUCCESS: Both paths verified!")
except Exception as e:
    print(f"Error: {e}")
