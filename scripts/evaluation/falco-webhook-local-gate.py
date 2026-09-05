#!/usr/bin/env python3
import importlib.util
import os
import sys
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
APP_PATH = ROOT / "ztx-control-plane" / "policy-engine" / "app.py"


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def ok(msg: str) -> None:
    print(f"[ OK ] {msg}")


class DummyFlaskApp:
    def __init__(self, name: str):
        self.name = name
        self.response_class = lambda body, mimetype=None: body

    def route(self, *args, **kwargs):
        def decorator(fn):
            return fn
        return decorator


class DummyApi:
    def __init__(self, *args, **kwargs):
        pass


class DummyClientModule:
    class ApiException(Exception):
        def __init__(self, status=None, *args, **kwargs):
            super().__init__(*args)
            self.status = status

    CoreV1Api = DummyApi
    AppsV1Api = DummyApi
    NetworkingV1Api = DummyApi
    DiscoveryV1Api = DummyApi

    def __getattr__(self, name):
        class _Dummy:
            def __init__(self, *args, **kwargs):
                pass
        return _Dummy


def install_stubs() -> None:
    flask_mod = types.ModuleType("flask")
    flask_mod.Flask = DummyFlaskApp
    flask_mod.jsonify = lambda obj=None, **kwargs: obj if obj is not None else kwargs
    flask_mod.request = types.SimpleNamespace(get_json=lambda *a, **k: {})
    flask_mod.render_template = lambda *a, **k: ""
    sys.modules["flask"] = flask_mod

    kubernetes_mod = types.ModuleType("kubernetes")
    client_mod = DummyClientModule()
    config_mod = types.ModuleType("kubernetes.config")
    config_mod.load_incluster_config = lambda: None
    config_mod.load_kube_config = lambda: None
    stream_mod = types.ModuleType("kubernetes.stream")
    stream_mod.stream = lambda *a, **k: ""

    kubernetes_mod.client = client_mod
    kubernetes_mod.config = config_mod
    sys.modules["kubernetes"] = kubernetes_mod
    sys.modules["kubernetes.client"] = client_mod
    sys.modules["kubernetes.config"] = config_mod
    sys.modules["kubernetes.stream"] = stream_mod


def load_app_module():
    install_stubs()
    os.environ.setdefault("EVIDENCE_DIR", "/tmp/ztx-falco-webhook-local-gate")
    sys.path.insert(0, str(APP_PATH.parent))
    spec = importlib.util.spec_from_file_location("ztx_test_app", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def make_pod(name: str, app_label: str):
    return types.SimpleNamespace(
        metadata=types.SimpleNamespace(
            name=name,
            labels={
                "app": app_label,
                "zt-xguard.io/quarantine": "true",
                "security-status": "quarantined",
                "zt-xguard.io/decision": "quarantined",
            },
            annotations={
                "zt-xguard.io/quarantine-reason": "old",
                "zt-xguard.io/quarantine-time": "old",
                "zt-xguard.io/incident-id": "old",
            },
        ),
        spec=types.SimpleNamespace(service_account_name=app_label),
        status=types.SimpleNamespace(phase="Running"),
    )


def patch_sets_quarantine(body) -> bool:
    if isinstance(body, dict):
        labels = ((body.get("metadata") or {}).get("labels") or {})
        return (
            labels.get("zt-xguard.io/quarantine") == "true"
            or labels.get("security-status") == "quarantined"
            or labels.get("zt-xguard.io/decision") == "quarantined"
        )

    if isinstance(body, list):
        for item in body:
            if not isinstance(item, dict):
                continue
            if item.get("op") not in {"add", "replace"}:
                continue
            path = str(item.get("path") or "")
            value = str(item.get("value") or "").strip().lower()
            if path.endswith("/zt-xguard.io~1quarantine") and value == "true":
                return True
            if path.endswith("/security-status") and value == "quarantined":
                return True
            if path.endswith("/zt-xguard.io~1decision") and value == "quarantined":
                return True

    return False


def main() -> None:
    app = load_app_module()

    payload_a13 = {
        "hostname": "near-rt-ric",
        "output": "17:33:24.410735404: Warning ztx_signal=package_manager_execution rule_id=ZTX-A13 xapp package manager execution (user=xappuser command=pip3 /usr/local/bin/pip3 --version pod=resource-optimizer-84fbcbf96c-7v5rw ns=ricxapp container=resource-optimizer)",
        "output_fields": {
            "container.name": "resource-optimizer",
            "k8s.ns.name": "ricxapp",
            "k8s.pod.name": "resource-optimizer-84fbcbf96c-7v5rw",
            "proc.cmdline": "pip3 /usr/local/bin/pip3 --version",
            "user.name": "xappuser",
        },
        "priority": "Warning",
        "rule": "ZTX xApp Package Manager Execution",
        "source": "syscall",
        "tags": ["package-manager", "process", "xapp", "zt-xguard"],
        "time": "2026-06-12T17:33:24.410735404Z",
    }

    signal = app.ztx_v4_signal_from_event(payload_a13)
    if signal != "package_manager_execution":
        fail(f"expected embedded ztx_signal parse to return package_manager_execution, got {signal!r}")
    ok("embedded ztx_signal parsing returns package_manager_execution")

    patch_calls = []

    class FakeCore:
        def patch_namespaced_pod(self, name, namespace, body):
            patch_calls.append({"name": name, "namespace": namespace, "body": body})

    pods = {
        "resource-optimizer": make_pod("resource-optimizer-84fbcbf96c-7v5rw", "resource-optimizer"),
        "telemetry-monitor": make_pod("telemetry-monitor-84fbcbf96c-a11tm", "telemetry-monitor"),
    }

    app.CORE = FakeCore()
    app.get_pods_for_xapp = lambda xapp, namespace: [pods[xapp]] if xapp in pods else []
    app.get_primary_pod_for_xapp = lambda xapp, namespace: pods.get(xapp)
    app.get_pod_safe = lambda name, namespace: next(
        (pod for pod in pods.values() if pod.metadata.name == name or pod.metadata.labels.get("app") == name),
        None,
    )
    app.verify_xapp_containment = lambda xapp, namespace: {
        "service_isolated": False,
        "contained": False,
        "quarantine_marked": False,
        "services": [{"endpoint_summary": {"endpoint_count": 1}}],
    }
    app.ensure_quarantine_network_policy = lambda namespace: None
    app.apply_service_isolation = lambda *a, **k: {"applied": True, "method": "service_selector_isolation"}
    app.scale_deployment_for_xapp = lambda *a, **k: {"applied": False}
    app.revoke_spire_entry = lambda spiffe_id: {"attempted": False, "revoked": False}
    app.csm_update_from_result = lambda *a, **k: None
    app.csm_remember_event = lambda *a, **k: None

    app.ztx_v4_decide = lambda xapp, signal, evidence=None: {
        "decision_state": "SUSPICIOUS",
        "detection_state": "SUSPICIOUS",
        "containment_required": False,
        "containment_action": "NONE",
        "action": "EVIDENCE_ONLY",
        "score": 35,
        "confidence": 0.79,
        "severity": "MEDIUM",
        "rule_ids": ["ZTX-A13"],
        "evidence_sources": {"falco": True},
        "transition": {"from": "TRUSTED", "to": "SUSPICIOUS"},
        "reasons": ["package manager executed inside controlled xApp"],
        "layers": {"L1_runtime_exploitation": ["package manager executed inside controlled xApp"]},
        "snapshot": {},
        "normalized_signal": "package_manager_execution",
    }
    app.request = types.SimpleNamespace(get_json=lambda *a, **k: payload_a13)
    suspicious_body, suspicious_status = app.falco_webhook()

    if suspicious_status != 200:
        fail(f"expected falco_webhook A13 status 200, got {suspicious_status!r}")
    if suspicious_body.get("normalized_signal") != "package_manager_execution":
        fail(f"expected normalized_signal=package_manager_execution, got {suspicious_body.get('normalized_signal')!r}")
    if suspicious_body.get("decision_state") != "SUSPICIOUS":
        fail(f"expected decision_state=SUSPICIOUS, got {suspicious_body.get('decision_state')!r}")
    if suspicious_body.get("containment_required") is not False:
        fail(f"expected containment_required=false, got {suspicious_body.get('containment_required')!r}")
    if suspicious_body.get("label_write_allowed") is not False:
        fail(f"expected label_write_allowed=false, got {suspicious_body.get('label_write_allowed')!r}")
    if suspicious_body.get("label_write_block_reason") != "suspicious_only_signal":
        fail(f"expected block reason suspicious_only_signal, got {suspicious_body.get('label_write_block_reason')!r}")
    expected_a13_path = "falco_webhook->csm_process_falco_event->ztx_v4_process_signal->ztx_v4_sync_runtime_labels->ztx_guarded_patch_namespaced_pod"
    if suspicious_body.get("handler_path") != expected_a13_path:
        fail(f"expected handler_path={expected_a13_path!r}, got {suspicious_body.get('handler_path')!r}")
    if suspicious_body.get("pod_label_sync", {}).get("desired_decision_label") != "suspicious":
        fail(f"expected decision label sync to set suspicious, got {suspicious_body.get('pod_label_sync')!r}")
    if any(patch_sets_quarantine(call["body"]) for call in patch_calls):
        fail(f"suspicious-only route wrote quarantine labels: {patch_calls!r}")
    if not any(
        ((call["body"].get("metadata") or {}).get("labels") or {}).get("zt-xguard.io/decision") == "suspicious"
        for call in patch_calls
        if isinstance(call.get("body"), dict)
    ):
        fail(f"expected suspicious decision label patch, got {patch_calls!r}")
    ok("real A13 webhook payload blocks quarantine labels and leaves only suspicious decision labelling")

    patch_calls.clear()
    payload_a11 = {
        "hostname": "near-rt-ric",
        "output": "17:34:24.410735404: Critical ztx_signal=svid_material_access rule_id=ZTX-A11 xapp SVID material access (user=xappuser command=cat /run/spire/sockets/agent.sock pod=telemetry-monitor-84fbcbf96c-a11tm ns=ricxapp container=telemetry-monitor)",
        "output_fields": {
            "container.name": "telemetry-monitor",
            "k8s.ns.name": "ricxapp",
            "k8s.pod.name": "telemetry-monitor-84fbcbf96c-a11tm",
            "proc.cmdline": "cat /run/spire/sockets/agent.sock",
            "user.name": "xappuser",
        },
        "priority": "Critical",
        "rule": "ZTX xApp SVID Material Access",
        "source": "syscall",
        "tags": ["identity", "xapp", "zt-xguard"],
        "time": "2026-06-12T17:34:24.410735404Z",
    }

    app.ztx_v4_decide = lambda xapp, signal, evidence=None: {
        "decision_state": "COMPROMISED",
        "detection_state": "COMPROMISED",
        "containment_required": True,
        "containment_action": "SERVICE_ISOLATION_AND_IDENTITY_CONTAINMENT",
        "action": "FORENSIC_QUARANTINE",
        "score": 100,
        "confidence": 0.98,
        "severity": "CRITICAL",
        "rule_ids": ["ZTX-A11"],
        "evidence_sources": {"falco": True},
        "transition": {"from": "TRUSTED", "to": "COMPROMISED"},
        "reasons": ["xApp accessed/tampered with SVID/SPIRE identity material"],
        "layers": {"L2_identity_svid": ["xApp accessed/tampered with SVID/SPIRE identity material"]},
        "snapshot": {},
        "normalized_signal": "svid_material_access",
    }
    app.request = types.SimpleNamespace(get_json=lambda *a, **k: payload_a11)
    critical_body, critical_status = app.falco_webhook()

    if critical_status != 200:
        fail(f"expected falco_webhook A11 status 200, got {critical_status!r}")
    if critical_body.get("normalized_signal") != "svid_material_access":
        fail(f"expected normalized_signal=svid_material_access, got {critical_body.get('normalized_signal')!r}")
    if critical_body.get("containment_required") is not True:
        fail(f"expected containment_required=true, got {critical_body.get('containment_required')!r}")
    if critical_body.get("label_write_allowed") is not True:
        fail(f"expected label_write_allowed=true for A11, got {critical_body.get('label_write_allowed')!r}")
    if not any(patch_sets_quarantine(call["body"]) for call in patch_calls):
        fail(f"critical route did not write quarantine labels: {patch_calls!r}")
    ok("critical A11 webhook payload still allows quarantine labels")

    print()
    print("A13_RESPONSE")
    print(suspicious_body)
    print()
    print("A11_RESPONSE")
    print(critical_body)
    print()
    print("FALCO_WEBHOOK_LOCAL_GATE_PASS")


if __name__ == "__main__":
    main()
