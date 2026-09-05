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
    os.environ.setdefault("EVIDENCE_DIR", "/tmp/ztx-containment-verification-local-gate")
    sys.path.insert(0, str(APP_PATH.parent))
    spec = importlib.util.spec_from_file_location("ztx_containment_test_app", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def make_service(name: str, selector: dict, annotations: dict):
    return types.SimpleNamespace(
        metadata=types.SimpleNamespace(name=name, annotations=annotations),
        spec=types.SimpleNamespace(selector=selector),
    )


def make_pod(name: str, app_label: str, quarantined: bool):
    labels = {"app": app_label}
    if quarantined:
        labels.update({
            "zt-xguard.io/quarantine": "true",
            "security-status": "quarantined",
            "zt-xguard.io/decision": "quarantined",
        })
    return types.SimpleNamespace(
        metadata=types.SimpleNamespace(name=name, labels=labels),
        status=types.SimpleNamespace(phase="Running", container_statuses=[]),
    )


def main() -> None:
    app = load_app_module()

    endpoints_map = {
        "telemetry-monitor": types.SimpleNamespace(subsets=None),
        "resource-optimizer": types.SimpleNamespace(subsets=[
            types.SimpleNamespace(
                addresses=[types.SimpleNamespace(ip="10.0.0.21")],
                ports=[types.SimpleNamespace(name="http", port=8080, protocol="TCP")],
            )
        ]),
    }

    class FakeCore:
        def read_namespaced_endpoints(self, name, namespace):
            if name not in endpoints_map:
                raise KeyError(name)
            return endpoints_map[name]

    app.CORE = FakeCore()

    isolated_service = make_service(
        "telemetry-monitor",
        {
            "app": "telemetry-monitor",
            "zt-xguard.io/service-isolated": "ztxq-12345",
        },
        {
            "zt-xguard.io/service-isolated": "true",
            "zt-xguard.io/original-service-selector": "{\"app\":\"telemetry-monitor\"}",
        },
    )
    healthy_service = make_service(
        "resource-optimizer",
        {"app": "resource-optimizer"},
        {},
    )

    pods = {
        "telemetry-monitor": [make_pod("telemetry-monitor-abc123", "telemetry-monitor", quarantined=True)],
        "resource-optimizer": [make_pod("resource-optimizer-abc123", "resource-optimizer", quarantined=False)],
    }
    services = {
        "telemetry-monitor": [isolated_service],
        "resource-optimizer": [healthy_service],
    }

    app.list_services_for_xapp = lambda xapp, namespace: services.get(xapp, [])
    app.get_pods_for_xapp = lambda xapp, namespace: pods.get(xapp, [])

    isolated_summary = app.service_endpoints_summary("telemetry-monitor", "ricxapp")
    if isolated_summary != {
        "service": "telemetry-monitor",
        "endpoint_count": 0,
        "addresses": [],
        "ports": [],
        "has_endpoints": False,
        "source": "endpoints",
        "error": None,
    }:
        fail(f"unexpected isolated endpoint summary: {isolated_summary!r}")

    isolated_verify = app.verify_xapp_containment("telemetry-monitor", "ricxapp")
    isolated_service_result = isolated_verify["services"][0]
    if isolated_verify.get("service_isolated") is not True:
        fail(f"expected isolated service_isolated=true, got {isolated_verify!r}")
    if isolated_verify.get("contained") is not True:
        fail(f"expected isolated contained=true, got {isolated_verify!r}")
    if isolated_verify.get("quarantine_marked") is not True:
        fail(f"expected isolated quarantine_marked=true, got {isolated_verify!r}")
    if isolated_verify.get("verification_unknown") is not False:
        fail(f"expected isolated verification_unknown=false, got {isolated_verify!r}")
    if isolated_service_result["endpoint_summary"].get("endpoint_count") != 0:
        fail(f"expected isolated endpoint_count=0, got {isolated_service_result!r}")
    ok("service-isolated service with Endpoints subsets=null verifies as contained with endpoint_count=0")

    healthy_summary = app.service_endpoints_summary("resource-optimizer", "ricxapp")
    if healthy_summary.get("endpoint_count") != 1 or healthy_summary.get("has_endpoints") is not True:
        fail(f"unexpected healthy endpoint summary: {healthy_summary!r}")

    healthy_verify = app.verify_xapp_containment("resource-optimizer", "ricxapp")
    healthy_service_result = healthy_verify["services"][0]
    if healthy_verify.get("service_isolated") is not False:
        fail(f"expected healthy service_isolated=false, got {healthy_verify!r}")
    if healthy_verify.get("contained") is not False:
        fail(f"expected healthy contained=false, got {healthy_verify!r}")
    if healthy_verify.get("quarantine_marked") is not False:
        fail(f"expected healthy quarantine_marked=false, got {healthy_verify!r}")
    if healthy_service_result["endpoint_summary"].get("endpoint_count") != 1:
        fail(f"expected healthy endpoint_count=1, got {healthy_service_result!r}")
    ok("healthy service with one endpoint remains uncontained and not service-isolated")

    print()
    print("CONTAINMENT_VERIFICATION_LOCAL_GATE_PASS")


if __name__ == "__main__":
    main()
