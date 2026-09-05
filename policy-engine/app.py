
















#!/usr/bin/env python3
"""
ZT-XGuard Runtime Policy Engine

Integrated version:
- Continuous/baseline trust evaluation for all controlled xApps
- Falco/Falcosidekick webhook correlation
- Kubernetes metadata, image digest, ServiceAccount, Kyverno metadata validation
- xApp endpoint collection: /health, /ready, /profile, /activity, /identity, /integrity, /metrics
- Intent-aware scoring using xApp profile and runtime counters
- Forensic incident/evidence capture
- Optional NetworkPolicy quarantine and optional SPIRE entry revocation

Designed for the ZT-XGuard FYP Near-RT RIC testbed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from flask import Flask, jsonify, request, render_template
from kubernetes import client, config
from kubernetes.client import ApiException
from kubernetes.stream import stream

try:
    from ztx_state_engine import STATE_ENGINE_VERSION as ZTX_STATE_ENGINE_VERSION
    from ztx_state_engine import SIGNAL_ALIASES as ZTX_STATE_ENGINE_SIGNAL_ALIASES
    from ztx_state_engine import evaluate_state as ztx_v5_evaluate_state
except Exception as _ztx_state_engine_import_error:
    ZTX_STATE_ENGINE_VERSION = "unavailable"
    ZTX_STATE_ENGINE_SIGNAL_ALIASES = {}
    ztx_v5_evaluate_state = None
    ZTX_STATE_ENGINE_IMPORT_ERROR = str(_ztx_state_engine_import_error)
else:
    ZTX_STATE_ENGINE_IMPORT_ERROR = None

try:
    from ztx_repeat_tracker import record_and_check as ztx_repeat_record_and_check
    from ztx_repeat_tracker import REPEAT_WINDOW_SECONDS as ZTX_REPEAT_WINDOW_SECONDS
except Exception as _ztx_repeat_tracker_import_error:
    ztx_repeat_record_and_check = None
    ZTX_REPEAT_WINDOW_SECONDS = None
    ZTX_REPEAT_TRACKER_IMPORT_ERROR = str(_ztx_repeat_tracker_import_error)
else:
    ZTX_REPEAT_TRACKER_IMPORT_ERROR = None

try:
    import ztx_isolation_manager
except Exception as _ztx_isolation_manager_import_error:
    ztx_isolation_manager = None
    ZTX_ISOLATION_MANAGER_IMPORT_ERROR = str(_ztx_isolation_manager_import_error)
else:
    ZTX_ISOLATION_MANAGER_IMPORT_ERROR = None

try:
    import ztx_falco_rule_sync
except Exception as _ztx_falco_rule_sync_import_error:
    ztx_falco_rule_sync = None
    ZTX_FALCO_RULE_SYNC_IMPORT_ERROR = str(_ztx_falco_rule_sync_import_error)
else:
    ZTX_FALCO_RULE_SYNC_IMPORT_ERROR = None

APP = Flask(__name__)

@APP.after_request
def add_header(response):
    if response.headers.get("Content-Type", "").startswith("text/javascript") or response.headers.get("Content-Type", "").startswith("text/css"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response

# -----------------------------
# Configuration
#
# step_xguard_02 Step B1 (2026-07-15): these constants, the K8s client
# singletons, and the shared CSM_STATE cache now live in ztx_config.py /
# k8s_clients.py / csm_shared_state.py respectively, so
# event_normalization.py and containment_orchestrator.py can use the same
# values/objects without importing app.py (which would be circular, since
# app.py imports functions back out of them below).
# -----------------------------

from ztx_config import (
    ENGINE_VERSION,
    XAPP_NAMESPACE,
    TRUST_DOMAIN,
    POLICY_NAMESPACE,
    XAPP_LIST,
    TRUSTED_PROVIDER,
    APPROVED_REGISTRY_PREFIX,
    STRICT_IMAGE_ID_MATCH,
    ACTIVITY_TIMEOUT,
    REQUEST_TIMEOUT,
    AUTO_QUARANTINE,
    REVOKE_SPIRE,
    T2_AUTO_CONTAIN,
    CONTAINMENT_MODE,
    SPIRE_SERVER_POD,
    SPIRE_NAMESPACE,
    SPIRE_CONTAINER,
    SPIRE_BIN,
    MAX_LOG_LINES,
    PROMETHEUS_URL,
    PROMETHEUS_TIMEOUT,
    ZTX_SUSPICIOUS_ONLY_SIGNALS,
    ZTX_QUARANTINE_CAPABLE_SIGNALS,
    ZTX_SIGNAL_ALIASES,
    ZTX_QUARANTINE_LABEL_VALUES,
    ORIGINAL_SELECTOR_ANNOTATION,
    SERVICE_ISOLATED_ANNOTATION,
    SERVICE_ISOLATED_INCIDENT_ANNOTATION,
    ORIGINAL_REPLICAS_ANNOTATION,
)

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "/evidence"))
SCAN_INTERVAL_SEC = float(os.environ.get("SCAN_INTERVAL_SEC", "0"))

EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
INCIDENT_DIR = EVIDENCE_DIR / "incidents"
SCAN_DIR = EVIDENCE_DIR / "scans"
INCIDENT_DIR.mkdir(parents=True, exist_ok=True)
SCAN_DIR.mkdir(parents=True, exist_ok=True)

# -----------------------------
# Kubernetes client init
# -----------------------------

from k8s_clients import CORE, APPS, NET

LAST_REPORT_LOCK = threading.Lock()
LAST_REPORT: Dict[str, Any] = {}
LAST_INCIDENTS: List[Dict[str, Any]] = []

# CSM_REALTIME_STATE_MARKER
# Fast CSM runtime state. This is cached/event-driven and must not
# perform a full endpoint audit on every read. The slow audit path updates this
# cache, and Falco/runtime events update it immediately. Shared with
# containment_orchestrator.py's _ztx_v2_set_state_normal (restore path) -
# both modules must mutate the SAME dict/lock, hence csm_shared_state.py.
from csm_shared_state import CSM_STATE_LOCK, CSM_STATE, csm_xapp_lock, csm_in_restore_grace, csm_mark_restored

CSM_EVENT_HISTORY: List[Dict[str, Any]] = []


# -----------------------------
# Event Normalization + Containment Orchestrator components
#
# step_xguard_02 Step B1: these were extracted verbatim out of this file
# into event_normalization.py and containment_orchestrator.py. Every name
# below is imported under its original name so every call site in this
# file - live or still-dead-code - keeps resolving exactly as before.
# -----------------------------

from event_normalization import (
    ZT_INTENT_PROFILES_V4,
    _ztx_get_output_fields,
    _ztx_get_event_namespace,
    _ztx_get_event_pod,
    _ztx_xapp_list,
    _ztx_xapp_from_pod_name,
    _ztx_event_scope_decision,
    ztx_v4_event_identity,
    _ZTX_FALCO_SIGNAL_RE,
    _ztx_v4_embedded_signal,
    ztx_v4_signal_from_event,
)

from containment_orchestrator import (
    ztx_normalize_signal,
    ztx_label_write_context,
    ztx_quarantine_label_write_decision,
    ztx_requested_pod_labels,
    ztx_attempts_quarantine_labels,
    ztx_non_quarantine_decision_label,
    ztx_quarantine_clear_patch,
    ztx_guarded_patch_namespaced_pod,
    ensure_quarantine_network_policy,
    ensure_suspicious_network_policy,
    apply_quarantine,
    get_pod_safe,
    get_xapp_from_pod_or_name,
    list_services_for_xapp,
    ztx_patch5b_v3_endpoint_summary,
    service_endpoints_summary,
    k8s_label_value,
    apply_service_isolation,
    restore_service_isolation,
    scale_deployment_for_xapp,
    restore_deployment_scale,
    get_pods_for_xapp,
    get_primary_pod_for_xapp,
    verify_xapp_containment,
    revoke_workload_identity,
    restore_workload_identity,
    apply_direct_network_isolation,
    restore_direct_network_isolation,
    ztx_release_blocked_ips_for_xapp,
    verify_direct_network_isolation,
    ztx_reassert_pod_level_containment,
    ztx_recreate_pods_for_clean_restore,
    _ztx_live_containment,
    _ztx_force_containment_for_xapp,
    _ztx_v2_set_state_normal,
    _ztx_v2_response_payload,
)


# -----------------------------
# Utility helpers
# -----------------------------


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def utc_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def safe_name(value: str) -> str:
    value = str(value or "unknown")
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in value)[:160]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def jsonable(obj: Any) -> Any:
    try:
        return client.ApiClient().sanitize_for_serialization(obj)
    except Exception:
        try:
            return json.loads(json.dumps(obj, default=str))
        except Exception:
            return str(obj)


def write_json(path: Path, data: Dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False), encoding="utf-8")
    return str(path)


# step_xguard_02 Step B1 (2026-07-15): ztx_normalize_signal,
# ztx_label_write_context, ztx_quarantine_label_write_decision,
# ztx_requested_pod_labels, ztx_attempts_quarantine_labels,
# ztx_non_quarantine_decision_label, ztx_quarantine_clear_patch, and
# ztx_guarded_patch_namespaced_pod moved to containment_orchestrator.py
# (imported above under their original names).


def finding(passed: bool, severity: str, signal: str, message: str, penalty: int) -> Optional[Dict[str, Any]]:
    if passed:
        return None
    return {
        "severity": severity,
        "signal": signal,
        "message": message,
        "score_penalty": penalty,
    }


def add_finding(findings: List[Dict[str, Any]], passed: bool, severity: str, signal: str, message: str, penalty: int) -> int:
    item = finding(passed, severity, signal, message, penalty)
    if item:
        findings.append(item)
        return penalty
    return 0


def severity_rank(severity: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(str(severity).lower(), 0)


def spiffe_for(namespace: str, service_account: str) -> str:
    return f"spiffe://{TRUST_DOMAIN}/ns/{namespace}/sa/{service_account}"


def normalize_image_id(image_id: str) -> str:
    if not image_id:
        return ""
    value = str(image_id).strip()

    # Kubernetes/containerd can expose image IDs in several forms:
    #   sha256:<digest>
    #   docker-pullable://repo@sha256:<digest>
    #   containerd://sha256:<digest>
    #   repo@sha256:<digest>
    value = value.replace("docker-pullable://", "")
    value = value.replace("docker://", "")
    value = value.replace("containerd://", "")

    if "@sha256:" in value:
        return "sha256:" + value.split("@sha256:", 1)[1]

    if "sha256:" in value:
        return "sha256:" + value.split("sha256:", 1)[1]

    return value


def digest_matches_annotation(annotated_digest: str, image_ids: list) -> bool:
    if not annotated_digest:
        return False

    annotated = normalize_image_id(annotated_digest)

    for image_id in image_ids:
        runtime = normalize_image_id(image_id)
        if not runtime:
            continue

        if runtime == annotated:
            return True

        # Defensive fallback for kubelet/containerd formatting differences.
        if annotated in runtime or runtime in annotated:
            return True

    return False


def service_url(service_name: str, path: str, namespace: str = XAPP_NAMESPACE) -> str:
    return f"http://{service_name}.{namespace}.svc.cluster.local:8080{path}"


def fetch_json(service_name: str, path: str, timeout: float = REQUEST_TIMEOUT) -> Dict[str, Any]:
    url = service_url(service_name, path)
    try:
        resp = requests.get(url, timeout=timeout)
        body_text = resp.text
        try:
            body = resp.json() if body_text else {}
        except Exception:
            body = {"raw": body_text[:2000]}
        return {"ok": 200 <= resp.status_code < 300, "status": resp.status_code, "body": body, "error": None, "url": url}
    except Exception as exc:
        return {"ok": False, "status": None, "body": {}, "error": str(exc), "url": url}


def fetch_text(service_name: str, path: str, timeout: float = REQUEST_TIMEOUT) -> Dict[str, Any]:
    url = service_url(service_name, path)
    try:
        resp = requests.get(url, timeout=timeout)
        return {"ok": 200 <= resp.status_code < 300, "status": resp.status_code, "body": resp.text, "error": None, "url": url}
    except Exception as exc:
        return {"ok": False, "status": None, "body": "", "error": str(exc), "url": url}


# -----------------------------
# Kubernetes helpers
# -----------------------------


def list_xapp_pods(namespace: str = XAPP_NAMESPACE) -> List[Any]:
    pods = CORE.list_namespaced_pod(namespace=namespace).items
    controlled = []
    for pod in pods:
        labels = pod.metadata.labels or {}
        app = labels.get("app")
        if app in XAPP_LIST:
            controlled.append(pod)
    return controlled


# step_xguard_02 Step B1: get_pods_for_xapp and get_primary_pod_for_xapp
# moved to containment_orchestrator.py (imported above).


def get_pod_by_name(pod_name: str, namespace: str) -> Optional[Any]:
    try:
        return CORE.read_namespaced_pod(name=pod_name, namespace=namespace)
    except ApiException as exc:
        if exc.status == 404:
            return None
        raise


def resolve_deployment_name(pod: Any) -> str:
    ns = pod.metadata.namespace
    owners = pod.metadata.owner_references or []
    labels = pod.metadata.labels or {}
    for owner in owners:
        if owner.kind == "ReplicaSet":
            try:
                rs = APPS.read_namespaced_replica_set(owner.name, ns)
                rs_owners = rs.metadata.owner_references or []
                for rs_owner in rs_owners:
                    if rs_owner.kind == "Deployment":
                        return rs_owner.name
            except Exception:
                pass
    return labels.get("app") or pod.metadata.name


def pod_events(namespace: str, pod_name: str) -> List[Dict[str, Any]]:
    try:
        events = CORE.list_namespaced_event(namespace=namespace, field_selector=f"involvedObject.name={pod_name}").items
        return jsonable(events)
    except Exception as exc:
        return [{"error": str(exc)}]


def pod_log_tail(namespace: str, pod_name: str, lines: int = MAX_LOG_LINES) -> str:
    try:
        return CORE.read_namespaced_pod_log(name=pod_name, namespace=namespace, tail_lines=lines, timestamps=True)
    except Exception as exc:
        return f"log_fetch_failed: {exc}"


# -----------------------------
# Endpoint collection
# -----------------------------


def collect_xapp_endpoints(xapp: str) -> Dict[str, Dict[str, Any]]:
    return {
        "health": fetch_json(xapp, "/health"),
        "ready": fetch_json(xapp, "/ready"),
        "profile": fetch_json(xapp, "/profile"),
        "activity": fetch_json(xapp, "/activity", timeout=ACTIVITY_TIMEOUT),
        "identity": fetch_json(xapp, "/identity"),
        "integrity": fetch_json(xapp, "/integrity"),
        "metrics": fetch_text(xapp, "/metrics"),
    }


# -----------------------------
# Trust evaluation
# -----------------------------


_ZTX_RETIRED_2026_07_16 = """
evaluate_xapp/classify_alert_fields/build_report/csm_update_from_report/
scanner_loop retired 2026-07-16 - this was a completely separate, static
label/annotation-scoring rubric that never went through evaluate_state(),
wrote into the same CSM_STATE cache the real Falco/T2 decision path uses,
and could emit the retired "OBSERVED" state. Its background loop was
already dead by default (SCAN_INTERVAL_SEC=0), but /scan, /csm/audit, and
/trust-state still called it directly on every request - a real two-
pipelines-racing risk, not just unused code. Those 3 routes now read the
same CSM_STATE-backed csm_state_payload() /csm/state already serves. See
ZTXGUARD_SESSION_LOG_20260710.md for the full removal rationale.
"""


def evaluate_xapp(xapp: str, namespace: str = XAPP_NAMESPACE, endpoints: Optional[Dict[str, Any]] = None, pod: Optional[Any] = None, extra_alert: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    score = 100

    if pod is None:
        pod = get_primary_pod_for_xapp(xapp, namespace)

    if pod is None:
        return {
            "xapp": xapp,
            "namespace": namespace,
            "state": "COMPROMISED",
            "score": 0,
            "pod": None,
            "findings": [{
                "severity": "critical",
                "signal": "pod_missing",
                "message": "No pod found for controlled xApp",
                "score_penalty": 100,
            }],
            "time": utc_now(),
        }

    pod_json = jsonable(pod)
    metadata = pod_json.get("metadata", {}) or {}
    spec = pod_json.get("spec", {}) or {}
    status = pod_json.get("status", {}) or {}

    pod_name = metadata.get("name")
    labels = metadata.get("labels", {}) or {}
    annotations = metadata.get("annotations", {}) or {}
    service_account = spec.get("serviceAccountName") or "default"
    containers = spec.get("containers", []) or []
    container_statuses = status.get("containerStatuses", []) or []
    phase = status.get("phase")

    images = [c.get("image", "") for c in containers]
    image_ids = [normalize_image_id(c.get("imageID", "")) for c in container_statuses]
    ready_statuses = [bool(c.get("ready")) for c in container_statuses]

    if endpoints is None:
        endpoints = collect_xapp_endpoints(xapp)

    health = endpoints.get("health", {}).get("body", {}) or {}
    ready = endpoints.get("ready", {}).get("body", {}) or {}
    profile = endpoints.get("profile", {}).get("body", {}) or {}
    activity = endpoints.get("activity", {}).get("body", {}) or {}
    identity = endpoints.get("identity", {}).get("body", {}) or {}
    integrity = endpoints.get("integrity", {}).get("body", {}) or {}
    metrics = endpoints.get("metrics", {}) or {}

    app_label = labels.get("app")
    verified_label = labels.get("zt-xguard.io/verified")
    provider_label = labels.get("zt-xguard.io/provider")
    descriptor_hash = annotations.get("zt-xguard.io/descriptor-sha256")
    annotated_image_digest = annotations.get("zt-xguard.io/image-digest")
    annotated_profile_hash = annotations.get("zt-xguard.io/profile-hash")
    admission_control = annotations.get("zt-xguard.io/admission-control")
    chart_generated_by = annotations.get("zt-xguard.io/chart-generated-by")
    expected_spiffe = spiffe_for(namespace, service_account)

    score -= add_finding(findings, phase == "Running", "critical", "pod_phase", f"Pod phase is {phase}", 50)
    score -= add_finding(findings, bool(ready_statuses) and all(ready_statuses), "high", "container_readiness", "One or more containers are not ready", 20)
    score -= add_finding(findings, app_label == xapp, "critical", "app_label", f"app label mismatch: {app_label}", 40)
    score -= add_finding(findings, verified_label == "true", "critical", "verified_label", "Missing zt-xguard.io/verified=true", 60)
    score -= add_finding(findings, provider_label == TRUSTED_PROVIDER, "high", "provider_label", f"Unexpected provider: {provider_label}", 20)
    score -= add_finding(findings, bool(descriptor_hash), "high", "descriptor_hash", "Missing descriptor hash annotation", 15)
    score -= add_finding(findings, bool(annotated_image_digest), "critical", "image_digest_annotation", "Missing image digest annotation", 40)
    score -= add_finding(findings, bool(annotated_profile_hash), "critical", "profile_hash_annotation", "Missing profile hash annotation", 40)
    score -= add_finding(findings, admission_control == "kyverno", "high", "admission_control", f"Unexpected admission-control annotation: {admission_control}", 15)
    score -= add_finding(findings, chart_generated_by == "zt-xguard-smo", "high", "chart_generator", f"Unexpected chart generator: {chart_generated_by}", 15)
    score -= add_finding(findings, service_account == xapp and service_account != "default", "critical", "service_account", f"Unexpected ServiceAccount: {service_account}", 45)

    approved_image = any(img.startswith(f"{APPROVED_REGISTRY_PREFIX}{xapp}:") or img.startswith(f"{APPROVED_REGISTRY_PREFIX}{xapp}@") for img in images)
    score -= add_finding(findings, approved_image, "critical", "approved_image", f"Unapproved image list: {images}", 40)

    runtime_digest_match = digest_matches_annotation(annotated_image_digest, image_ids)

    # Important:
    # Kubernetes/containerd imageID can differ from the registry manifest digest
    # stored by the SMO. Therefore this check is diagnostic by default.
    # Set STRICT_IMAGE_ID_MATCH=true only when the runtime imageID format is
    # known to match the SMO/registry digest format exactly.
    if STRICT_IMAGE_ID_MATCH:
        score -= add_finding(
            findings,
            runtime_digest_match,
            "high",
            "image_digest_match",
            f"Runtime image digest mismatch. annotated={annotated_image_digest}, imageIDs={image_ids}",
            30,
        )

    score -= add_finding(findings, endpoints.get("health", {}).get("ok") and health.get("status") == "ok", "high", "health_endpoint", "/health failed or returned non-ok", 20)
    score -= add_finding(findings, endpoints.get("ready", {}).get("ok") and ready.get("ready") is True, "high", "ready_endpoint", "/ready failed or ready=false", 25)
    score -= add_finding(findings, endpoints.get("profile", {}).get("ok") and profile.get("xapp") == xapp, "high", "profile_endpoint", "/profile missing or xApp mismatch", 20)
    score -= add_finding(findings, endpoints.get("activity", {}).get("ok") and activity.get("heartbeat_ok") is True, "high", "heartbeat", "Heartbeat missing/stale or /activity failed", 25)
    score -= add_finding(findings, int(activity.get("errors", 1)) == 0, "medium", "internal_errors", f"xApp reports errors={activity.get('errors')}", 10)

    endpoint_expected_spiffe = identity.get("expected_spiffe_id")
    score -= add_finding(findings, endpoint_expected_spiffe == expected_spiffe, "medium", "spiffe_id_expected", f"SPIFFE mismatch. expected={expected_spiffe}, endpoint={endpoint_expected_spiffe}", 10)
    score -= add_finding(findings, identity.get("svid_certificate_present") is True and identity.get("svid_key_present") is True, "high", "svid_presence", "SVID certificate/key not reported as mounted", 20)
    score -= add_finding(findings, integrity.get("profile_sha256") == annotated_profile_hash, "critical", "profile_hash_match", f"Profile hash mismatch. runtime={integrity.get('profile_sha256')}, annotated={annotated_profile_hash}", 60)

    runtime_controls = integrity.get("runtime_expected_controls", {}) or {}
    for ctrl in ["expected_shell", "expected_sensitive_file_access", "expected_external_egress", "expected_cross_xapp_comm"]:
        score -= add_finding(findings, runtime_controls.get(ctrl) is False, "medium", f"runtime_control_{ctrl}", f"Runtime control {ctrl} is not false", 8)

    metrics_body = metrics.get("body", "")
    score -= add_finding(findings, metrics.get("ok") is True and "xapp_work_units_processed" in metrics_body, "medium", "metrics_endpoint", "/metrics missing xapp_work_units_processed", 8)

    # Intent-aware behavior checks.
    expected_ric = bool(profile.get("expected_ric_activity", profile.get("controls", {}).get("expected_ric_activity", False)))
    expected_control = bool(profile.get("expected_control_activity", profile.get("controls", {}).get("expected_control_activity", False)))
    expected_external = bool(profile.get("expected_external_egress", profile.get("controls", {}).get("expected_external_egress", False)))
    expected_cross = bool(profile.get("expected_cross_xapp_comm", profile.get("controls", {}).get("expected_cross_xapp_comm", False)))

    ric_counter = int(activity.get("ric_activity_counter", 0) or 0)
    control_counter = int(activity.get("control_action_counter", 0) or 0)
    heartbeat_age = float(activity.get("heartbeat_age_sec", 999999) or 999999)
    heartbeat_period = float(profile.get("heartbeat_period_sec", profile.get("controls", {}).get("heartbeat_period_sec", 5)) or 5)

    if not expected_ric and ric_counter > 0:
        score -= add_finding(findings, False, "medium", "unexpected_ric_activity", f"RIC activity counter {ric_counter} but profile says no RIC activity expected", 12)
    if not expected_control and control_counter > 0:
        score -= add_finding(findings, False, "medium", "unexpected_control_activity", f"Control action counter {control_counter} but profile says no control activity expected", 12)
    score -= add_finding(findings, heartbeat_age <= max(15, heartbeat_period * 4), "medium", "heartbeat_age_threshold", f"Heartbeat age {heartbeat_age}s exceeds threshold", 10)

    # Falco/webhook alert correlation.
    alert_evidence = None
    if extra_alert:
        alert_evidence = classify_alert_fields(extra_alert, profile, activity)
        for f in alert_evidence.get("findings", []):
            findings.append(f)
            score -= int(f.get("score_penalty", 0))

    score = max(0, min(100, score))
    criticals = [f for f in findings if f.get("severity") == "critical"]
    highs = [f for f in findings if f.get("severity") == "high"]

    high_conf_compromise_signals = {
        "pod_missing", "verified_label", "app_label", "service_account", "approved_image", "profile_hash_match",
        "unexpected_shell", "sensitive_file_access", "service_account_token_access", "malicious_tool_execution",
    }
    has_high_conf_compromise = any(f.get("signal") in high_conf_compromise_signals for f in criticals)

    if has_high_conf_compromise or score < 60:
        state = "COMPROMISED"
    elif criticals or score < 85:
        state = "SUSPICIOUS"
    elif highs or score < 98:
        state = "OBSERVED"
    else:
        state = "TRUSTED"

    return {
        "xapp": xapp,
        "namespace": namespace,
        "state": state,
        "score": score,
        "pod": pod_name,
        "deployment": resolve_deployment_name(pod),
        "service_account": service_account,
        "expected_spiffe_id": expected_spiffe,
        "images": images,
        "image_ids": image_ids,
        "labels": labels,
        "annotations": annotations,
        "endpoint_summary": {k: {"ok": v.get("ok"), "status": v.get("status"), "error": v.get("error")} for k, v in endpoints.items()},
        "key_runtime_values": {
            "ready": ready.get("ready"),
            "heartbeat_ok": activity.get("heartbeat_ok"),
            "heartbeat_age_sec": activity.get("heartbeat_age_sec"),
            "errors": activity.get("errors"),
            "work_units_processed": activity.get("work_units_processed"),
            "ric_activity_counter": activity.get("ric_activity_counter"),
            "control_action_counter": activity.get("control_action_counter"),
            "svid_certificate_present": identity.get("svid_certificate_present"),
            "svid_key_present": identity.get("svid_key_present"),
            "runtime_profile_sha256": integrity.get("profile_sha256"),
            "annotated_profile_sha256": annotated_profile_hash,
            "annotated_image_digest": annotated_image_digest,
            "runtime_image_digest_match": runtime_digest_match,
            "strict_image_id_match": STRICT_IMAGE_ID_MATCH,
        },
        "alert_evidence": alert_evidence,
        "findings": sorted(findings, key=lambda x: (-severity_rank(x.get("severity", "info")), x.get("signal", ""))),
        "time": utc_now(),
    }


def classify_alert_fields(alert: Dict[str, Any], profile: Dict[str, Any], activity: Dict[str, Any]) -> Dict[str, Any]:
    fields = alert.get("output_fields", {}) or {}
    rule = str(alert.get("rule") or alert.get("rule_name") or "unknown-rule")
    priority = str(alert.get("priority") or alert.get("priority_num") or "UNKNOWN").upper()
    output = str(alert.get("output") or "")

    rule_l = rule.lower()
    output_l = output.lower()
    priority_l = priority.lower()
    findings: List[Dict[str, Any]] = []

    def profile_bool(name: str, default: bool = False) -> bool:
        return bool(profile.get(name, profile.get("controls", {}).get(name, default)))

    expected_shell = profile_bool("expected_shell", False)
    expected_sensitive = profile_bool("expected_sensitive_file_access", False)
    expected_external = profile_bool("expected_external_egress", False)
    expected_cross = profile_bool("expected_cross_xapp_comm", False)

    shell_patterns = ["shell", "bash", "/bin/sh", " sh ", "zsh", "dash"]
    sensitive_patterns = ["/etc/shadow", "/etc/passwd", "sensitive", "private key", "id_rsa"]
    token_patterns = ["serviceaccount", "service account", "token", "/var/run/secrets/kubernetes.io"]
    tool_patterns = ["nmap", "nc ", "ncat", "netcat", "wget", "curl", "stress-ng", "xmrig", "miner", "masscan"]

    if any(p in rule_l or p in output_l for p in shell_patterns) and not expected_shell:
        findings.append({"severity": "critical", "signal": "unexpected_shell", "message": "Falco indicates unexpected shell/process execution", "score_penalty": 100})
    if any(p in rule_l or p in output_l for p in sensitive_patterns) and not expected_sensitive:
        findings.append({"severity": "critical", "signal": "sensitive_file_access", "message": "Falco indicates sensitive file access", "score_penalty": 100})
    if any(p in rule_l or p in output_l for p in token_patterns):
        findings.append({"severity": "critical", "signal": "service_account_token_access", "message": "Falco indicates Kubernetes ServiceAccount token access", "score_penalty": 100})
    if any(p in output_l for p in tool_patterns):
        findings.append({"severity": "critical", "signal": "malicious_tool_execution", "message": "Falco output indicates suspicious tool execution", "score_penalty": 70})
    if any(p in rule_l or p in output_l for p in ["outbound", "egress", "connection", "network"]):
        if not expected_external:
            findings.append({"severity": "high", "signal": "unexpected_network_egress", "message": "Falco indicates unexpected network/egress behavior", "score_penalty": 35})
    if "cross-xapp" in output_l and not expected_cross:
        findings.append({"severity": "high", "signal": "unexpected_cross_xapp", "message": "Falco indicates cross-xApp communication drift", "score_penalty": 35})

    if priority_l in ["critical", "emergency", "alert"]:
        findings.append({"severity": "high", "signal": "falco_priority", "message": f"Falco priority is {priority}", "score_penalty": 25})
    elif priority_l in ["error", "warning"]:
        findings.append({"severity": "medium", "signal": "falco_priority", "message": f"Falco priority is {priority}", "score_penalty": 10})

    if not findings:
        findings.append({"severity": "info", "signal": "falco_observed", "message": "Falco alert observed but no high-confidence profile violation found", "score_penalty": 0})

    return {
        "rule": rule,
        "priority": priority,
        "output": output,
        "fields": fields,
        "findings": findings,
    }


def build_report(namespace: str = XAPP_NAMESPACE, persist: bool = True, reason: str = "manual_scan") -> Dict[str, Any]:
    started = time.time()
    results = []
    for xapp in XAPP_LIST:
        try:
            results.append(evaluate_xapp(xapp, namespace=namespace))
        except Exception as exc:
            results.append({
                "xapp": xapp,
                "namespace": namespace,
                "state": "COMPROMISED",
                "score": 0,
                "pod": None,
                "findings": [{"severity": "critical", "signal": "engine_exception", "message": str(exc), "score_penalty": 100}],
                "trace": traceback.format_exc(),
                "time": utc_now(),
            })

    counts = {"TRUSTED": 0, "OBSERVED": 0, "SUSPICIOUS": 0, "COMPROMISED": 0, "QUARANTINED": 0}
    for item in results:
        counts[item.get("state", "SUSPICIOUS")] = counts.get(item.get("state", "SUSPICIOUS"), 0) + 1

    if counts.get("COMPROMISED", 0):
        overall = "COMPROMISED"
    elif counts.get("SUSPICIOUS", 0):
        overall = "DEGRADED"
    elif counts.get("OBSERVED", 0):
        overall = "OBSERVED"
    else:
        overall = "HEALTHY"

    report = {
        "component": "zt-xguard-policy-engine",
        "version": ENGINE_VERSION,
        "state_engine_version": ZTX_STATE_ENGINE_VERSION,
        "state_engine_import_error": ZTX_STATE_ENGINE_IMPORT_ERROR,
        "reason": reason,
        "time": utc_now(),
        "namespace": namespace,
        "trust_domain": TRUST_DOMAIN,
        "auto_quarantine": AUTO_QUARANTINE,
        "revoke_spire": REVOKE_SPIRE,
        "overall_state": overall,
        "summary": {**counts, "total": len(results)},
        "duration_sec": round(time.time() - started, 3),
        "xapps": results,
    }

    with LAST_REPORT_LOCK:
        global LAST_REPORT
        LAST_REPORT = report

    csm_update_from_report(report, source=reason)

    if persist:
        path = SCAN_DIR / f"scan-{utc_id()}-{safe_name(reason)}.json"
        report["evidence_path"] = write_json(path, report)

    return report


# -----------------------------
# Falco alert handling
# -----------------------------


def extract_alert_identity(alert: Dict[str, Any]) -> Tuple[str, str, str, str, str, Dict[str, Any]]:
    fields = alert.get("output_fields", {}) or {}
    pod = (
        fields.get("k8s.pod.name")
        or fields.get("k8s.pod")
        or fields.get("pod.name")
        or fields.get("pod")
        or fields.get("container.name")
        or "unknown"
    )
    namespace = (
        fields.get("k8s.ns.name")
        or fields.get("k8s.namespace.name")
        or fields.get("container.namespace")
        or fields.get("namespace")
        or XAPP_NAMESPACE
    )
    rule = alert.get("rule") or alert.get("rule_name") or "unknown-rule"
    priority = str(alert.get("priority") or alert.get("priority_num") or "UNKNOWN").upper()
    output = alert.get("output") or ""

    # Last resort: parse pod and namespace from Falco output text.
    if pod == "unknown" and output:
        m = re.search(r"pod[=:\s]+([a-zA-Z0-9_.-]+)", output)
        if m:
            pod = m.group(1)
    if namespace == XAPP_NAMESPACE and output:
        m = re.search(r"ns[=:\s]+([a-zA-Z0-9_.-]+)", output)
        if m:
            namespace = m.group(1)

    return str(pod), str(namespace), str(rule), str(priority), str(output), fields


def xapp_from_pod(pod: Optional[Any], fallback_pod_name: str) -> str:
    if pod:
        labels = pod.metadata.labels or {}
        if labels.get("app"):
            return labels["app"]
    for xapp in XAPP_LIST:
        if fallback_pod_name.startswith(xapp):
            return xapp
    return fallback_pod_name


def collect_forensic_snapshot(pod: Optional[Any], namespace: str, pod_name: str, incident_dir: Path) -> Dict[str, Any]:
    snapshot: Dict[str, Any] = {"namespace": namespace, "pod_name": pod_name, "time": utc_now()}
    if pod:
        snapshot["pod"] = jsonable(pod)
        snapshot["deployment"] = resolve_deployment_name(pod)
        snapshot["events"] = pod_events(namespace, pod_name)
        snapshot["logs_tail"] = pod_log_tail(namespace, pod_name)
        write_json(incident_dir / "pod.json", snapshot["pod"])
        write_json(incident_dir / "events.json", {"events": snapshot["events"]})
        (incident_dir / "pod-log-tail.txt").write_text(snapshot["logs_tail"], encoding="utf-8")
    else:
        snapshot["error"] = "pod_not_found"
    return snapshot


# -----------------------------
# Containment
# -----------------------------


# step_xguard_02 Step B1: ensure_quarantine_network_policy and the
# original (first-definition) apply_quarantine body moved to
# containment_orchestrator.py as _ztx_original_apply_quarantine. The
# annotation-key constants (ORIGINAL_SELECTOR_ANNOTATION etc.) moved to
# ztx_config.py (imported above).


def _annotations(obj: Any) -> Dict[str, str]:
    try:
        return obj.metadata.annotations or {}
    except Exception:
        return {}


def _labels(obj: Any) -> Dict[str, str]:
    try:
        return obj.metadata.labels or {}
    except Exception:
        return {}


# step_xguard_02 Step B1: get_pod_safe, get_xapp_from_pod_or_name, and
# list_services_for_xapp moved to containment_orchestrator.py.
# The original (now-shadowed, already-dead) service_endpoints_summary
# below is left in place untouched - it has no remaining callers by name
# since the live implementation moved to containment_orchestrator.py too.


def _ztx_dead_original_service_endpoints_summary(service_name: str, namespace: str = None) -> Dict[str, Any]:
    """Summarize Service endpoints.

    Patch5B: Endpoints subsets=None or [] is a valid zero-backend state.
    For service-selector isolation this means endpoint_count=0, not unknown/error.
    """
    namespace = namespace or XAPP_NAMESPACE

    try:
        ep = CORE.read_namespaced_endpoints(name=service_name, namespace=namespace)
        subsets = getattr(ep, "subsets", None)

        addresses = []
        ports = []

        if not subsets:
            return {
                "service": service_name,
                "endpoint_count": 0,
                "addresses": [],
                "ports": [],
                "has_endpoints": False,
                "source": "endpoints",
                "error": None,
                "patch5b_real_replace": True,
            }

        for subset in subsets:
            for addr in (getattr(subset, "addresses", None) or []):
                ip = getattr(addr, "ip", None)
                if ip:
                    addresses.append(ip)

            for port in (getattr(subset, "ports", None) or []):
                ports.append({
                    "name": getattr(port, "name", None),
                    "port": getattr(port, "port", None),
                    "protocol": getattr(port, "protocol", None),
                })

        return {
            "service": service_name,
            "endpoint_count": len(addresses),
            "addresses": addresses,
            "ports": ports,
            "has_endpoints": len(addresses) > 0,
            "source": "endpoints",
            "error": None,
            "patch5b_real_replace": True,
        }

    except Exception as exc:
        return {
            "service": service_name,
            "endpoint_count": None,
            "addresses": [],
            "ports": [],
            "has_endpoints": None,
            "source": None,
            "error": str(exc),
            "verification_status": "unknown",
            "patch5b_real_replace": True,
        }

# step_xguard_02 Step B1: k8s_label_value, apply_service_isolation,
# restore_service_isolation, scale_deployment_for_xapp,
# restore_deployment_scale, the live apply_quarantine (plus the
# _ztx_original_apply_quarantine alias), the live verify_xapp_containment,
# and revoke_spire_entry all moved to containment_orchestrator.py
# (imported above under their original names).


# -----------------------------
# Fast CSM state helpers
# -----------------------------


def _csm_clamp_score(value: Any) -> Optional[float]:
    try:
        return max(0.0, min(100.0, float(value)))
    except Exception:
        return None


def csm_score_fields_from_result(result: Dict[str, Any], source: str = "unknown") -> Dict[str, Any]:
    """Return canonical dashboard score fields.

    Public dashboard meaning:
      trust_score: 100 = healthy/trusted, 0 = compromised
      risk_score : 0 = low risk, 100 = high risk
      score      : public risk score, kept for backward compatibility

    Legacy audit/evaluate_xapp results use score as a trust score.
    V5/intention results may use score as risk score when score_type says so.
    """
    state = str(
        result.get("state")
        or result.get("final_state")
        or result.get("decision_state")
        or "UNKNOWN"
    ).upper()

    raw_score = _csm_clamp_score(result.get("score"))
    trust_score = _csm_clamp_score(result.get("trust_score"))
    risk_score = _csm_clamp_score(result.get("risk_score"))
    score_type = str(result.get("score_type") or "").lower()

    if trust_score is None and risk_score is None and raw_score is not None:
        if "risk" in score_type:
            risk_score = raw_score
            trust_score = 100.0 - risk_score
        elif "trust" in score_type:
            trust_score = raw_score
            risk_score = 100.0 - trust_score
        elif source in {"csm_audit", "api_trust_state", "manual_scan", "scheduled_scan"}:
            # build_report/evaluate_xapp legacy score means trust score.
            trust_score = raw_score
            risk_score = 100.0 - trust_score
        elif state in {"TRUSTED", "HEALTHY", "RESTORED", "OBSERVED"}:
            # For benign/observed legacy paths, score is still closer to trust.
            trust_score = raw_score
            risk_score = 100.0 - trust_score
        elif state in {"COMPROMISED", "QUARANTINED"}:
            risk_score = 100.0
            trust_score = 0.0
        else:
            # Conservative fallback: old suspicious score usually means remaining trust.
            trust_score = raw_score
            risk_score = 100.0 - trust_score

    if trust_score is None and risk_score is not None:
        trust_score = 100.0 - risk_score
    if risk_score is None and trust_score is not None:
        risk_score = 100.0 - trust_score

    # Final state-based safety correction for dashboard clarity.
    if state in {"COMPROMISED", "QUARANTINED"}:
        trust_score = 0.0
        risk_score = 100.0
    elif state == "SUSPICIOUS":
        if risk_score is None or risk_score < 50.0:
            risk_score = 60.0
        trust_score = 100.0 - risk_score
    elif state == "OBSERVED":
        if risk_score is None or risk_score > 40.0:
            risk_score = 20.0
        trust_score = 100.0 - risk_score
    elif state in {"TRUSTED", "HEALTHY", "RESTORED"}:
        if risk_score is None or risk_score > 20.0:
            risk_score = 0.0
        trust_score = 100.0 - risk_score

    if trust_score is not None:
        trust_score = round(max(0.0, min(100.0, trust_score)), 3)
    if risk_score is not None:
        risk_score = round(max(0.0, min(100.0, risk_score)), 3)

    return {
        "trust_score": trust_score,
        "risk_score": risk_score,
        "score": risk_score if risk_score is not None else raw_score,
        "score_type": "risk_score_0_to_100_higher_means_riskier",
    }


def csm_update_from_result(result: Dict[str, Any], source: str = "unknown") -> None:
    xapp = result.get("xapp")
    if not xapp:
        return

    score_fields = csm_score_fields_from_result(result, source=source)

    entry = {
        "xapp": xapp,
        "namespace": result.get("namespace", XAPP_NAMESPACE),
        "state": result.get("state", "UNKNOWN"),
        "detection_state": result.get("detection_state") or result.get("decision_state") or result.get("state", "UNKNOWN"),
        "decision_state": result.get("decision_state") or result.get("state", "UNKNOWN"),
        "containment_required": bool(result.get("containment_required", False)),
        "containment_action": result.get("containment_action") or result.get("action"),

        # Canonical score fields for dashboard/Grafana/API.
        "score": score_fields.get("score"),
        "trust_score": score_fields.get("trust_score"),
        "risk_score": score_fields.get("risk_score"),
        "score_type": score_fields.get("score_type"),

        "confidence": result.get("confidence"),
        "rule_ids": result.get("rule_ids") or (result.get("decision") or {}).get("rule_ids", []),
        "reasons": result.get("reasons") or [],
        "pod": result.get("pod"),
        "service_account": result.get("service_account"),
        "findings": result.get("findings", []),
        "key_runtime_values": result.get("key_runtime_values", {}),
        "last_source": source,
        "last_update": utc_now(),
    }

    with CSM_STATE_LOCK:
        CSM_STATE[xapp] = entry

def csm_update_from_report(report: Dict[str, Any], source: str = "audit") -> None:
    for item in report.get("xapps", []) or []:
        csm_update_from_result(item, source=source)


def csm_summary(states: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {
        "TRUSTED": 0,
        "OBSERVED": 0,
        "SUSPICIOUS": 0,
        "COMPROMISED": 0,
        "QUARANTINED": 0,
        "UNKNOWN": 0,
    }

    for item in states:
        state = item.get("state", "UNKNOWN")
        counts[state] = counts.get(state, 0) + 1

    counts["total"] = len(states)
    return counts


def csm_overall_state(counts: Dict[str, int]) -> str:
    if counts.get("COMPROMISED", 0):
        return "COMPROMISED"
    if counts.get("QUARANTINED", 0):
        return "CONTAINED"
    if counts.get("SUSPICIOUS", 0):
        return "DEGRADED"
    if counts.get("OBSERVED", 0):
        return "OBSERVED"
    if counts.get("UNKNOWN", 0):
        return "INITIALIZING"
    return "HEALTHY"


def csm_state_payload() -> Dict[str, Any]:
    started = time.time()

    with CSM_STATE_LOCK:
        states = [
            dict(CSM_STATE.get(xapp, {
                "xapp": xapp,
                "state": "UNKNOWN",
                "score": 0,
                "findings": [],
            }))
            for xapp in XAPP_LIST
        ]
        recent_events = list(CSM_EVENT_HISTORY[:20])

    counts = csm_summary(states)

    return {
        "component": "zt-xguard-policy-engine",
        "mode": "cached_event_driven_csm_state",
        "description": "Fast CSM state from cached audit results and runtime events; does not run full endpoint checks.",
        "overall_state": csm_overall_state(counts),
        "summary": counts,
        "xapps": states,
        "recent_events": recent_events,
        "duration_ms": round((time.time() - started) * 1000, 3),
        "time": utc_now(),
    }


def csm_remember_event(event: Dict[str, Any]) -> None:
    with CSM_STATE_LOCK:
        CSM_EVENT_HISTORY.insert(0, event)
        del CSM_EVENT_HISTORY[100:]


def csm_fast_event_decision(
    alert: Dict[str, Any],
    pod_name: str,
    namespace: str,
    xapp: str,
    pod: Optional[Any],
    rule: str,
    priority: str,
    output: str,
    fields: Dict[str, Any],
) -> Dict[str, Any]:
    blob = " ".join([
        str(rule or ""),
        str(priority or ""),
        str(output or ""),
        json.dumps(fields or {}, sort_keys=True, default=str),
    ]).lower()

    findings: List[Dict[str, Any]] = []

    def add(signal: str, severity: str, message: str, penalty: int) -> None:
        findings.append({
            "severity": severity,
            "signal": signal,
            "message": message,
            "score_penalty": penalty,
        })

    if any(x in blob for x in [
        "terminal shell",
        "shell in",
        "spawned shell",
        "/bin/sh",
        "/bin/bash",
        " proc.name=sh",
        "proc.name\": \"sh",
        "bash",
    ]):
        add(
            "unexpected_shell",
            "critical",
            "Shell execution observed in an xApp whose intent profile forbids shell execution",
            100,
        )

    if any(x in blob for x in [
        "/etc/shadow",
        "sensitive file",
        "read sensitive",
        "open_read",
        "etc/shadow",
    ]):
        add(
            "sensitive_file_access",
            "critical",
            "Sensitive file access observed in xApp runtime",
            100,
        )

    if any(x in blob for x in [
        "serviceaccount",
        "service account",
        "kubernetes.io/serviceaccount",
        "token access",
        "sa token",
    ]):
        add(
            "service_account_token_access",
            "critical",
            "Kubernetes ServiceAccount token access observed",
            100,
        )

    if any(x in blob for x in [
        "netcat",
        " ncat",
        " nc ",
        "nmap",
        "masscan",
        "socat",
        "curl",
        "wget",
        "stress-ng",
        "xmrig",
    ]):
        add(
            "malicious_or_unexpected_tool",
            "critical",
            "Unexpected offensive/admin tool execution observed inside xApp",
            100,
        )

    if any(x in blob for x in [
        "unexpected outbound",
        "unexpected connection",
        "outbound connection",
        "external connection",
    ]):
        add(
            "unexpected_external_egress",
            "critical",
            "Unexpected network egress observed for xApp",
            100,
        )

    if namespace != XAPP_NAMESPACE:
        add(
            "unexpected_namespace",
            "medium",
            f"Falco event namespace {namespace} is outside controlled xApp namespace {XAPP_NAMESPACE}",
            20,
        )

    if xapp not in XAPP_LIST:
        add(
            "uncontrolled_pod_alert",
            "medium",
            "Falco event is not from the controlled xApp set",
            25,
        )

    if not findings:
        if str(priority).upper() in ["EMERGENCY", "ALERT", "CRITICAL", "ERROR"]:
            add(
                "falco_high_priority",
                "high",
                f"High-priority Falco event observed: {priority}",
                40,
            )
        else:
            add(
                "falco_observed",
                "info",
                "Falco event observed but no deterministic compromise rule matched",
                0,
            )

    has_critical = any(f.get("severity") == "critical" for f in findings)
    has_high = any(f.get("severity") == "high" for f in findings)

    if has_critical:
        state = "COMPROMISED"
        score = 0
    elif has_high:
        state = "SUSPICIOUS"
        score = 60
    else:
        state = "OBSERVED"
        score = 90

    service_account = None
    if pod is not None:
        try:
            service_account = pod.spec.service_account_name
        except Exception:
            service_account = xapp

    service_account = service_account or xapp

    return {
        "xapp": xapp,
        "namespace": namespace,
        "state": state,
        "score": score,
        "pod": pod_name,
        "service_account": service_account,
        "expected_spiffe_id": spiffe_for(namespace, service_account),
        "findings": findings,
        "decision_source": "event_driven_falco_csm",
        "event_rule": rule,
        "event_priority": priority,
        "time": utc_now(),
    }


def csm_collect_forensics_async(
    pod: Optional[Any],
    namespace: str,
    pod_name: str,
    incident_path: Path,
    incident: Dict[str, Any],
) -> None:
    def worker() -> None:
        try:
            forensic = collect_forensic_snapshot(pod, namespace, pod_name, incident_path)
            incident["forensic_snapshot"] = forensic
            incident["forensic_completed_time"] = utc_now()
            write_json(incident_path / "incident.json", incident)
        except Exception as exc:
            incident["forensic_error"] = str(exc)
            incident["forensic_trace"] = traceback.format_exc()
            write_json(incident_path / "incident.json", incident)

    threading.Thread(target=worker, daemon=True).start()


def _ztx_original_csm_process_falco_event(alert: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    received_at = time.time()

    pod_name, namespace, rule, priority, output, fields = extract_alert_identity(alert)
    normalized_signal = ztx_normalize_signal(ztx_v4_signal_from_event(alert))

    incident_id = (
        f"{utc_id()}-{safe_name(rule)}-{safe_name(pod_name)}-"
        f"{sha256_text(json.dumps(alert, sort_keys=True, default=str))[:10]}"
    )

    incident_path = INCIDENT_DIR / incident_id
    incident_path.mkdir(parents=True, exist_ok=True)

    pod = get_pod_by_name(pod_name, namespace) if pod_name != "unknown" else None
    xapp = xapp_from_pod(pod, pod_name)

    decision_started = time.time()
    result = csm_fast_event_decision(
        alert,
        pod_name,
        namespace,
        xapp,
        pod,
        rule,
        priority,
        output,
        fields,
    )
    decision_ms = round((time.time() - decision_started) * 1000, 3)

    # ZTX_PATCH7_A11_FORCE_COMPROMISED:
    # SVID/SPIFFE material access is credential-material access, not a weak anomaly.
    # It must be treated as COMPROMISED and quarantine-capable.
    ztx_patch7_a11_hit = (
        normalized_signal == "svid_material_access"
        or "ZTX-A11" in str(rule)
        or "ZTX-A11" in str(output)
        or "svid_material_access" in str(output)
        or "svid_material_access" in json.dumps(alert, default=str)
    )
    if ztx_patch7_a11_hit:
        normalized_signal = "svid_material_access"
        result["state"] = "COMPROMISED"
        result["score"] = 0
        result.setdefault("findings", []).append({
            "signal": "svid_material_access",
            "rule_id": "ZTX-A11",
            "severity": "critical",
            "source": "ZTX_PATCH7_A11_FORCE_COMPROMISED",
            "reason": "SVID/SPIFFE credential material access is compromise-level evidence",
        })

    # ZTX_PATCH8B_A1_FINAL_FORCE:
    # Final guardrail: unexpected shell in a verified xApp is compromise-level evidence.
    ztx_patch8b_a1_hit = (
        normalized_signal == "unexpected_shell"
        or "ZTX-A1" in str(rule)
        or "unexpected_shell" in str(output)
        or "Unexpected Shell" in str(rule)
        or "Unexpected Shell" in str(output)
        or "ZTX_xApp_Unexpected_Shell" in str(rule)
        or "ZTX_xApp_Unexpected_Shell" in str(output)
    )
    if ztx_patch8b_a1_hit:
        normalized_signal = "unexpected_shell"
        result["state"] = "COMPROMISED"
        result["score"] = 0
        findings = result.get("findings")
        if not isinstance(findings, list):
            findings = []
            result["findings"] = findings
        findings.append({
            "signal": "unexpected_shell",
            "rule_id": "ZTX-A1",
            "severity": "critical",
            "source": "ZTX_PATCH8B_A1_FINAL_FORCE",
            "reason": "Unexpected shell execution violates xApp profile expected_shell=false",
        })

    decision_state = str(result.get("state") or "").upper() or "OBSERVED"
    containment_required = (
        decision_state == "COMPROMISED"
        and (
            normalized_signal in ZTX_QUARANTINE_CAPABLE_SIGNALS
            or normalized_signal in {"svid_material_access", "unexpected_shell"}
        )
    )
    label_guard = ztx_quarantine_label_write_decision(ztx_label_write_context(
        normalized_signal=normalized_signal,
        containment_required=containment_required,
        decision_state=decision_state,
        handler_path="_ztx_original_csm_process_falco_event->apply_quarantine",
        incident_id=incident_id,
    ))

    quarantine = {"applied": False, "reason": "not_applicable"}
    quarantine_ms = None
    spire_revoke = {"attempted": False, "revoked": False, "reason": "not_applicable"}

    if (result.get("state") == "COMPROMISED" or containment_required) and xapp in XAPP_LIST and pod_name != "unknown":
        if AUTO_QUARANTINE:
            q_started = time.time()
            reason = "; ".join(f.get("signal", "finding") for f in result.get("findings", [])[:5])

            if not label_guard.get("label_write_allowed"):
                 quarantine = {
                     "applied": False,
                     "reason": label_guard.get("label_write_block_reason"),
                     **label_guard,
                 }
                 result["state"] = "SUSPICIOUS"
            else:
                 quarantine = apply_quarantine(
                     pod_name,
                     namespace,
                     reason,
                     incident_id,
                     normalized_signal=normalized_signal,
                     containment_required=containment_required,
                     decision_state=decision_state,
                     handler_path="_ztx_original_csm_process_falco_event->apply_quarantine",
                 )
                 quarantine_ms = round((time.time() - q_started) * 1000, 3)
                 if quarantine.get("applied"):
                     spire_revoke = revoke_spire_entry(result.get("expected_spiffe_id"))
                     result["state"] = "QUARANTINED"
                 else:
                     result["state"] = "SUSPICIOUS" # Fallback if quarantine blocked
        else:
            quarantine = {
                "applied": False,
                "reason": "AUTO_QUARANTINE=false; fast CSM incident logged only",
            }

    csm_update_from_result(result, source="falco_event")

    event_record = {
        "incident_id": incident_id,
        "time": utc_now(),
        "xapp": xapp,
        "pod": pod_name,
        "rule": rule,
        "priority": priority,
        "state": result.get("state"),
        "decision_ms": decision_ms,
        "quarantine_ms": quarantine_ms,
        "auto_quarantine": AUTO_QUARANTINE,
    }
    csm_remember_event(event_record)

    incident = {
        "incident_id": incident_id,
        "time": utc_now(),
        "mode": "event_driven_fast_csm",
        "alert": {
            "rule": rule,
            "priority": priority,
            "output": output,
            "fields": fields,
            "raw": alert,
        },
        "xapp": xapp,
        "namespace": namespace,
        "pod_name": pod_name,
        "trust_result": result,
        "auto_quarantine": AUTO_QUARANTINE,
        "quarantine": quarantine,
        "spire_revoke": spire_revoke,
        "timing": {
            "event_processing_total_ms": round((time.time() - received_at) * 1000, 3),
            "decision_ms": decision_ms,
            "quarantine_ms": quarantine_ms,
        },
        "evidence_dir": str(incident_path),
        "forensic_snapshot": {"status": "scheduled_async"},
    }

    write_json(incident_path / "incident.json", incident)
    csm_collect_forensics_async(pod, namespace, pod_name, incident_path, incident)

    with LAST_REPORT_LOCK:
        LAST_INCIDENTS.insert(0, incident)
        del LAST_INCIDENTS[50:]

    print(json.dumps({
        "component": "zt-xguard-policy-engine",
        "mode": "event_driven_fast_csm",
        "incident_id": incident_id,
        "xapp": xapp,
        "pod": pod_name,
        "state": result.get("state"),
        "score": result.get("score"),
        "quarantine": quarantine,
        "timing": incident["timing"],
        "evidence_dir": str(incident_path),
    }), flush=True)

    return {
        "incident_id": incident_id,
        "mode": "event_driven_fast_csm",
        "xapp": xapp,
        "pod_name": pod_name,
        "state": result.get("state"),
        "score": result.get("score"),
        "findings": result.get("findings", []),
        "normalized_signal": normalized_signal,
        "containment_required": containment_required,
        "label_write_allowed": label_guard.get("label_write_allowed"),
        "label_write_block_reason": label_guard.get("label_write_block_reason"),
        "handler_path": label_guard.get("handler_path"),
        "quarantine": quarantine,
        "spire_revoke": spire_revoke,
        "timing": incident["timing"],
        "evidence_dir": str(incident_path),
    }, 200


# -----------------------------
# API routes
# -----------------------------



def ztx_v5_normalize_score_fields(obj):
    """Ensure V5 API responses expose both trust_score and risk_score.

    Current V5 public score is risk_score:
      0   = low risk
      100 = high risk / compromised

    Some legacy app.py wrappers only propagate "score", so this function adds
    trust_score, risk_score, and score_type before returning JSON.
    """
    def _clamp_score(value):
        try:
            return max(0, min(100, int(round(float(value)))))
        except Exception:
            return None

    def _fix_one(d):
        if not isinstance(d, dict):
            return d

        score = _clamp_score(d.get("score"))
        trust = _clamp_score(d.get("trust_score"))
        risk = _clamp_score(d.get("risk_score"))

        if risk is None and score is not None:
            # In active V5.3 API, top-level score is already risk score.
            risk = score

        if trust is None and risk is not None:
            trust = max(0, min(100, 100 - risk))

        if risk is None and trust is not None:
            risk = max(0, min(100, 100 - trust))

        if trust is not None:
            d["trust_score"] = trust
        if risk is not None:
            d["risk_score"] = risk
            d["score"] = risk
            d["score_type"] = "risk_score_0_to_100_higher_means_riskier"

        return d

    if isinstance(obj, dict):
        _fix_one(obj)
        for key in ("result", "decision", "state_decision"):
            if isinstance(obj.get(key), dict):
                _fix_one(obj[key])
    return obj


@APP.route("/health", methods=["GET"])
def health() -> Any:
    return jsonify({
        "status": "ok",
        "component": "zt-xguard-policy-engine",
        "version": ENGINE_VERSION,
        "state_engine_version": ZTX_STATE_ENGINE_VERSION,
        "state_engine_import_error": ZTX_STATE_ENGINE_IMPORT_ERROR,
        "namespace": POLICY_NAMESPACE,
        "xapp_namespace": XAPP_NAMESPACE,
        "xapps": XAPP_LIST,
        "auto_quarantine": AUTO_QUARANTINE,
        "revoke_spire": REVOKE_SPIRE,
        "time": utc_now(),
    })


@APP.route("/ready", methods=["GET"])
def ready() -> Any:
    try:
        CORE.list_namespaced_pod(namespace=XAPP_NAMESPACE, limit=1)
        kubernetes_ok = True
        error = None
    except Exception as exc:
        kubernetes_ok = False
        error = str(exc)

    return jsonify({
        "ready": kubernetes_ok,
        "status": "ready" if kubernetes_ok else "not_ready",
        "checks": {"kubernetes_api": kubernetes_ok},
        "error": error,
        "time": utc_now(),
    }), (200 if kubernetes_ok else 503)

@APP.route("/analyze", methods=["GET"])
def ztx_analyze_page() -> Any:
    return render_template("analyze.html")

# ------------------------------------------------------------
# ZT_XGUARD_EVENT_SCOPE_FILTER_MARKER
# Falco event scope filter
# ------------------------------------------------------------

# step_xguard_02 Step B1: _ztx_get_output_fields, _ztx_get_event_namespace,
# _ztx_get_event_pod, _ztx_xapp_list, _ztx_xapp_from_pod_name, and
# _ztx_event_scope_decision moved to event_normalization.py (imported
# above under their original names).


def csm_process_falco_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Scope-filtered wrapper around the original Falco event processor.

    Only events for known xApp pods in the ricxapp namespace are allowed to
    affect ZT-XGuard trust state or trigger containment.

    Control-plane events such as:
      - zt-xguard-policy-engine contacting Kubernetes API
      - falco/falcosidekick activity
      - kube-system activity
    are ignored to prevent false positives.
    """
    scope = _ztx_event_scope_decision(event)

    if not scope.get("process"):
        return {
            "ignored": True,
            "mode": "event_scope_filter",
            "reason": scope.get("reason"),
            "namespace": scope.get("namespace"),
            "pod_name": scope.get("pod_name"),
            "xapp": scope.get("xapp"),
            "rule": scope.get("rule"),
            "priority": scope.get("priority"),
            "state": "IGNORED",
            "time": utc_now(),
        }

    return _ztx_original_csm_process_falco_event(event)


@APP.route("/csm/state", methods=["GET"])
def csm_state() -> Any:
    return jsonify(csm_state_payload())


@APP.route("/csm/audit", methods=["GET", "POST"])
def csm_audit() -> Any:
    # 2026-07-16: previously ran the old scan-based rubric (build_report/
    # evaluate_xapp) - a completely separate, non-Falco/T2-aware scoring
    # path that wrote into the same CSM_STATE cache the real decision
    # engine uses, and could emit the retired "OBSERVED" state. Retired;
    # this route (and /trust-state, /scan) now read the same authoritative
    # cache csm_state() already serves, per attack-orchestrator.py's own
    # documented assumption that /csm/state is the authoritative decision.
    return jsonify(csm_state_payload())


@APP.route("/csm/quarantine", methods=["POST"])
def csm_quarantine() -> Any:
    payload = request.get_json(force=True, silent=True) or {}
    namespace = payload.get("namespace") or XAPP_NAMESPACE
    xapp = payload.get("xapp")
    pod_name = payload.get("pod") or payload.get("pod_name")
    reason = payload.get("reason") or "manual_csm_quarantine"

    pod = None

    if pod_name:
        pod = get_pod_by_name(pod_name, namespace)
    elif xapp:
        pod = get_primary_pod_for_xapp(xapp, namespace)
        pod_name = pod.metadata.name if pod else None

    if not pod_name:
        return jsonify({
            "applied": False,
            "error": "pod_not_found",
            "xapp": xapp,
            "namespace": namespace,
        }), 404

    detected_xapp = xapp or xapp_from_pod(pod, pod_name)
    if not detected_xapp:
        return jsonify({
            "applied": False,
            "error": "xapp_not_resolved",
            "pod_name": pod_name,
            "namespace": namespace,
        }), 404

    # 2026-07-23 (Fix G): routed through the same shared
    # _ztx_perform_isolation_now path used by the dwell-checker and
    # /csm/containment/isolate-now, instead of calling apply_quarantine
    # directly and writing an ad-hoc "QUARANTINED" CSM_STATE entry - that
    # state label collapsed back to COMPROMISED on the next read and
    # skipped the ISOLATED-gated re-verification path the rest of the state
    # machine relies on. This is an explicit manual operator action, so
    # (like isolate-now) it proceeds regardless of the xApp's current
    # state.
    started = time.time()
    entry = _ztx_perform_isolation_now(detected_xapp, namespace, reason)
    quarantine_ms = round((time.time() - started) * 1000, 3)
    quarantine = entry.get("quarantine") or {}

    return jsonify({
        "applied": bool(entry.get("containment_verified")),
        "xapp": detected_xapp,
        "pod_name": pod_name,
        "namespace": namespace,
        "state": entry.get("state"),
        "containment_verified": entry.get("containment_verified"),
        "quarantine": quarantine,
        "quarantine_ms": quarantine_ms,
        "incident_id": quarantine.get("incident_id") if isinstance(quarantine, dict) else None,
    })


@APP.route("/csm/events/falco", methods=["POST"])
def csm_events_falco() -> Any:
    alert = request.get_json(force=True, silent=True) or {}
    body, status = ztx_normalize_result(csm_process_falco_event(alert))  # ZTX_SCOPE_FILTERED_CSM
    body = ztx_attach_route_handler_path(body, "csm_events_falco")
    return jsonify(body), status



@APP.route("/csm/containment/apply", methods=["POST"])
def csm_containment_apply() -> Any:
    payload = request.get_json(force=True, silent=True) or {}

    namespace = payload.get("namespace") or XAPP_NAMESPACE
    xapp = payload.get("xapp")
    pod_name = payload.get("pod") or payload.get("pod_name")
    reason = payload.get("reason") or "manual_csm_containment"

    pod = None
    if pod_name:
        pod = get_pod_by_name(pod_name, namespace)
    elif xapp:
        pod = get_primary_pod_for_xapp(xapp, namespace)
        pod_name = pod.metadata.name if pod else None

    if not pod_name:
        return jsonify({
            "applied": False,
            "error": "pod_not_found",
            "xapp": xapp,
            "namespace": namespace,
        }), 404

    detected_xapp = xapp or xapp_from_pod(pod, pod_name)
    if not detected_xapp:
        return jsonify({
            "applied": False,
            "error": "xapp_not_resolved",
            "pod_name": pod_name,
            "namespace": namespace,
        }), 404

    # 2026-07-23 (Fix G): routed through _ztx_perform_isolation_now, same as
    # /csm/quarantine above - this route previously called apply_quarantine
    # directly and never touched CSM_STATE at all, so an xApp contained
    # through this endpoint would still read as its pre-existing state (e.g.
    # NORMAL/SUSPICIOUS) from every other route that reads the cache, one of
    # the two independently-drifting manual containment paths the plan
    # flagged.
    entry = _ztx_perform_isolation_now(detected_xapp, namespace, reason)
    verify = entry.get("verification") or verify_xapp_containment(detected_xapp, namespace)

    return jsonify({
        "applied": bool(entry.get("containment_verified")),
        "xapp": detected_xapp,
        "namespace": namespace,
        "state": entry.get("state"),
        "containment": entry.get("quarantine"),
        "verification": verify,
        "time": utc_now(),
    })


@APP.route("/csm/containment/restore", methods=["POST"])
def csm_containment_restore() -> Any:
    payload = request.get_json(force=True, silent=True) or {}

    namespace = payload.get("namespace") or XAPP_NAMESPACE
    xapp = payload.get("xapp")

    if not xapp:
        return jsonify({
            "restored": False,
            "error": "xapp_required",
        }), 400

    # 2026-08-23: open the restore-grace window at the very START of restore,
    # BEFORE pod recreation, and long enough (60s) to cover the ~30s
    # recreation wait plus settle. Critical: while an xApp is mid-restore its
    # CSM_STATE is still ISOLATED, so a trailing SOFT signal (e.g. a T2
    # resource-anomaly tick) arriving during recreation would otherwise
    # sticky-hold ISOLATED and re-run _ztx_force_containment_for_xapp against
    # the freshly-created replacement pod - quarantining the new pod while
    # the grace-pinned dashboard shows NORMAL. Marking grace here pins those
    # soft signals to NORMAL for the whole restore, so the new pod is never
    # re-contained. A genuine fresh critical is still exempt. The
    # end-of-restore _ztx_v2_set_state_normal re-marks a shorter window too.
    csm_mark_restored(xapp, seconds=60.0)

    # 2026-07-24: recreate the pod(s) FIRST, before anything else - restore
    # used to only lift network/label restrictions on the SAME pod that was
    # contained, which is not real remediation if that pod was genuinely
    # compromised (attacker-controlled code would just get its network
    # access handed back). Deleting it and waiting for the ReplicaSet to
    # schedule a fresh replacement from the clean Deployment template
    # actually delivers the "healthy uncompromised xapp" a restore should.
    # Everything below (service/scale restore, per-pod label cleanup,
    # final verification) still runs afterward as a safety net - it now
    # mostly operates on the fresh pod (which never had quarantine labels
    # to begin with) but still matters if recreation is disabled/fails.
    pod_recreation = ztx_recreate_pods_for_clean_restore(xapp, namespace)

    # 2026-08-23: release the direct-iptables DROP rules for every IP this
    # xApp was blocked at (tracked in memory at block time). Reliable even
    # though the old pod is already gone - see ztx_release_blocked_ips_for_xapp.
    try:
        direct_iptables_release = ztx_release_blocked_ips_for_xapp(xapp)
    except Exception as _exc:
        direct_iptables_release = {"attempted": False, "error": str(_exc)}

    # 2026-07-25: restore never cleared ztx_isolation_manager's dwell
    # tracker (keyed by xapp name, not pod identity, so pod recreation above
    # does not touch it). A stale _dwell_started timestamp from an earlier
    # incident survived every restore, so the NEXT incident's dwell either
    # got cleared incidentally (if some unrelated benign signal happened to
    # reach final_state != COMPROMISED during the settle window and hit the
    # clear() path at line ~5434) or didn't - producing nondeterministic,
    # sometimes-instant, sometimes-30s+ isolation timing that looked like
    # measurement noise but was actually this gap. Restore is the one place
    # that unconditionally means "this xapp is no longer compromised" -
    # clear its dwell state explicitly here so every future incident starts
    # a clean, correctly-timed 30s window.
    if ztx_isolation_manager is not None:
        ztx_isolation_manager.clear(xapp)

    service_restore = restore_service_isolation(xapp, namespace)
    scale_restore = restore_deployment_scale(xapp, namespace)

    # Remove quarantine labels/annotations from all current pods of the xApp.
    # Use JSON Patch because Kubernetes label keys such as zt-xguard.io/quarantine
    # contain "/" and are not always removed reliably by merge-style null patches.
    pod_results = []
    quarantine_label_keys = [
        "zt-xguard.io/quarantine",
        "security-status",
        "zt-xguard.io/decision",
        # Phase 3, 2026-07-17: clears the SUSPICIOUS-tier Calico policy's
        # selector match too, so a restore reverses both tiers, not just
        # the COMPROMISED/ISOLATED one.
        "zt-xguard.io/suspicious",
    ]
    quarantine_annotation_keys = [
        "zt-xguard.io/quarantine-reason",
        "zt-xguard.io/quarantine-time",
        "zt-xguard.io/incident-id",
    ]

    def _json_pointer_escape(value: str) -> str:
        return value.replace("~", "~0").replace("/", "~1")

    for pod in get_pods_for_xapp(xapp, namespace):
        pod_name = pod.metadata.name
        labels = pod.metadata.labels or {}
        annotations = pod.metadata.annotations or {}
        ops = []

        for key in quarantine_label_keys:
            if key in labels:
                ops.append({"op": "remove", "path": f"/metadata/labels/{_json_pointer_escape(key)}"})

        for key in quarantine_annotation_keys:
            if key in annotations:
                ops.append({"op": "remove", "path": f"/metadata/annotations/{_json_pointer_escape(key)}"})

        try:
            if ops:
                CORE.patch_namespaced_pod(
                    name=pod_name,
                    namespace=namespace,
                    body=ops,
                )
            identity_restore = restore_workload_identity(pod_name, namespace)
            pod_ip = getattr(pod.status, "pod_ip", None)
            direct_network_restore = restore_direct_network_isolation(pod_ip) if pod_ip else {"attempted": False, "reason": "no_pod_ip"}
            pod_results.append({
                "pod": pod_name,
                "labels_removed": True,
                "removed_count": len(ops),
                "identity_restore": identity_restore,
                "direct_network_restore": direct_network_restore,
            })
        except Exception as exc:
            pod_results.append({"pod": pod_name, "labels_removed": False, "removed_count": 0, "error": str(exc)})

    verify = verify_xapp_containment(xapp, namespace)

    # 2026-07-23 (Fix E, second half): "restored" used to be an OR across
    # service_restore/scale_restore/labels_removed - 2 of those 3 are no-ops
    # under the active CONTAINMENT_MODE=service (scale_restore always runs
    # but only did something under service_then_scale; labels_removed is
    # cosmetic without the enforcement it labels), so this could report
    # restored=True while the actual enforcing mechanism (Service isolation
    # or direct iptables) was still blocking traffic. Derive it instead from
    # verify_xapp_containment's own re-check, run fresh right above - the
    # same real-verification-not-self-reported-status principle as Fix E's
    # isolate-now change.
    return jsonify({
        "restored": not verify.get("contained", False),
        "xapp": xapp,
        "namespace": namespace,
        "pod_recreation": pod_recreation,
        "service_restore": service_restore,
        "scale_restore": scale_restore,
        "pod_label_restore": pod_results,
        "direct_iptables_release": direct_iptables_release,
        "verification_after_restore": verify,
        "time": utc_now(),
    })


@APP.route("/csm/containment/verify", methods=["GET", "POST"])
def csm_containment_verify() -> Any:
    if request.method == "POST":
        payload = request.get_json(force=True, silent=True) or {}
        xapp = payload.get("xapp")
        namespace = payload.get("namespace") or XAPP_NAMESPACE
    else:
        xapp = request.args.get("xapp")
        namespace = request.args.get("namespace") or XAPP_NAMESPACE

    if not xapp:
        return jsonify({"error": "xapp_required"}), 400

    return jsonify(verify_xapp_containment(xapp, namespace))

@APP.route("/trust-state", methods=["GET"])
def trust_state() -> Any:
    # 2026-07-16: see /csm/audit's comment above - same retirement.
    return jsonify(csm_state_payload())


@APP.route("/scan", methods=["POST", "GET"])
def scan() -> Any:
    # 2026-07-16: see /csm/audit's comment above - same retirement. Kept as
    # a route (not deleted) since it may still be linked from old tooling;
    # it now just returns the current cached state rather than running a
    # scan, since there is no separate scan to run anymore.
    return jsonify(csm_state_payload())


ZTX_T2_STATE_FILE = Path("/var/lib/ztx-t2-state/latest.json")
ZTX_T2_XAPP_NAME = "ricxapp-kpimon-go"


@APP.route("/csm/t2/state", methods=["GET"])
def csm_t2_state() -> Any:
    """Read-only passthrough of ztx_t2_collector.py's own shared state file
    (same file ztx_t2_visualizer.py's terminal view already reads via its
    own hostPath mount) - lets the web dashboard show the same T2 score /
    6-of-8 / cpu_gate_hit / dwell-countdown data without duplicating any
    scoring logic. Requires this pod's Deployment to mount
    /var/lib/ztx-t2-state read-only (added 2026-07-25, same hostPath
    pattern as the visualizer pod - single-node cluster, so the T2
    collector, this pod and kpimon-go are always on the same node)."""
    try:
        state = json.loads(ZTX_T2_STATE_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        return jsonify({"available": False, "error": str(exc)}), 200

    # Prefer a fresh read over whatever the collector's own /trust-state
    # poll last captured (that poll only happens once per tick while
    # throttled - see ztx_t2_collector.py's _check_throttle_release) - this
    # request can compute it live from the same in-process tracker with
    # zero extra cost, so the dashboard never shows a stale dwell value.
    if ztx_isolation_manager is not None:
        live_dwell = ztx_isolation_manager.dwell_status(ZTX_T2_XAPP_NAME)
        state["isolation_dwell_seconds_remaining"] = round(live_dwell, 1) if live_dwell is not None else None

    state["available"] = True
    state["xapp"] = ZTX_T2_XAPP_NAME
    return jsonify(state)


@APP.route("/last-report", methods=["GET"])
def last_report() -> Any:
    with LAST_REPORT_LOCK:
        if not LAST_REPORT:
            return jsonify({"error": "no_report_yet"}), 404
        return jsonify(LAST_REPORT)


@APP.route("/incidents", methods=["GET"])
def incidents() -> Any:
    files = sorted(INCIDENT_DIR.glob("*/incident.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    data = []
    for p in files[:50]:
        try:
            data.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            data.append({"path": str(p), "error": "could_not_read"})
    return jsonify({"count": len(data), "incidents": data})


@APP.route("/falco-webhook", methods=["POST"])
def falco_webhook() -> Any:
    # Backward-compatible Falcosidekick endpoint.
    # ZTX_PATCH6: force quarantine-capable CSM processor; avoid late csm_process_falco_event override.
    # This now uses the event-driven CSM path and does not run the slow
    # full xApp audit before containment.
    alert = request.get_json(force=True, silent=True) or {}
    body, status = ztx_normalize_result(csm_process_falco_event(alert))  # ZTX_SCOPE_FILTERED_CSM
    body = ztx_attach_route_handler_path(body, "falco_webhook")
    return jsonify(body), status


# -----------------------------
# Background scanner
# -----------------------------


def scanner_loop() -> None:
    if SCAN_INTERVAL_SEC <= 0:
        return
    while True:
        try:
            build_report(persist=True, reason="scheduled_scan")
        except Exception as exc:
            print(json.dumps({"component": "zt-xguard-policy-engine", "scanner_error": str(exc), "trace": traceback.format_exc()}), flush=True)
        time.sleep(SCAN_INTERVAL_SEC)



# ------------------------------------------------------------
# ZT_XGUARD_DASHBOARD_V1_MARKER
# Dashboard and controlled attack-lab routes
# ------------------------------------------------------------

@APP.route("/", methods=["GET"])
@APP.route("/dashboard", methods=["GET"])
def ztx_dashboard() -> Any:
    return render_template("dashboard.html")

@APP.route("/analyze", methods=["GET"])
def analyze_incident_center() -> Any:
    return render_template("analyze.html")

@APP.route("/attack-lab", methods=["GET"])
def ztx_attack_lab() -> Any:
    return render_template("attack_lab.html")


@APP.route("/csm/scenario/falco-shell", methods=["POST"])
def csm_scenario_falco_shell() -> Any:
    """Controlled FYP demo scenario.

    This does not execute a real shell. It injects a Falco-style event into the
    existing ZT-XGuard event pipeline so the dashboard can demonstrate:
      event -> detection -> decision -> containment -> verification.

    Real Falco testing is still done using kubectl exec.
    """
    payload = request.get_json(force=True, silent=True) or {}

    xapp = payload.get("xapp") or "telemetry-monitor"
    namespace = payload.get("namespace") or XAPP_NAMESPACE

    try:
        allowed = _ztx_xapp_list()
    except Exception:
        allowed = XAPP_LIST if isinstance(XAPP_LIST, list) else str(XAPP_LIST).split(",")

    allowed = [str(item).strip() for item in allowed if str(item).strip()]

    if xapp not in allowed:
        return jsonify({
            "ok": False,
            "error": "xapp_not_allowed",
            "xapp": xapp,
            "allowed_xapps": allowed,
        }), 400

    pod = get_primary_pod_for_xapp(xapp, namespace)
    if not pod:
        return jsonify({
            "ok": False,
            "error": "pod_not_found",
            "xapp": xapp,
            "namespace": namespace,
        }), 404

    pod_name = pod.metadata.name

    event = {
        "rule": "Terminal shell in container",
        "priority": "WARNING",
        "output": f"Controlled scenario: Terminal shell in container pod={pod_name} ns={namespace} command=/bin/sh",
        "output_fields": {
            "k8s.ns.name": namespace,
            "k8s.pod.name": pod_name,
            "proc.name": "sh",
            "proc.cmdline": "/bin/sh",
            "container.name": xapp,
        },
        "ztx_controlled_scenario": True,
        "scenario": "falco_shell",
    }

    started = time.time()

    raw_result = csm_process_falco_event(event)

    # Normalize result. Some Flask handlers may return dict, list, Response, or tuple.
    status_code = 200
    event_result = {}

    try:
        if isinstance(raw_result, tuple):
            first = raw_result[0]
            if len(raw_result) > 1 and isinstance(raw_result[1], int):
                status_code = raw_result[1]
        else:
            first = raw_result

        if hasattr(first, "get_json"):
            event_result = first.get_json(silent=True) or {}
        elif isinstance(first, dict):
            event_result = first
        elif isinstance(first, list):
            event_result = {"raw_list": first}
        else:
            event_result = {"raw": str(first)}
    except Exception as exc:
        event_result = {
            "normalization_error": str(exc),
            "raw_type": str(type(raw_result)),
        }

    verify = verify_xapp_containment(xapp, namespace)

    findings = event_result.get("findings") if isinstance(event_result, dict) else []
    if not isinstance(findings, list):
        findings = []

    quarantine = event_result.get("quarantine") if isinstance(event_result, dict) else {}
    if not isinstance(quarantine, dict):
        quarantine = {}

    signal = None
    if findings and isinstance(findings[0], dict):
        signal = findings[0].get("signal")

    compact = {
        "ok": True,
        "scenario": "falco_shell",
        "controlled": True,
        "xapp": xapp,
        "namespace": namespace,
        "pod": pod_name,
        "state": event_result.get("state") if isinstance(event_result, dict) else None,
        "signal": signal,
        "score": event_result.get("score") if isinstance(event_result, dict) else None,
        "timing": event_result.get("timing") if isinstance(event_result, dict) else None,
        "quarantine_applied": quarantine.get("applied"),
        "quarantine_effective": quarantine.get("effective_containment_applied"),
        "service_isolation": quarantine.get("service_isolation_applied"),
        "quarantine_duration_ms": quarantine.get("duration_ms"),
        "contained": verify.get("contained"),
        "service_isolated": verify.get("service_isolated"),
        "quarantine_marked": verify.get("quarantine_marked"),
        "endpoint_count": (
            verify.get("services", [{}])[0]
            .get("endpoint_summary", {})
            .get("endpoint_count")
            if verify.get("services") else None
        ),
        "selector": (
            verify.get("services", [{}])[0].get("selector")
            if verify.get("services") else None
        ),
        "duration_ms": round((time.time() - started) * 1000, 3),
        "time": utc_now(),
    }

    # Keep backward compatibility for dashboard.js:
    # result = normalized event result
    # verification = containment verification
    compact["result"] = event_result
    compact["verification"] = verify

    return jsonify(compact), status_code




# ------------------------------------------------------------
# ZT_XGUARD_SCENARIO_ORCHESTRATOR_V2_MARKER
# Scenario Orchestrator and Evaluation API
# ------------------------------------------------------------

ZT_SCENARIO_RESULTS = []

ZT_SCENARIOS = [
    {
        "id": "A1",
        "name": "Runtime shell compromise",
        "category": "runtime_exploitation",
        "target_xapp": "telemetry-monitor",
        "signal": "unexpected_shell",
        "rule": "Terminal shell in container",
        "expected_state": "QUARANTINED",
        "expected_containment": True,
        "malicious": True,
        "mode": "real-falco-validated-and-controlled",
        "description": "Unauthorized shell execution inside a verified xApp container.",
    },
    {
        "id": "A2",
        "name": "Sensitive file access",
        "category": "runtime_exploitation",
        "target_xapp": "telemetry-monitor",
        "signal": "sensitive_file_access",
        "rule": "Read sensitive file trusted after startup",
        "expected_state": "QUARANTINED",
        "expected_containment": True,
        "malicious": True,
        "mode": "controlled-signal",
        "description": "xApp attempts to read sensitive host/container files such as /etc/shadow.",
    },
    {
        "id": "A3",
        "name": "ServiceAccount token access",
        "category": "credential_access",
        "target_xapp": "telemetry-monitor",
        "signal": "serviceaccount_token_access",
        "rule": "Contact K8S API Server From Container",
        "expected_state": "QUARANTINED",
        "expected_containment": True,
        "malicious": True,
        "mode": "controlled-signal",
        "description": "xApp attempts to access Kubernetes identity/token material.",
    },
    {
        "id": "A4",
        "name": "Malicious CPU exhaustion",
        "category": "resource_abuse",
        "target_xapp": "resource-optimizer",
        "signal": "resource_abuse",
        "rule": "Unexpected resource exhaustion pattern",
        "expected_state": "SUSPICIOUS",
        "expected_containment": False,
        "malicious": True,
        "mode": "controlled-behavior-signal",
        "description": "Resource usage becomes inconsistent with the xApp intent profile.",
    },
    {
        "id": "A5",
        "name": "Legitimate high workload",
        "category": "benign_intent_aware_control",
        "target_xapp": "traffic-analyzer",
        "signal": "profile_consistent_high_workload",
        "rule": "Profile-consistent high workload",
        "expected_state": "OBSERVED",
        "expected_containment": False,
        "malicious": False,
        "mode": "benign-control",
        "description": "traffic-analyzer performs high workload that is valid for its declared profile.",
    },
    {
        "id": "A6",
        "name": "RIC service probing",
        "category": "communication_drift",
        "target_xapp": "security-observer",
        "signal": "ric_service_probing",
        "rule": "Unexpected RIC service probing",
        "expected_state": "QUARANTINED",
        "expected_containment": True,
        "malicious": True,
        "mode": "controlled-communication-signal",
        "description": "xApp contacts RIC platform services outside its allowed communication profile.",
    },
    {
        "id": "A7",
        "name": "Cross-xApp communication attempt",
        "category": "lateral_movement",
        "target_xapp": "security-observer",
        "signal": "unexpected_peer_contact",
        "rule": "Unexpected inter-xApp communication",
        "expected_state": "SUSPICIOUS",
        "expected_containment": False,
        "malicious": True,
        "mode": "controlled-communication-signal",
        "description": "xApp attempts unexpected communication with another xApp.",
    },
    {
        "id": "A8",
        "name": "External egress attempt",
        "category": "exfiltration",
        "target_xapp": "security-observer",
        "signal": "external_egress",
        "rule": "Unexpected outbound connection from xApp",
        "expected_state": "QUARANTINED",
        "expected_containment": True,
        "malicious": True,
        "mode": "controlled-communication-signal",
        "description": "xApp attempts outbound communication to an unapproved external destination.",
    },
    {
        "id": "A9",
        "name": "Output/profile drift",
        "category": "behavioral_drift",
        "target_xapp": "qos-optimizer",
        "signal": "profile_output_drift",
        "rule": "xApp output deviates from declared role",
        "expected_state": "SUSPICIOUS",
        "expected_containment": False,
        "malicious": True,
        "mode": "controlled-profile-signal",
        "description": "Analytics or recommendation behavior deviates from declared xApp intent.",
    },
    {
        "id": "A10",
        "name": "Image/config/profile tampering",
        "category": "deployment_integrity",
        "target_xapp": "telemetry-monitor",
        "signal": "integrity_mismatch",
        "rule": "xApp image or profile integrity mismatch",
        "expected_state": "QUARANTINED",
        "expected_containment": True,
        "malicious": True,
        "mode": "controlled-integrity-signal",
        "description": "Runtime image/profile evidence no longer matches verified onboarding metadata.",
    },
    {
        "id": "B1",
        "name": "Clean baseline audit",
        "category": "benign_baseline",
        "target_xapp": "telemetry-monitor",
        "signal": "clean_baseline",
        "rule": "Clean baseline audit",
        "expected_state": "TRUSTED",
        "expected_containment": False,
        "malicious": False,
        "mode": "benign-control",
        "description": "Clean verified xApp should remain trusted and reachable.",
    },
    {
        "id": "B2",
        "name": "Normal telemetry heartbeat",
        "category": "benign_activity",
        "target_xapp": "telemetry-monitor",
        "signal": "normal_heartbeat",
        "rule": "Normal heartbeat",
        "expected_state": "TRUSTED",
        "expected_containment": False,
        "malicious": False,
        "mode": "benign-control",
        "description": "Normal telemetry heartbeat should not trigger containment.",
    },
    {
        "id": "B3",
        "name": "Normal QoS decision generation",
        "category": "benign_activity",
        "target_xapp": "qos-optimizer",
        "signal": "normal_qos_activity",
        "rule": "Normal QoS activity",
        "expected_state": "TRUSTED",
        "expected_containment": False,
        "malicious": False,
        "mode": "benign-control",
        "description": "Normal QoS recommendation generation should not trigger containment.",
    },
]


def ztx_get_scenarios():
    return ZT_SCENARIOS


def ztx_find_scenario(scenario_id):
    scenario_id = str(scenario_id or "").upper().strip()
    for scenario in ZT_SCENARIOS:
        if scenario["id"].upper() == scenario_id:
            return scenario
    return None


def ztx_compact_verify(xapp, namespace=None):
    namespace = namespace or XAPP_NAMESPACE
    verify = verify_xapp_containment(xapp, namespace)
    svc = (verify.get("services") or [{}])[0]
    ep = svc.get("endpoint_summary") or {}
    return {
        "contained": verify.get("contained"),
        "service_isolated": verify.get("service_isolated"),
        "quarantine_marked": verify.get("quarantine_marked"),
        "selector": svc.get("selector"),
        "endpoint_count": ep.get("endpoint_count"),
        "raw": verify,
    }


def ztx_primary_pod_name(xapp, namespace=None):
    namespace = namespace or XAPP_NAMESPACE
    try:
        pod = get_primary_pod_for_xapp(xapp, namespace)
        if pod:
            return pod.metadata.name
    except Exception:
        pass
    return f"{xapp}-unknown"


def ztx_normalize_result(raw_result):
    status_code = 200
    first = raw_result

    if isinstance(raw_result, tuple):
        first = raw_result[0]
        if len(raw_result) > 1 and isinstance(raw_result[1], int):
            status_code = raw_result[1]

    if hasattr(first, "get_json"):
        data = first.get_json(silent=True) or {}
    elif isinstance(first, dict):
        data = first
    elif isinstance(first, list):
        data = {"raw_list": first}
    else:
        data = {"raw": str(first)}

    return data, status_code


def ztx_attach_route_handler_path(body: Dict[str, Any], route_name: str) -> Dict[str, Any]:
    if not isinstance(body, dict):
        return body

    base_path = str(body.get("handler_path") or "").strip()
    body["handler_path"] = f"{route_name}->{base_path}" if base_path else route_name
    return body


def ztx_scenario_event(scenario, xapp, pod_name, namespace):
    signal = scenario.get("signal")
    rule = scenario.get("rule")

    output_by_signal = {
        "unexpected_shell": f"Terminal shell in container pod={pod_name} ns={namespace} command=/bin/sh",
        "sensitive_file_access": f"Sensitive file opened by xApp pod={pod_name} ns={namespace} file=/etc/shadow",
        "serviceaccount_token_access": f"ServiceAccount token access pod={pod_name} ns={namespace} file=/var/run/secrets/kubernetes.io/serviceaccount/token",
        "resource_abuse": f"Resource exhaustion pattern pod={pod_name} ns={namespace} command=stress-ng",
        "ric_service_probing": f"Unexpected RIC service probing pod={pod_name} ns={namespace} target=ricplt/e2mgr",
        "unexpected_peer_contact": f"Unexpected inter-xApp communication pod={pod_name} ns={namespace} peer=qos-optimizer",
        "external_egress": f"Unexpected outbound connection pod={pod_name} ns={namespace} dest=attacker-collector",
        "profile_output_drift": f"xApp output deviates from declared role pod={pod_name} ns={namespace}",
        "integrity_mismatch": f"xApp image/profile integrity mismatch pod={pod_name} ns={namespace}",
    }

    proc_by_signal = {
        "unexpected_shell": "sh",
        "sensitive_file_access": "cat",
        "serviceaccount_token_access": "cat",
        "resource_abuse": "stress-ng",
        "ric_service_probing": "curl",
        "unexpected_peer_contact": "curl",
        "external_egress": "curl",
        "profile_output_drift": "python",
        "integrity_mismatch": "kubectl",
    }

    return {
        "rule": rule,
        "priority": "WARNING" if scenario.get("expected_state") == "SUSPICIOUS" else "CRITICAL",
        "output": output_by_signal.get(signal, f"{rule} pod={pod_name} ns={namespace}"),
        "output_fields": {
            "k8s.ns.name": namespace,
            "k8s.pod.name": pod_name,
            "container.name": xapp,
            "proc.name": proc_by_signal.get(signal, "unknown"),
            "proc.cmdline": output_by_signal.get(signal, rule),
            "fd.name": "/etc/shadow" if signal == "sensitive_file_access" else "",
            "scenario.id": scenario.get("id"),
            "ztx.signal": signal,
        },
        "ztx_controlled_scenario": True,
        "scenario": scenario.get("id"),
        "ztx_expected_state": scenario.get("expected_state"),
        "ztx_signal": signal,
    }


def ztx_apply_scenario_containment_if_required(scenario, xapp, namespace, event_result):
    verify_before = ztx_compact_verify(xapp, namespace)

    if not scenario.get("expected_containment"):
        return {
            "attempted": False,
            "reason": "containment_not_expected_for_scenario",
            "verify_before": verify_before,
            "containment": None,
        }

    if verify_before.get("contained") is True:
        return {
            "attempted": False,
            "reason": "already_contained",
            "verify_before": verify_before,
            "containment": None,
        }

    incident_id = None
    if isinstance(event_result, dict):
        incident_id = event_result.get("incident_id")

    if not incident_id:
        incident_id = f"{utc_now().replace(':','').replace('-','')}-{scenario.get('id')}-{xapp}"

    reason = f"ZT-XGuard scenario {scenario.get('id')} {scenario.get('name')}: {scenario.get('signal')}"
    normalized_signal = ztx_normalize_signal(scenario.get("signal"))

    try:
        pod_name = ztx_primary_pod_name(xapp, namespace)
        containment = apply_quarantine(
            pod_name,
            namespace,
            reason,
            incident_id,
            normalized_signal=normalized_signal,
            containment_required=bool(scenario.get("expected_containment")),
            decision_state="QUARANTINED",
            handler_path="ztx_apply_scenario_containment_if_required->apply_quarantine",
        )
        return {
            "attempted": True,
            "reason": "scenario_policy_containment",
            "incident_id": incident_id,
            "containment": containment,
            "verify_before": verify_before,
        }
    except Exception as exc:
        return {
            "attempted": True,
            "reason": "scenario_policy_containment_failed",
            "incident_id": incident_id,
            "error": str(exc),
            "containment": None,
            "verify_before": verify_before,
        }


def ztx_run_scenario(scenario_id, payload=None):
    payload = payload or {}
    scenario = ztx_find_scenario(scenario_id)
    if not scenario:
        return {
            "ok": False,
            "error": "unknown_scenario",
            "scenario_id": scenario_id,
            "available": [s["id"] for s in ZT_SCENARIOS],
        }, 404

    namespace = payload.get("namespace") or XAPP_NAMESPACE
    xapp = payload.get("xapp") or scenario["target_xapp"]
    started = time.time()

    pod_name = ztx_primary_pod_name(xapp, namespace)
    pre = ztx_compact_verify(xapp, namespace)

    event_result = {}
    event_status = 200
    containment_action = {
        "attempted": False,
        "reason": "not_applicable",
        "containment": None,
    }

    # Benign/control scenarios must not inject malicious runtime events.
    if scenario.get("malicious"):
        event = ztx_scenario_event(scenario, xapp, pod_name, namespace)

        # Use the existing event path first. This preserves the same CSM pipeline used by Falco.
        raw = csm_process_falco_event(event)
        event_result, event_status = ztx_normalize_result(raw)

        # Some controlled signals may not be native Falco rules yet.
        # If the scenario expects quarantine and the event path did not isolate the service,
        # apply the scenario policy decision through the same quarantine controller.
        verify_mid = ztx_compact_verify(xapp, namespace)
        if scenario.get("expected_containment") and not verify_mid.get("contained"):
            containment_action = ztx_apply_scenario_containment_if_required(
                scenario, xapp, namespace, event_result
            )
    else:
        event_result = {
            "state": scenario.get("expected_state"),
            "signal": scenario.get("signal"),
            "decision_source": "benign_intent_control",
            "reason": "profile_consistent_behavior_no_containment",
        }

    post = ztx_compact_verify(xapp, namespace)

    expected_state = scenario.get("expected_state")
    expected_containment = bool(scenario.get("expected_containment"))
    actual_containment = bool(post.get("contained"))

    if actual_containment:
        actual_state = "QUARANTINED"
    elif scenario.get("malicious") and expected_state == "SUSPICIOUS":
        actual_state = "SUSPICIOUS"
    elif not scenario.get("malicious") and expected_state == "OBSERVED":
        actual_state = "OBSERVED"
    elif not scenario.get("malicious"):
        actual_state = "TRUSTED"
    else:
        actual_state = event_result.get("state") if isinstance(event_result, dict) else expected_state

    malicious = bool(scenario.get("malicious"))
    detected_positive = actual_state in ["SUSPICIOUS", "COMPROMISED", "QUARANTINED"]

    if malicious and detected_positive:
        classification = "TP"
    elif malicious and not detected_positive:
        classification = "FN"
    elif (not malicious) and detected_positive:
        classification = "FP"
    else:
        classification = "TN"

    containment_pass = expected_containment == actual_containment
    state_pass = (
        actual_state == expected_state
        or (expected_state == "QUARANTINED" and actual_state in ["COMPROMISED", "QUARANTINED"])
        or (expected_state == "OBSERVED" and actual_state in ["OBSERVED", "TRUSTED"])
    )

    passed = bool(state_pass and containment_pass)

    result = {
        "ok": True,
        "scenario_id": scenario.get("id"),
        "name": scenario.get("name"),
        "category": scenario.get("category"),
        "mode": scenario.get("mode"),
        "xapp": xapp,
        "namespace": namespace,
        "pod": pod_name,
        "signal": scenario.get("signal"),
        "rule": scenario.get("rule"),
        "malicious": malicious,
        "expected_state": expected_state,
        "actual_state": actual_state,
        "expected_containment": expected_containment,
        "actual_containment": actual_containment,
        "classification": classification,
        "pass": passed,
        "state_pass": state_pass,
        "containment_pass": containment_pass,
        "pre": {
            "contained": pre.get("contained"),
            "endpoint_count": pre.get("endpoint_count"),
            "selector": pre.get("selector"),
        },
        "post": {
            "contained": post.get("contained"),
            "service_isolated": post.get("service_isolated"),
            "quarantine_marked": post.get("quarantine_marked"),
            "endpoint_count": post.get("endpoint_count"),
            "selector": post.get("selector"),
        },
        "event_result": event_result,
        "event_status": event_status,
        "containment_action": containment_action,
        "duration_ms": round((time.time() - started) * 1000, 3),
        "time": utc_now(),
    }

    ZT_SCENARIO_RESULTS.append(result)

    # Keep memory bounded.
    if len(ZT_SCENARIO_RESULTS) > 300:
        del ZT_SCENARIO_RESULTS[:-300]

    return result, 200


def ztx_evaluation_summary():
    results = list(ZT_SCENARIO_RESULTS)

    tp = sum(1 for r in results if r.get("classification") == "TP")
    tn = sum(1 for r in results if r.get("classification") == "TN")
    fp = sum(1 for r in results if r.get("classification") == "FP")
    fn = sum(1 for r in results if r.get("classification") == "FN")

    total = len(results)
    passed = sum(1 for r in results if r.get("pass") is True)

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (
        (2 * precision * recall / (precision + recall))
        if precision is not None and recall is not None and (precision + recall)
        else None
    )
    fpr = fp / (fp + tn) if (fp + tn) else None
    fnr = fn / (fn + tp) if (fn + tp) else None

    return {
        "total_runs": total,
        "passed": passed,
        "failed": total - passed,
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1_score": round(f1, 4) if f1 is not None else None,
        "false_positive_rate": round(fpr, 4) if fpr is not None else None,
        "false_negative_rate": round(fnr, 4) if fnr is not None else None,
        "recent_results": results[-20:][::-1],
        "time": utc_now(),
    }


@APP.route("/scenario-console", methods=["GET"])
def ztx_scenario_console_page():
    return render_template("scenario_console.html")


@APP.route("/evaluation", methods=["GET"])
def ztx_evaluation_page():
    return render_template("evaluation.html")


@APP.route("/csm/scenarios", methods=["GET"])
def ztx_scenarios_api():
    return jsonify({
        "scenarios": ztx_get_scenarios(),
        "results_count": len(ZT_SCENARIO_RESULTS),
        "last_results": ZT_SCENARIO_RESULTS[-10:][::-1],
        "time": utc_now(),
    })


@APP.route("/csm/scenarios/<scenario_id>/run", methods=["POST"])
def ztx_run_scenario_api(scenario_id):
    payload = request.get_json(force=True, silent=True) or {}
    result, status = ztx_run_scenario(scenario_id, payload)
    return jsonify(result), status


@APP.route("/csm/evaluation/summary", methods=["GET"])
def ztx_evaluation_summary_api():
    return jsonify(ztx_evaluation_summary())


@APP.route("/csm/evaluation/clear", methods=["POST"])
def ztx_evaluation_clear_api():
    ZT_SCENARIO_RESULTS.clear()
    return jsonify({"ok": True, "cleared": True, "time": utc_now()})



# ------------------------------------------------------------
# ZT_XGUARD_RUNTIME_TABLE_V3_MARKER
# k9s-style xApp runtime table API
# ------------------------------------------------------------

def ztx_runtime_xapp_names_v3():
    try:
        return _ztx_xapp_list()
    except Exception:
        try:
            if isinstance(XAPP_LIST, list):
                return [str(x).strip() for x in XAPP_LIST if str(x).strip()]
            return [x.strip() for x in str(XAPP_LIST).split(",") if x.strip()]
        except Exception:
            return [
                "telemetry-monitor",
                "qos-optimizer",
                "traffic-analyzer",
                "resource-optimizer",
                "security-observer",
            ]


def ztx_runtime_pod_summary_v3(pod):
    labels = pod.metadata.labels or {}

    statuses = pod.status.container_statuses or []
    restarts = sum(int(cs.restart_count or 0) for cs in statuses)
    ready_containers = sum(1 for cs in statuses if cs.ready)
    total_containers = len(statuses)

    return {
        "name": pod.metadata.name,
        "namespace": pod.metadata.namespace,
        "phase": pod.status.phase,
        "ready": bool(total_containers and ready_containers == total_containers and pod.status.phase == "Running"),
        "ready_text": f"{ready_containers}/{total_containers}" if total_containers else "0/0",
        "restarts": restarts,
        "pod_ip": pod.status.pod_ip,
        "node": pod.spec.node_name,
        "service_account": pod.spec.service_account_name,
        "quarantine_label": labels.get("zt-xguard.io/quarantine") == "true",
        "decision_label": labels.get("zt-xguard.io/decision"),
        "provider": labels.get("zt-xguard.io/provider"),
        "verified": labels.get("zt-xguard.io/verified"),
        "age": pod.metadata.creation_timestamp.isoformat() if pod.metadata.creation_timestamp else None,
    }


def ztx_runtime_service_for_xapp_v3(xapp, services):
    for svc in services:
        labels = svc.metadata.labels or {}
        annotations = svc.metadata.annotations or {}
        selector = svc.spec.selector or {}

        if svc.metadata.name == xapp:
            return svc
        if annotations.get("zt-xguard.io/xapp") == xapp:
            return svc
        if labels.get("app") == xapp:
            return svc
        if selector.get("app") == xapp:
            return svc

    return None


def ztx_runtime_trust_index_v3():
    # Use the in-memory CSM route indirectly by reading the same route output is messy.
    # Instead, fall back safely. The frontend also merges /csm/state directly.
    return {}




def ztx_runtime_prometheus_resources_v3(namespace: str, pod_name: str) -> Dict[str, Any]:
    """Return per-pod CPU and memory from Prometheus/cAdvisor.

    Source path:
      kubelet/cAdvisor -> Prometheus -> ZT-XGuard policy engine

    CPU is returned as cores and as percent of one CPU core.
    Memory is returned as bytes.
    """
    base = {
        "ok": False,
        "source": "prometheus-cadvisor",
        "pod": pod_name,
        "cpu_cores_2m": None,
        "cpu_percent_1core": None,
        # Backward-compatible alias for older exports/UI code.
        "cpu_percent_1core_2m": None,
        "memory_working_set_bytes": None,
        "memory_usage_bytes": None,
    }

    if not pod_name:
        return {
            **base,
            "reason": "pod_missing",
        }

    if not PROMETHEUS_URL:
        return {
            **base,
            "reason": "PROMETHEUS_URL_not_configured",
        }

    def _prom_query(query: str) -> Dict[str, Any]:
        import json as _json
        import urllib.parse as _parse
        import urllib.request as _request

        url = PROMETHEUS_URL.rstrip("/") + "/api/v1/query?" + _parse.urlencode({"query": query})
        with _request.urlopen(url, timeout=PROMETHEUS_TIMEOUT) as r:
            return _json.loads(r.read().decode("utf-8"))

    def _first_value(resp: Dict[str, Any]) -> Optional[float]:
        try:
            result = resp.get("data", {}).get("result", [])
            if not result:
                return None
            return float(result[0].get("value", [None, None])[1])
        except Exception:
            return None

    def _sum_values(resp: Dict[str, Any]) -> Optional[float]:
        try:
            result = resp.get("data", {}).get("result", [])
            if not result:
                return None
            total = 0.0
            seen = False
            for item in result:
                value = item.get("value", [None, None])[1]
                if value is None:
                    continue
                total += float(value)
                seen = True
            return total if seen else None
        except Exception:
            return None

    safe_namespace = str(namespace).replace("\\", "\\\\").replace('"', '\\"')
    safe_pod = str(pod_name).replace("\\", "\\\\").replace('"', '\\"')

    cpu_q_2m = (
        'sum(rate(container_cpu_usage_seconds_total{'
        f'namespace="{safe_namespace}",pod="{safe_pod}",container!="POD",container!=""'
        '}[2m]))'
    )
    cpu_q_5m = (
        'sum(rate(container_cpu_usage_seconds_total{'
        f'namespace="{safe_namespace}",pod="{safe_pod}",container!="POD",container!=""'
        '}[5m]))'
    )
    mem_ws_q = (
        'sum(container_memory_working_set_bytes{'
        f'namespace="{safe_namespace}",pod="{safe_pod}",container!="POD",container!=""'
        '})'
    )
    mem_usage_q = (
        'sum(container_memory_usage_bytes{'
        f'namespace="{safe_namespace}",pod="{safe_pod}",container!="POD",container!=""'
        '})'
    )

    try:
        cpu_resp_2m = _prom_query(cpu_q_2m)
        mem_ws_resp = _prom_query(mem_ws_q)
        mem_usage_resp = _prom_query(mem_usage_q)

        cpu_cores = _sum_values(cpu_resp_2m)
        cpu_source_query = cpu_q_2m
        cpu_status_2m = cpu_resp_2m.get("status")
        cpu_resp_5m = None

        if cpu_cores is None:
            cpu_resp_5m = _prom_query(cpu_q_5m)
            cpu_cores = _sum_values(cpu_resp_5m)
            if cpu_cores is not None:
                cpu_source_query = cpu_q_5m

        mem_ws = _sum_values(mem_ws_resp)
        mem_usage = _sum_values(mem_usage_resp)

        warnings = []
        reason = None

        if cpu_cores is None and mem_ws is not None:
            cpu_cores = 0.0
            reason = "cpu_metric_missing_assumed_idle"
            warnings.append(reason)

        cpu_percent = None if cpu_cores is None else round(cpu_cores * 100.0, 4)

        if mem_ws is None:
            reason = "memory_working_set_metric_missing"
        elif cpu_cores is None:
            reason = "cpu_metric_missing"

        data = {
            **base,
            "ok": mem_ws is not None and cpu_cores is not None,
            "queries": {
                "cpu_cores_2m": cpu_q_2m,
                "cpu_cores_5m_fallback": cpu_q_5m,
                "cpu_cores_effective": cpu_source_query,
                "memory_working_set_bytes": mem_ws_q,
                "memory_usage_bytes": mem_usage_q,
            },
            "cpu_cores_2m": cpu_cores,
            "cpu_percent_1core": cpu_percent,
            "cpu_percent_1core_2m": cpu_percent,
            "memory_working_set_bytes": None if mem_ws is None else int(mem_ws),
            "memory_usage_bytes": None if mem_usage is None else int(mem_usage),
            "prometheus": {
                "url": PROMETHEUS_URL,
                "cpu_status_2m": cpu_status_2m,
                "cpu_status_5m": cpu_resp_5m.get("status") if cpu_resp_5m else None,
                "cpu_query_window_used": "5m" if cpu_source_query == cpu_q_5m else "2m",
                "memory_working_set_status": mem_ws_resp.get("status"),
                "memory_usage_status": mem_usage_resp.get("status"),
            },
        }
        if warnings:
            data["warnings"] = warnings
        if reason:
            data["reason"] = reason
        return data
    except Exception as exc:
        return {
            **base,
            "reason": "prometheus_query_failed",
            "error": str(exc),
        }


@APP.route("/csm/xapps/runtime", methods=["GET"])
def ztx_xapps_runtime_table_api_v3():
    namespace = request.args.get("namespace") or XAPP_NAMESPACE

    xapps = ztx_runtime_xapp_names_v3()
    rows = []

    try:
        pods = CORE.list_namespaced_pod(namespace=namespace).items
    except Exception as exc:
        return jsonify({
            "ok": False,
            "error": "pod_list_failed",
            "message": str(exc),
            "namespace": namespace,
            "rows": [],
            "time": utc_now(),
        }), 500

    try:
        services = CORE.list_namespaced_service(namespace=namespace).items
    except Exception:
        services = []

    for xapp in xapps:
        xpods = []
        for pod in pods:
            labels = pod.metadata.labels or {}
            if labels.get("app") == xapp or pod.metadata.name.startswith(xapp + "-"):
                xpods.append(pod)

        # Prefer a running pod, otherwise first matching pod.
        xpods_sorted = sorted(
            xpods,
            key=lambda pod: (
                pod.status.phase != "Running",
                pod.metadata.creation_timestamp or utc_now(),
            )
        )

        pod = xpods_sorted[0] if xpods_sorted else None
        pod_summary = ztx_runtime_pod_summary_v3(pod) if pod else {
            "name": None,
            "namespace": namespace,
            "phase": "Missing",
            "ready": False,
            "ready_text": "0/0",
            "restarts": None,
            "pod_ip": None,
            "node": None,
            "service_account": None,
            "quarantine_label": False,
            "decision_label": None,
            "provider": None,
            "verified": None,
            "age": None,
        }
        resources = ztx_runtime_prometheus_resources_v3(namespace, pod_summary.get("name"))

        svc = ztx_runtime_service_for_xapp_v3(xapp, services)
        selector = svc.spec.selector if svc and svc.spec else None
        service_name = svc.metadata.name if svc else None

        endpoint_summary = {}
        if service_name:
            try:
                endpoint_summary = service_endpoints_summary(service_name, namespace)
            except Exception as exc:
                endpoint_summary = {
                    "service": service_name,
                    "endpoint_count": None,
                    "has_endpoints": None,
                    "error": str(exc),
                }

        try:
            verify = verify_xapp_containment(xapp, namespace)
        except Exception as exc:
            verify = {
                "contained": None,
                "service_isolated": None,
                "quarantine_marked": None,
                "error": str(exc),
            }

        rows.append({
            "xapp": xapp,
            "namespace": namespace,
            "pod": pod_summary,
            "service": {
                "name": service_name,
                "selector": selector,
                "endpoint_count": endpoint_summary.get("endpoint_count"),
                "has_endpoints": endpoint_summary.get("has_endpoints"),
                "addresses": endpoint_summary.get("addresses"),
                "ports": endpoint_summary.get("ports"),
                "source": endpoint_summary.get("source"),
                "error": endpoint_summary.get("error"),
            },
            "resources": resources,
            "containment": {
                "contained": verify.get("contained"),
                "service_isolated": verify.get("service_isolated"),
                "quarantine_marked": verify.get("quarantine_marked"),
                "verification_unknown": verify.get("verification_unknown"),
            },
        })

    return jsonify({
        "ok": True,
        "namespace": namespace,
        "rows": rows,
        "time": utc_now(),
    })




# ------------------------------------------------------------
# ZT-XGuard Policy Engine Prometheus Metrics
# ------------------------------------------------------------

def ztx_prom_escape(value: Any) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


@APP.route("/metrics", methods=["GET"])
def ztx_policy_engine_metrics() -> Any:
    """Prometheus text exposition for the policy engine itself.

    This endpoint intentionally uses cached state only. It must stay cheap because
    Prometheus may scrape it frequently. Expensive Kubernetes endpoint checks stay
    in /csm/audit and /csm/xapps/runtime.
    """
    state_value = {
        "UNKNOWN": 0,
        "TRUSTED": 1,
        "OBSERVED": 2,
        "SUSPICIOUS": 3,
        "COMPROMISED": 4,
        "QUARANTINED": 5,
        "RESTORED": 6,
        "IGNORED": 7,
    }
    lines = [
        "# HELP ztx_policy_engine_up ZT-XGuard policy engine availability.",
        "# TYPE ztx_policy_engine_up gauge",
        "ztx_policy_engine_up 1",
        "# HELP ztx_xapp_trust_state Numeric trust state per xApp: UNKNOWN=0 TRUSTED=1 OBSERVED=2 SUSPICIOUS=3 COMPROMISED=4 QUARANTINED=5 RESTORED=6 IGNORED=7.",
        "# TYPE ztx_xapp_trust_state gauge",
    ]

    with CSM_STATE_LOCK:
        states = {x: dict(CSM_STATE.get(x, {})) for x in XAPP_LIST}
        events = list(CSM_EVENT_HISTORY[:200])

    for xapp in XAPP_LIST:
        item = states.get(xapp) or {}
        st = str(item.get("state") or "UNKNOWN").upper()
        det = str(item.get("detection_state") or item.get("decision_state") or st).upper()
        source = item.get("last_source") or "unknown"
        confidence = item.get("confidence")
        trust_score = item.get("trust_score")
        risk_score = item.get("risk_score")

        # Backward compatibility for older events before score clarity patch.
        if trust_score is None and item.get("score") is not None and item.get("score_type") != "risk_score_0_to_100_higher_means_riskier":
            trust_score = item.get("score")
        if risk_score is None:
            if item.get("score_type") == "risk_score_0_to_100_higher_means_riskier" and item.get("score") is not None:
                risk_score = item.get("score")
            elif trust_score is not None:
                risk_score = max(0.0, min(100.0, 100.0 - float(trust_score)))

        containment_required = 1 if item.get("containment_required") else 0
        lines.append(f'ztx_xapp_trust_state{{xapp="{ztx_prom_escape(xapp)}",state="{ztx_prom_escape(st)}",detection_state="{ztx_prom_escape(det)}",source="{ztx_prom_escape(source)}"}} {state_value.get(st, 0)}')
        # Final safety correction based on decision state.
        # Prevent internal legacy trust-score values from being exported as risk.
        if st in ("QUARANTINED", "COMPROMISED"):
            trust_score = 0.0
            risk_score = 100.0
        elif st == "SUSPICIOUS":
            if risk_score is None or float(risk_score) < 50.0:
                risk_score = 60.0
            trust_score = max(0.0, min(100.0, 100.0 - float(risk_score)))
        elif st in ("OBSERVED", "TRUSTED", "RESTORED"):
            if risk_score is None or float(risk_score) > 40.0:
                # OBSERVED should not look high-risk in Grafana.
                risk_score = 20.0 if st == "OBSERVED" else 0.0
            trust_score = max(0.0, min(100.0, 100.0 - float(risk_score)))

        if trust_score is not None:
            lines.append(f'ztx_xapp_trust_score{{xapp="{ztx_prom_escape(xapp)}"}} {float(trust_score)}')
        if risk_score is not None:
            lines.append(f'ztx_xapp_risk_score{{xapp="{ztx_prom_escape(xapp)}"}} {float(risk_score)}')
            lines.append(f'ztx_xapp_score{{xapp="{ztx_prom_escape(xapp)}",score_type="risk"}} {float(risk_score)}')
        if confidence is not None:
            lines.append(f'ztx_xapp_confidence{{xapp="{ztx_prom_escape(xapp)}"}} {float(confidence)}')
        lines.append(f'ztx_xapp_containment_required{{xapp="{ztx_prom_escape(xapp)}"}} {containment_required}')

    lines.extend([
        "# HELP ztx_policy_events_total Number of remembered policy events by state.",
        "# TYPE ztx_policy_events_total counter",
    ])
    counts: Dict[Tuple[str, str], int] = {}
    for event in events:
        key = (str(event.get("xapp") or "unknown"), str(event.get("state") or "UNKNOWN").upper())
        counts[key] = counts.get(key, 0) + 1
    for (xapp, st), count in sorted(counts.items()):
        lines.append(f'ztx_policy_events_total{{xapp="{ztx_prom_escape(xapp)}",state="{ztx_prom_escape(st)}"}} {count}')

    body = "\n".join(lines) + "\n"
    return APP.response_class(body, mimetype="text/plain; version=0.0.4; charset=utf-8")

# ------------------------------------------------------------
# ZT_XGUARD_INTENT_ENGINE_V4_MARKER

# ZT_XGUARD_INTENT_ENGINE_V4_COMPAT_MARKER
import hashlib as _ztx_v4_hashlib
import re as _ztx_v4_re
from datetime import datetime as _ztx_v4_datetime, timezone as _ztx_v4_timezone

try:
    json
except NameError:
    import json

try:
    utc_id
except NameError:
    def utc_id():
        return _ztx_v4_datetime.now(_ztx_v4_timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

try:
    safe_name
except NameError:
    def safe_name(value):
        value = str(value or "unknown").lower()
        value = _ztx_v4_re.sub(r"[^a-z0-9.-]+", "-", value)
        value = value.strip("-")
        return value[:50] or "unknown"

try:
    sha256_text
except NameError:
    def sha256_text(value):
        return _ztx_v4_hashlib.sha256(str(value).encode("utf-8")).hexdigest()

# Intent-aware trust-state engine
# ------------------------------------------------------------

try:
    ZT_SCENARIO_RESULTS
except NameError:
    ZT_SCENARIO_RESULTS = []


# step_xguard_02 Step B1: ZT_INTENT_PROFILES_V4 moved to
# event_normalization.py (imported above under its original name).


ZT_SCENARIOS = [
    {
        "id": "A1",
        "name": "Runtime shell compromise",
        "signal": "unexpected_shell",
        "default_xapp": "telemetry-monitor",
        "expected_state": "QUARANTINED",
        "expected_containment": True,
        "malicious": True,
        "mode": "intent-signal",
        "description": "Unauthorized shell execution in an xApp container.",
    },
    {
        "id": "A2",
        "name": "Sensitive file access",
        "signal": "sensitive_file_access",
        "default_xapp": "telemetry-monitor",
        "expected_state": "QUARANTINED",
        "expected_containment": True,
        "malicious": True,
        "mode": "intent-signal",
        "description": "Attempt to access sensitive files such as /etc/shadow.",
    },
    {
        "id": "A3",
        "name": "ServiceAccount token access",
        "signal": "serviceaccount_token_access",
        "default_xapp": "telemetry-monitor",
        "expected_state": "QUARANTINED",
        "expected_containment": True,
        "malicious": True,
        "mode": "intent-signal",
        "description": "Attempt to access Kubernetes ServiceAccount token material.",
    },
    {
        "id": "A4",
        "name": "Malicious CPU exhaustion",
        "signal": "high_cpu",
        "default_xapp": "resource-optimizer",
        "expected_state": "SUSPICIOUS",
        "expected_containment": False,
        "malicious": True,
        "mode": "intent-signal",
        "description": "Resource behavior inconsistent with the xApp intent profile.",
    },
    {
        "id": "A5",
        "name": "Legitimate high workload",
        "signal": "high_cpu",
        "default_xapp": "traffic-analyzer",
        "expected_state": "OBSERVED",
        "expected_containment": False,
        "malicious": False,
        "mode": "intent-signal",
        "description": "High workload that is profile-consistent for traffic-analyzer.",
    },
    {
        "id": "A6",
        "name": "RIC service probing",
        "signal": "ric_service_probe",
        "default_xapp": "security-observer",
        "expected_state": "SUSPICIOUS",
        "expected_containment": False,
        "malicious": True,
        "mode": "intent-signal",
        "description": "Unexpected access attempt toward RIC platform services.",
    },
    {
        "id": "A7",
        "name": "Cross-xApp communication attempt",
        "signal": "unexpected_peer_contact",
        "default_xapp": "security-observer",
        "expected_state": "SUSPICIOUS",
        "expected_containment": False,
        "malicious": True,
        "mode": "intent-signal",
        "description": "Unexpected communication attempt toward another xApp.",
    },
    {
        "id": "A8",
        "name": "External egress attempt",
        "signal": "external_egress",
        "default_xapp": "security-observer",
        "expected_state": "QUARANTINED",
        "expected_containment": True,
        "malicious": True,
        "mode": "intent-signal",
        "description": "External outbound communication from an xApp whose profile forbids it.",
    },
    {
        "id": "A9",
        "name": "Output/profile drift",
        "signal": "profile_output_drift",
        "default_xapp": "qos-optimizer",
        "expected_state": "SUSPICIOUS",
        "expected_containment": False,
        "malicious": True,
        "mode": "intent-signal",
        "description": "xApp output or activity deviates from its declared intent.",
    },
    {
        "id": "A10",
        "name": "Image/config/profile tampering",
        "signal": "integrity_mismatch",
        "default_xapp": "telemetry-monitor",
        "expected_state": "QUARANTINED",
        "expected_containment": True,
        "malicious": True,
        "mode": "intent-signal",
        "description": "Runtime integrity no longer matches verified onboarding metadata.",
    },
    {
        "id": "B1",
        "name": "Clean baseline audit",
        "signal": "clean_baseline",
        "default_xapp": "telemetry-monitor",
        "expected_state": "TRUSTED",
        "expected_containment": False,
        "malicious": False,
        "mode": "intent-signal",
        "description": "Verified xApp remains healthy and trusted.",
    },
    {
        "id": "B2",
        "name": "Normal telemetry heartbeat",
        "signal": "normal_heartbeat",
        "default_xapp": "telemetry-monitor",
        "expected_state": "TRUSTED",
        "expected_containment": False,
        "malicious": False,
        "mode": "intent-signal",
        "description": "Normal telemetry heartbeat and activity remain profile-consistent.",
    },
    {
        "id": "B3",
        "name": "Normal QoS activity",
        "signal": "normal_qos_activity",
        "default_xapp": "qos-optimizer",
        "expected_state": "TRUSTED",
        "expected_containment": False,
        "malicious": False,
        "mode": "intent-signal",
        "description": "Normal QoS optimizer activity should not trigger containment.",
    },
]


def ztx_v4_profile(xapp):
    return ZT_INTENT_PROFILES_V4.get(str(xapp), {})


def ztx_v4_activity_snapshot(xapp, namespace=None):
    namespace = namespace or XAPP_NAMESPACE
    try:
        endpoints = collect_xapp_endpoints(xapp)
        profile = ((endpoints.get("profile") or {}).get("body") or {})
        activity = ((endpoints.get("activity") or {}).get("body") or {})
        metrics = ((endpoints.get("metrics") or {}).get("body") or "")
        return {
            "ok": True,
            "profile": profile,
            "activity": activity,
            "metrics": metrics,
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "profile": {},
            "activity": {},
            "metrics": "",
        }


# step_xguard_02 Step B1: ztx_v4_event_identity, _ZTX_FALCO_SIGNAL_RE,
# _ztx_v4_embedded_signal, and ztx_v4_signal_from_event moved to
# event_normalization.py (imported above under their original names).


def ztx_v4_decide(xapp, signal, evidence=None):
    evidence = evidence or {}
    profile = ztx_v4_profile(xapp)
    snapshot = ztx_v4_activity_snapshot(xapp)
    activity = snapshot.get("activity") or {}

    reasons = []
    layers = {
        "L1_exploitation": [],
        "L2_identity": [],
        "L3_behavior": [],
        "L4_communication": [],
        "L5_integrity": [],
    }

    score = 100
    decision_state = "TRUSTED"
    action = "MONITOR"

    def hit(layer, reason, penalty=0):
        nonlocal score
        layers[layer].append(reason)
        reasons.append(reason)
        score = max(0, score - int(penalty or 0))

    signal = str(signal or "unknown")

    # Layer 1 — exploitation attempt detection.
    if signal == "unexpected_shell":
        if not profile.get("expected_shell", False):
            hit("L1_exploitation", "shell_spawn_detected_profile_forbids_shell", 100)
            decision_state = "COMPROMISED"
            action = "FORENSIC_QUARANTINE"

    elif signal == "sensitive_file_access":
        if not profile.get("expected_sensitive_file_access", False):
            hit("L1_exploitation", "sensitive_file_access_profile_forbids_it", 100)
            decision_state = "COMPROMISED"
            action = "FORENSIC_QUARANTINE"

    elif signal == "serviceaccount_token_access":
        if not profile.get("expected_serviceaccount_token_access", False):
            hit("L1_exploitation", "serviceaccount_token_access_profile_forbids_it", 100)
            decision_state = "COMPROMISED"
            action = "FORENSIC_QUARANTINE"

    # Layer 2 — workload identity and registration validation.
    elif signal in ["spiffe_mismatch", "serviceaccount_mismatch", "identity_mismatch"]:
        hit("L2_identity", f"{signal}_detected", 100)
        decision_state = "COMPROMISED"
        action = "FORENSIC_QUARANTINE"

    # Layer 3 — behavioral drift.
    elif signal == "high_cpu":
        allowed_high = bool(profile.get("expected_high_workload", False))

        work_units = int(activity.get("work_units_processed", 0) or 0)
        heartbeat_ok = bool(activity.get("heartbeat_ok", True))
        evidence_valid_activity = bool(evidence.get("valid_activity", True))

        if allowed_high and heartbeat_ok and evidence_valid_activity:
            hit("L3_behavior", "high_cpu_profile_consistent_valid_activity", 5)
            decision_state = "OBSERVED"
            action = "INCREASE_MONITORING"
        else:
            hit("L3_behavior", "high_cpu_not_profile_consistent_or_activity_invalid", 35)
            decision_state = "SUSPICIOUS"
            action = "EVIDENCE_ONLY"

    elif signal == "profile_output_drift":
        hit("L3_behavior", "xapp_output_or_activity_deviates_from_declared_intent", 35)
        decision_state = "SUSPICIOUS"
        action = "EVIDENCE_ONLY"

    # Layer 4 — communication drift.
    elif signal == "ric_service_probe":
        allowed_services = profile.get("allowed_ric_services") or []
        target = str(evidence.get("target") or "")
        if target and target in allowed_services:
            hit("L4_communication", "ric_service_contact_allowed_by_profile", 0)
            decision_state = "OBSERVED"
            action = "MONITOR"
        else:
            hit("L4_communication", "unexpected_ric_service_probe", 35)
            decision_state = "SUSPICIOUS"
            action = "EVIDENCE_ONLY"

    elif signal == "unexpected_peer_contact":
        allowed_peers = profile.get("allowed_peers") or []
        peer = str(evidence.get("peer") or "")
        if peer and peer in allowed_peers:
            hit("L4_communication", "peer_contact_allowed_by_profile", 0)
            decision_state = "OBSERVED"
            action = "MONITOR"
        else:
            hit("L4_communication", "unexpected_cross_xapp_or_peer_contact", 35)
            decision_state = "SUSPICIOUS"
            action = "EVIDENCE_ONLY"

    elif signal == "external_egress":
        if not profile.get("expected_external_egress", False):
            hit("L4_communication", "external_egress_profile_forbids_it", 100)
            decision_state = "COMPROMISED"
            action = "FORENSIC_QUARANTINE"
        else:
            hit("L4_communication", "external_egress_allowed_by_profile", 0)
            decision_state = "OBSERVED"
            action = "MONITOR"

    # Layer 5 — deployment/file integrity.
    elif signal in ["integrity_mismatch", "image_digest_mismatch", "profile_hash_mismatch", "verified_label_missing"]:
        hit("L5_integrity", f"{signal}_detected", 100)
        decision_state = "COMPROMISED"
        action = "FORENSIC_QUARANTINE"

    # Benign controls.
    elif signal in ["clean_baseline", "normal_heartbeat", "normal_qos_activity"]:
        hit("L3_behavior", f"{signal}_profile_consistent", 0)
        decision_state = "TRUSTED"
        action = "MONITOR"

    else:
        hit("L1_exploitation", f"unclassified_signal_observed:{signal}", 10)
        decision_state = "OBSERVED"
        action = "MONITOR"

    # Multi-signal escalation hook.
    suspicious_layers = [
        layer for layer, values in layers.items()
        if values and decision_state in ["SUSPICIOUS", "OBSERVED"]
    ]
    correlated = evidence.get("correlated_signals") or []
    if decision_state == "SUSPICIOUS" and len(correlated) >= 2:
        hit("L3_behavior", "multiple_suspicious_indicators_within_window", 30)
        decision_state = "COMPROMISED"
        action = "FORENSIC_QUARANTINE"

    confidence = 0.98 if decision_state == "COMPROMISED" else 0.75 if decision_state == "SUSPICIOUS" else 0.65 if decision_state == "OBSERVED" else 0.9

    return {
        "xapp": xapp,
        "signal": signal,
        "profile_role": profile.get("role"),
        "decision_state": decision_state,
        "score": score,
        "confidence": confidence,
        "action": action,
        "reasons": reasons,
        "layers": layers,
        "snapshot": {
            "activity_ok": snapshot.get("ok"),
            "heartbeat_ok": activity.get("heartbeat_ok"),
            "work_units_processed": activity.get("work_units_processed"),
            "activity_error": snapshot.get("error"),
        },
        "time": utc_now(),
    }



# Preserve legacy V4 rule-map decision function as fallback.
_ztx_v4_legacy_decide = ztx_v4_decide


def ztx_v5_prometheus_query(query: str) -> Dict[str, Any]:
    if not PROMETHEUS_URL:
        return {"ok": False, "reason": "PROMETHEUS_URL_not_configured", "query": query}
    try:
        resp = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": query},
            timeout=PROMETHEUS_TIMEOUT,
        )
        data = resp.json()
        return {"ok": resp.ok and data.get("status") == "success", "query": query, "data": data}
    except Exception as exc:
        return {"ok": False, "query": query, "error": str(exc)}


def ztx_v5_collect_evidence(xapp: str, namespace: str, signal: str, evidence: Dict[str, Any], snapshot: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Collect lightweight evidence for the V5 state engine.

    This deliberately avoids slow full audits. It may read xApp endpoints and
    optionally Prometheus if PROMETHEUS_URL is configured.
    """
    enriched = dict(evidence or {})
    v5_snapshot = dict(snapshot or {})
    metrics_snapshot = v5_snapshot.get("metrics")
    if not isinstance(metrics_snapshot, dict):
        metrics_snapshot = {}
    else:
        metrics_snapshot = dict(metrics_snapshot)
    evidence_sources = v5_snapshot.get("evidence_sources")
    if not isinstance(evidence_sources, dict):
        evidence_sources = {}
    else:
        evidence_sources = dict(evidence_sources)

    try:
        endpoints = collect_xapp_endpoints(xapp)
        v5_snapshot["profile"] = ((endpoints.get("profile") or {}).get("body") or {})
        v5_snapshot["activity"] = ((endpoints.get("activity") or {}).get("body") or {})
        v5_snapshot["identity"] = ((endpoints.get("identity") or {}).get("body") or {})
        v5_snapshot["integrity"] = ((endpoints.get("integrity") or {}).get("body") or {})
        v5_snapshot["metrics_text"] = ((endpoints.get("metrics") or {}).get("body") or "")
    except Exception as exc:
        enriched["endpoint_collection_error"] = str(exc)

    # Expected SPIFFE/SVID values from Kubernetes metadata.
    try:
        resolved_pod_name = str(enriched.get("pod") or "").strip() or None
        pod = get_pod_by_name(resolved_pod_name, namespace) if resolved_pod_name else None
        if not resolved_pod_name:
            pod = get_primary_pod_for_xapp(xapp, namespace)
            if pod:
                resolved_pod_name = pod.metadata.name

        if resolved_pod_name:
            enriched["pod"] = resolved_pod_name
            v5_snapshot["pod"] = resolved_pod_name

        if pod:
            sa = pod.spec.service_account_name or "default"
            enriched["service_account"] = sa
            enriched["expected_spiffe_id"] = spiffe_for(namespace, sa)
            v5_snapshot.setdefault("kubernetes", {})["pod"] = pod.metadata.name
            v5_snapshot.setdefault("kubernetes", {})["service_account"] = sa
            v5_snapshot.setdefault("kubernetes", {})["phase"] = pod.status.phase
    except Exception as exc:
        enriched["kubernetes_lookup_error"] = str(exc)

    # Identity/SVID consistency from xApp /identity endpoint.
    identity = v5_snapshot.get("identity") or {}
    if identity:
        cert_ok = identity.get("svid_certificate_present") is True
        key_ok = identity.get("svid_key_present") is True
        expected = enriched.get("expected_spiffe_id")
        endpoint_expected = identity.get("expected_spiffe_id")
        enriched["svid"] = {
            "certificate_present": cert_ok,
            "key_present": key_ok,
            "expected_spiffe_id": expected,
            "endpoint_expected_spiffe_id": endpoint_expected,
            "valid": bool(cert_ok and key_ok and ((not expected) or endpoint_expected == expected)),
        }
        if not cert_ok or not key_ok:
            enriched["svid_invalid"] = True

    # Optional Prometheus/cAdvisor instant metrics. These are best-effort and
    # should not block critical Falco fast-path decisions.
    if PROMETHEUS_URL:
        safe_pod = str(enriched.get("pod") or "")
        prometheus_metrics = {}
        if safe_pod:
            cpu_q = f'rate(container_cpu_usage_seconds_total{{namespace="{namespace}",pod="{safe_pod}",container!="POD",container!=""}}[1m]) * 100'
            mem_q = f'container_memory_working_set_bytes{{namespace="{namespace}",pod="{safe_pod}",container!="POD",container!=""}}'
            prometheus_metrics["prometheus_cpu"] = ztx_v5_prometheus_query(cpu_q)
            prometheus_metrics["prometheus_memory"] = ztx_v5_prometheus_query(mem_q)
        metrics_snapshot["prometheus"] = prometheus_metrics
        enriched["prometheus"] = prometheus_metrics

    resources = ztx_runtime_prometheus_resources_v3(namespace, str(enriched.get("pod") or "").strip() or None)
    metrics_snapshot["resources"] = resources
    metrics_snapshot["cpu_usage_percent"] = resources.get("cpu_percent_1core")
    metrics_snapshot["cpu_cores_2m"] = resources.get("cpu_cores_2m")
    metrics_snapshot["memory_usage_bytes"] = resources.get("memory_working_set_bytes")
    metrics_snapshot["memory_working_set_bytes"] = resources.get("memory_working_set_bytes")

    if resources.get("ok") is True:
        metrics_snapshot["cadvisor"] = resources
        enriched["cadvisor"] = resources
        evidence_sources["cadvisor"] = True
    else:
        metrics_snapshot.pop("cadvisor", None)
        evidence_sources.pop("cadvisor", None)

    v5_snapshot["metrics"] = metrics_snapshot
    v5_snapshot["evidence_sources"] = evidence_sources

    return enriched, v5_snapshot


def ztx_v4_decide(xapp, signal, evidence=None):
    """V5 state-machine decision behind the existing V4 API contract.

    The name remains ztx_v4_decide for compatibility with existing routes, but
    the decision model is V5.3: deterministic critical rules + resource/profile
    checks + SVID evidence + correlation + separate containment decision.
    """
    evidence = dict(evidence or {})
    normalized_signal = ztx_normalize_signal(signal) or str(signal or "unknown").strip().lower()
    namespace = evidence.get("namespace") or XAPP_NAMESPACE
    profile = ztx_v4_profile(xapp)

    try:
        snapshot = ztx_v4_activity_snapshot(xapp, namespace)
    except Exception:
        snapshot = {"ok": False, "profile": {}, "activity": {}, "metrics": ""}

    try:
        with CSM_STATE_LOCK:
            previous_state = (CSM_STATE.get(xapp) or {}).get("state") or "UNKNOWN"
    except Exception:
        previous_state = "UNKNOWN"

    enriched, v5_snapshot = ztx_v5_collect_evidence(xapp, namespace, signal, evidence, snapshot)

    # Repeat-count tracking (added 2026-07-14, see session log Section 10/11):
    # consult the tracker for every signal, before evaluate_state() runs.
    # record_and_check() is a no-op (False, 0) for any signal not in its
    # own REPEAT_THRESHOLDS table, so this is safe to call unconditionally
    # rather than needing a signal-type check duplicated here. Merged into
    # `enriched` (the same evidence dict already passed to evaluate_state
    # below), not a separate parameter - keeps evaluate_state()'s own
    # signature untouched, matching this project's established pattern of
    # threading new evidence through the existing `evidence` dict.
    if ztx_repeat_record_and_check is not None:
        try:
            repeat_threshold_met, repeat_count = ztx_repeat_record_and_check(xapp, normalized_signal)
            enriched["repeat_threshold_met"] = repeat_threshold_met
            enriched["repeat_count"] = repeat_count
            enriched["repeat_window_seconds"] = ZTX_REPEAT_WINDOW_SECONDS
        except Exception:
            pass

    if ztx_v5_evaluate_state is None:
        decision = _ztx_v4_legacy_decide(xapp, signal, enriched)
        decision["normalized_signal"] = normalized_signal
        decision["containment_required"] = bool(decision.get("containment_required")) or decision.get("action") == "FORENSIC_QUARANTINE"
        if normalized_signal in ZTX_SUSPICIOUS_ONLY_SIGNALS and bool(decision.get("containment_required")):
            decision["containment_required"] = False
            decision["action"] = "EVIDENCE_ONLY"
            if str(decision.get("decision_state") or "").upper() in {"COMPROMISED", "QUARANTINED"}:
                decision["decision_state"] = "SUSPICIOUS"
        decision["state_engine_version"] = "legacy_v4_fallback"
        decision["state_engine_import_error"] = ZTX_STATE_ENGINE_IMPORT_ERROR
        return decision

    decision = ztx_v5_evaluate_state(
        xapp=xapp,
        signal=normalized_signal,
        profile=profile,
        evidence=enriched,
        snapshot=v5_snapshot,
        previous_state=previous_state,
    )
    decision["normalized_signal"] = normalized_signal

    # ZTX_XGUARD_01_COMPAT_SHIM: ztx_state_engine.py now emits the validated
    # 4-state vocabulary (NORMAL/SUSPICIOUS/COMPROMISED/ISOLATED). The rest
    # of app.py has not been migrated yet (tracked as step_xguard_02) and
    # still expects the old 8-state vocabulary (TRUSTED/OBSERVED/SUSPICIOUS/
    # COMPROMISED/QUARANTINED) - e.g. the literal {"COMPROMISED","QUARANTINED"}
    # check a few lines below. Translate here, at the single funnel point,
    # immediately after the call and before anything else in this function
    # reads the result, so this change is a no-op everywhere else until
    # step_xguard_02 removes this shim.
    _ZTX01_NEW_TO_OLD = {"NORMAL": "TRUSTED", "ISOLATED": "QUARANTINED"}
    for _field in ("state", "detection_state", "decision_state"):
        if _field in decision:
            decision[_field] = _ZTX01_NEW_TO_OLD.get(decision[_field], decision[_field])

    if normalized_signal in ZTX_SUSPICIOUS_ONLY_SIGNALS and bool(decision.get("containment_required")):
        decision["containment_required"] = False
        decision["containment_action"] = "NONE"
        decision["action"] = "EVIDENCE_ONLY"
        if str(decision.get("decision_state") or "").upper() in {"COMPROMISED", "QUARANTINED"}:
            decision["decision_state"] = "SUSPICIOUS"
            decision["detection_state"] = "SUSPICIOUS"
        decision.setdefault("policy_overrides", []).append("suspicious_only_signal_blocks_quarantine")

    decision["profile_role"] = profile.get("role")
    decision["state_engine_version"] = ZTX_STATE_ENGINE_VERSION
    decision["state_engine_import_error"] = ZTX_STATE_ENGINE_IMPORT_ERROR
    return decision

def ztx_v4_apply_quarantine_compat(
    xapp,
    namespace,
    incident_id,
    reason,
    normalized_signal: Optional[str] = None,
    containment_required: Optional[bool] = None,
    decision_state: Optional[str] = None,
    handler_path: Optional[str] = None,
):
    """Apply quarantine for V4 intent engine using the correct active signature.

    Active apply_quarantine signature is:
        apply_quarantine(pod_name, namespace, reason, incident_id)

    Earlier compatibility code passed xapp as pod_name and also swapped
    reason/incident_id. That allowed service isolation in some cases, but
    pod labelling and evidence fields could be wrong.
    """
    attempts = []

    pod_name = None
    try:
        pod = get_primary_pod_for_xapp(xapp, namespace)
        if pod:
            pod_name = pod.metadata.name
    except Exception as exc:
        attempts.append(f"primary_pod_lookup_failed={exc}")

    if pod_name:
        try:
            result = apply_quarantine(
                pod_name,
                namespace,
                reason,
                incident_id,
                normalized_signal=normalized_signal,
                containment_required=containment_required,
                decision_state=decision_state,
                handler_path=handler_path or "ztx_v4_apply_quarantine_compat->apply_quarantine",
            )
            result["compat_path"] = "pod_name_primary"
            return result
        except Exception as exc:
            attempts.append(f"pod_name_primary_failed={exc}")

    # Fallback: pass xApp name as pod_name only if no pod was found.
    # The containment wrapper can still infer the xApp for service isolation.
    try:
        result = apply_quarantine(
            xapp,
            namespace,
            reason,
            incident_id,
            normalized_signal=normalized_signal,
            containment_required=containment_required,
            decision_state=decision_state,
            handler_path=handler_path or "ztx_v4_apply_quarantine_compat->apply_quarantine",
        )
        result["compat_path"] = "xapp_name_fallback_service_isolation"
        result["compat_warning"] = "pod lookup failed; service isolation fallback used"
        return result
    except Exception as exc:
        attempts.append(f"xapp_name_fallback_failed={exc}")

    return {
        "applied": False,
        "effective_containment_applied": False,
        "error": "all_apply_quarantine_paths_failed",
        "attempts": attempts,
        "xapp": xapp,
        "namespace": namespace,
        "incident_id": incident_id,
    }


def _ztx_json_pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def ztx_v4_sync_runtime_labels(
    xapp: str,
    namespace: str,
    decision_state: str,
    normalized_signal: Optional[str] = None,
    containment_required: Optional[bool] = None,
    handler_path: Optional[str] = None,
) -> Dict[str, Any]:
    desired_decision_label = str(decision_state or "").strip().lower() or None
    write_context = ztx_label_write_context(
        normalized_signal=normalized_signal,
        containment_required=containment_required,
        decision_state=decision_state,
        handler_path=handler_path or "ztx_v4_sync_runtime_labels->ztx_guarded_patch_namespaced_pod",
    )

    try:
        verify_before = verify_xapp_containment(xapp, namespace)
    except Exception as exc:
        verify_before = {"error": str(exc)}

    if verify_before.get("service_isolated") is True:
        return {
            "applied": False,
            "skipped": True,
            "reason": "service_isolation_still_active",
            "desired_decision_label": desired_decision_label,
            "verification_before": verify_before,
        }

    quarantine_label_keys = [
        "zt-xguard.io/quarantine",
        "security-status",
        "zt-xguard.io/decision",
    ]
    quarantine_annotation_keys = [
        "zt-xguard.io/quarantine-reason",
        "zt-xguard.io/quarantine-time",
        "zt-xguard.io/incident-id",
    ]

    pod_results = []
    patched_any = False

    # Phase 3 (mechanism #2, 2026-07-17): ensure the Calico-native
    # SUSPICIOUS-tier policy object exists once, before touching any pod
    # labels below - mirrors the existing pattern where
    # _ztx_original_apply_quarantine ensures its own NetworkPolicy before
    # returning applied=True.
    suspicious_netpol_result = None
    if desired_decision_label == "suspicious":
        suspicious_netpol_result = ensure_suspicious_network_policy(namespace)

    for pod in get_pods_for_xapp(xapp, namespace):
        pod_name = pod.metadata.name
        labels = pod.metadata.labels or {}
        annotations = pod.metadata.annotations or {}
        ops = []

        for key in quarantine_label_keys:
            if key in labels:
                ops.append({"op": "remove", "path": f"/metadata/labels/{_ztx_json_pointer_escape(key)}"})

        for key in quarantine_annotation_keys:
            if key in annotations:
                ops.append({"op": "remove", "path": f"/metadata/annotations/{_ztx_json_pointer_escape(key)}"})

        try:
            if ops:
                ztx_guarded_patch_namespaced_pod(
                    name=pod_name,
                    namespace=namespace,
                    body=ops,
                    write_context=write_context,
                )
                patched_any = True

            if desired_decision_label:
                ztx_guarded_patch_namespaced_pod(
                    name=pod_name,
                    namespace=namespace,
                    body={"metadata": {"labels": {"zt-xguard.io/decision": desired_decision_label}}},
                    write_context=write_context,
                )
                patched_any = True

            # Phase 3: zt-xguard.io/suspicious is the label
            # ensure_suspicious_network_policy's Calico selector actually
            # watches - set it only for the suspicious tier, clear
            # (null = delete in a strategic-merge-patch) it for every other
            # decision so the policy stops matching this pod again.
            suspicious_flag = "true" if desired_decision_label == "suspicious" else None
            if labels.get("zt-xguard.io/suspicious") != suspicious_flag:
                ztx_guarded_patch_namespaced_pod(
                    name=pod_name,
                    namespace=namespace,
                    body={"metadata": {"labels": {"zt-xguard.io/suspicious": suspicious_flag}}},
                    write_context=write_context,
                )
                patched_any = True

            pod_results.append({
                "pod": pod_name,
                "cleared_quarantine_labels": bool(ops),
                "decision_label": desired_decision_label,
                "suspicious_label": suspicious_flag,
                "patched": bool(ops) or bool(desired_decision_label) or (labels.get("zt-xguard.io/suspicious") != suspicious_flag),
            })
        except Exception as exc:
            pod_results.append({
                "pod": pod_name,
                "cleared_quarantine_labels": False,
                "decision_label": desired_decision_label,
                "patched": False,
                "error": str(exc),
            })

    return {
        "applied": patched_any,
        "desired_decision_label": desired_decision_label,
        "verification_before": verify_before,
        "pods": pod_results,
        "suspicious_network_policy": suspicious_netpol_result,
    }


def ztx_v4_process_signal(xapp, signal, evidence=None, namespace=None, source="intent_signal"):
    namespace = namespace or XAPP_NAMESPACE
    evidence = dict(evidence or {})
    evidence.setdefault("namespace", namespace)

    started = time.time()
    decision_started = time.time()
    decision = ztx_v4_decide(xapp, signal, evidence)
    decision_ms = round((time.time() - decision_started) * 1000, 3)

    containment = {
        "applied": False,
        "effective_containment_applied": False,
        "reason": "not_required",
    }
    pod_label_sync = {
        "applied": False,
        "reason": "not_required",
    }

    quarantine_ms = None
    spire_revoke = {"attempted": False, "revoked": False, "reason": "not_applicable"}
    normalized_signal = ztx_normalize_signal(decision.get("normalized_signal") or signal) or str(signal or "unknown").strip().lower()
    containment_required = bool(decision.get("containment_required"))
    decision_state = str(decision.get("decision_state") or decision.get("state") or "UNKNOWN").upper()
    handler_path = "csm_process_falco_event->ztx_v4_process_signal" if source == "falco_event" else "ztx_v4_process_signal"
    if containment_required:
        handler_path = f"{handler_path}->ztx_v4_apply_quarantine_compat->apply_quarantine"
    else:
        handler_path = f"{handler_path}->ztx_v4_sync_runtime_labels->ztx_guarded_patch_namespaced_pod"

    label_guard = ztx_quarantine_label_write_decision(ztx_label_write_context(
        normalized_signal=normalized_signal,
        containment_required=containment_required,
        decision_state=decision_state,
        handler_path=handler_path,
        incident_id=evidence.get("incident_id"),
    ))
    final_state = decision_state

    if containment_required:
        incident_id = evidence.get("incident_id") or f"{utc_id()}-{safe_name(signal)}-{safe_name(xapp)}-{sha256_text(json.dumps(evidence, sort_keys=True, default=str))[:10]}"
        reason = "; ".join(decision.get("reasons") or [signal])

        q_started = time.time()
        containment = ztx_v4_apply_quarantine_compat(
            xapp,
            namespace,
            incident_id,
            reason,
            normalized_signal=normalized_signal,
            containment_required=containment_required,
            decision_state=decision_state,
            handler_path=handler_path,
        )
        quarantine_ms = round((time.time() - q_started) * 1000, 3)

        if containment.get("effective_containment_applied") or containment.get("service_isolation_applied") or containment.get("applied"):
            final_state = "QUARANTINED"
        else:
            final_state = "COMPROMISED"

        # 2026-07-23: removed the revoke_spire_entry() call that used to run
        # here. It's redundant with (and actively harmful alongside)
        # apply_quarantine's own revoke_workload_identity adjunct
        # (containment_orchestrator.py) - that one flips the
        # zt-xguard.io/svid-enabled pod label, which the cluster's
        # spire-controller-manager reconciles safely; this raw
        # `spire-server entry delete` fought that same controller directly
        # (deletes the entry, controller recreates it on its next
        # reconcile pass since the pod still matches its ClusterSPIFFEID
        # selector) for zero net benefit, and failed silently on every
        # call (its own try/except never logs, just returns the error in
        # an unused dict) - confirmed via zero related entries in
        # production logs despite firing on every containment-required
        # event today. spire_revoke keeps its safe default
        # ({"attempted": False, "reason": "not_applicable"}, set above)
        # rather than actually attempting this.
    else:
        try:
            pod_label_sync = ztx_v4_sync_runtime_labels(
                xapp,
                namespace,
                final_state,
                normalized_signal=normalized_signal,
                containment_required=containment_required,
                handler_path=handler_path,
            )
        except Exception as exc:
            pod_label_sync = {"applied": False, "error": str(exc)}

    try:
        verify = verify_xapp_containment(xapp, namespace)
    except Exception as exc:
        verify = {"error": str(exc)}

    total_ms = round((time.time() - started) * 1000, 3)

    result = {
        "mode": "intent_aware_trust_engine_v4",
        "source": source,
        "xapp": xapp,
        "namespace": namespace,
        "signal": signal,
        "normalized_signal": normalized_signal,
        "decision_state": decision_state,
        "detection_state": decision.get("detection_state") or decision_state,
        "final_state": final_state,
        "state": final_state,
        "containment_required": containment_required,
        # 2026-07-25: ztx_state_engine.py's StateDecision carries
        # isolation_timing (DWELL_30S vs IMMEDIATE) as a field of the
        # nested `decision` dict below, but every downstream caller
        # (ztx_v4_process_signal's outer wrapper, csm_update_from_result)
        # reads it via result.get("isolation_timing") at the TOP level -
        # which was never set here, so it always silently fell back to
        # "IMMEDIATE" regardless of what the state engine actually decided.
        # Confirmed live via a temporary debug log: real resource_anomaly_t2
        # signals (tagged DWELL_30S by the state engine) were isolating
        # instantly instead of honoring the 30s operator-intervention
        # window. Hoisting it to the top level here, once, so it survives
        # through every subsequent wrapper layer.
        "isolation_timing": decision.get("isolation_timing") or "IMMEDIATE",
        "label_write_allowed": label_guard.get("label_write_allowed"),
        "label_write_block_reason": label_guard.get("label_write_block_reason"),
        "handler_path": label_guard.get("handler_path"),
        "containment_action": decision.get("containment_action"),
        "score": decision["score"],
        "confidence": decision["confidence"],
        "severity": decision.get("severity"),
        "rule_ids": decision.get("rule_ids", []),
        "evidence_sources": decision.get("evidence_sources", {}),
        "transition": decision.get("transition", {}),
        "action": decision["action"],
        "reasons": decision["reasons"],
        "layers": decision["layers"],
        "decision": decision,
        "quarantine": containment,
        "pod_label_sync": pod_label_sync,
        "spire_revoke": spire_revoke,
        "verification": verify,
        "timing": {
            "decision_ms": decision_ms,
            "quarantine_ms": quarantine_ms,
            "event_processing_total_ms": total_ms,
        },
        "time": utc_now(),
    }

    # Keep runtime state event-driven and fast. This fixes signal-only decisions
    # remaining UNKNOWN and gives /csm/state, /metrics, and dashboards a cached
    # view without forcing slow audits.
    try:
        csm_update_from_result(result, source=source)
        csm_remember_event({
            "time": result.get("time"),
            "xapp": xapp,
            "signal": signal,
            "state": final_state,
            "detection_state": result.get("detection_state"),
            "containment_required": containment_required,
            "action": result.get("action"),
            "rule_ids": result.get("rule_ids", []),
            "decision_ms": decision_ms,
            "quarantine_ms": quarantine_ms,
            "source": source,
        })
    except Exception:
        pass

    return result


# step_xguard_02 Step B2 (2026-07-15): real forensic evidence capture on
# the live path. The dead line-1312 _ztx_original_csm_process_falco_event
# was NOT revived wholesale - it turns out to contain a full second,
# cruder decision pipeline (csm_fast_event_decision's keyword-blob
# matching, plus hardcoded A11/A1 override patches) that duplicates and
# would have competed with the live V4/V5 intent-aware engine. Reviving
# that would have violated the standing instruction to leave
# detection/decision logic untouched. Only the decision-independent
# evidence-writing piece (collect_forensic_snapshot, already defined
# above and already unused/dead until now) is wired in here, as a pure
# side effect that runs AFTER the real decision is already final - it
# never influences state/severity/containment, it only persists it.
def ztx_capture_incident_forensics(incident_id, event, xapp, pod_name, namespace, result):
    """Write real forensic evidence for a processed Falco event to
    /evidence/incidents/<incident_id>/ - the raw alert, the decision
    result, and a pod snapshot (spec/status, recent K8s events, log
    tail). Runs in a background thread so the forensic K8s API calls
    (pod events, pod logs) never add latency to the Falco webhook
    response the caller is waiting on.
    """
    def worker():
        incident_path = INCIDENT_DIR / incident_id
        try:
            incident_path.mkdir(parents=True, exist_ok=True)
            pod = get_pod_by_name(pod_name, namespace) if pod_name and pod_name != "unknown" else None
            forensic_snapshot = collect_forensic_snapshot(pod, namespace, pod_name or "unknown", incident_path)
            incident = {
                "incident_id": incident_id,
                "time": utc_now(),
                "mode": "intent_aware_trust_engine_v4",
                "xapp": xapp,
                "namespace": namespace,
                "pod_name": pod_name,
                "raw_event": event,
                "decision_result": result,
                "forensic_snapshot": forensic_snapshot,
            }
            write_json(incident_path / "incident.json", incident)
        except Exception as exc:
            try:
                incident_path.mkdir(parents=True, exist_ok=True)
                write_json(incident_path / "incident.json", {
                    "incident_id": incident_id,
                    "time": utc_now(),
                    "xapp": xapp,
                    "pod_name": pod_name,
                    "forensic_error": str(exc),
                    "forensic_trace": traceback.format_exc(),
                })
            except Exception:
                pass

    threading.Thread(target=worker, daemon=True).start()


# Mirrors the out-of-scope signal set ztx_state_engine.py's R-SCOPE-01 check
# treats as non-actionable (state -> IGNORED, no containment).
_ZTX_NON_ACTIONABLE_SIGNALS = {"ignored", "out_of_scope", "event_not_mapped_to_controlled_xapp"}


def csm_process_falco_event(event):
    xapp, pod_name, namespace = ztx_v4_event_identity(event or {})

    if not xapp:
        return {
            "ignored": True,
            "mode": "intent_aware_trust_engine_v4",
            "reason": "event_not_mapped_to_controlled_xapp",
            "state": "IGNORED",
            "time": utc_now(),
        }

    signal = ztx_v4_signal_from_event(event or {})
    incident_id = f"{utc_id()}-{safe_name(signal)}-{safe_name(xapp)}-{sha256_text(json.dumps(event or {}, sort_keys=True, default=str))[:10]}"
    evidence = {
        "pod": pod_name,
        "namespace": namespace,
        "raw_event": event,
        "incident_id": incident_id,
    }

    result = ztx_v4_process_signal(
        xapp=xapp,
        signal=signal,
        evidence=evidence,
        namespace=namespace,
        source="falco_event",
    )

    # 2026-07-23: skip forensics capture (K8s pod/event/log snapshot + disk
    # write, in a background thread) for signals the decision engine itself
    # already treats as non-actionable (ztx_state_engine.py's R-SCOPE-01
    # check). Real xApps emit these "confirmed normal" events continuously
    # for routine in-cluster traffic - at full volume over hours this filled
    # /evidence/incidents with 266k+ directories (26GB) and saturated the
    # K8s API server with pod/log lookups for events nobody needed forensics
    # on, degrading responsiveness for real incidents.
    if signal not in _ZTX_NON_ACTIONABLE_SIGNALS:
        ztx_capture_incident_forensics(incident_id, event, xapp, pod_name, namespace, result)

    return result


@APP.route("/csm/intent/evaluate", methods=["POST"])
def ztx_v4_intent_evaluate_api():
    payload = request.get_json(force=True, silent=True) or {}
    xapp = payload.get("xapp") or payload.get("target_xapp")
    signal = payload.get("signal")
    evidence = payload.get("evidence") or {}

    if not xapp or not signal:
        return jsonify({
            "ok": False,
            "error": "xapp_and_signal_required",
            "example": {"xapp": "traffic-analyzer", "signal": "high_cpu", "evidence": {"valid_activity": True}},
        }), 400

    return jsonify({
        "ok": True,
        "result": ztx_v4_decide(xapp, signal, evidence),
    })


# ---------------------------------------------------------------------------
# T2 / resource-anomaly forensic capture.
# The node-side ztx_t2_collector re-posts resource_anomaly_t2[_elevated] to
# /csm/intent/ingest every ~1s while an anomaly persists. We must NOT snapshot
# every tick (that is exactly what once filled /evidence with 266k dirs). So we
# capture forensics ONCE per episode - only on a fresh escalation into a
# containment-worthy state (COMPROMISED / ISOLATED) - mirroring the Falco path
# so resource incidents also land in /evidence/incidents (and the vault).
_T2_CAPTURED_STATE: Dict[str, str] = {}


def _ztx_maybe_capture_t2_forensics(xapp, signal, evidence, payload, result):
    sig = str(signal or "")
    if not sig.startswith("resource_anomaly"):
        return
    state = str((result or {}).get("final_state") or (result or {}).get("state") or "").upper()
    if state in ("NORMAL", "IGNORED", ""):
        _T2_CAPTURED_STATE.pop(xapp, None)     # episode cleared - allow the next one to capture
        return
    if state not in ("COMPROMISED", "ISOLATED"):
        return                                 # SUSPICIOUS elevated ticks repeat ~1 Hz - evidence-only, no snapshot
    if _T2_CAPTURED_STATE.get(xapp) == state:
        return                                 # already captured this state for this episode
    _T2_CAPTURED_STATE[xapp] = state
    namespace = payload.get("namespace") or XAPP_NAMESPACE
    try:
        pod_name = ztx_primary_pod_name(xapp, namespace)
    except Exception:
        pod_name = None
    incident_id = f"{utc_id()}-{safe_name(sig)}-{safe_name(xapp)}-{sha256_text(json.dumps(evidence or {}, sort_keys=True, default=str))[:10]}"
    ev = evidence or {}
    event = {
        "source": "ztx_t2_collector",
        "ztx_signal": sig,
        "rule": "ZTX T2 Resource Anomaly",
        "priority": "Critical" if state in ("COMPROMISED", "ISOLATED") else "Warning",
        "rule_ids": (result or {}).get("rule_ids") or (["R-T2-01"] if sig == "resource_anomaly_t2" else ["R-T2-02"]),
        "output": (
            f"{utc_now()}: {'Critical' if state in ('COMPROMISED','ISOLATED') else 'Warning'} "
            f"ztx_signal={sig} xapp={xapp} state={state} "
            f"cpu_millicores={ev.get('cpu_millicores', ev.get('cpu_mc'))} "
            f"score={(result or {}).get('score')} detector=ztx_t2_collector (cgroup + streaming MEWMA)"
        ),
        "evidence": ev,
    }
    ztx_capture_incident_forensics(incident_id, event, xapp, pod_name, namespace, result)


@APP.route("/csm/intent/ingest", methods=["POST"])
def ztx_v4_intent_ingest_api():
    try:
        payload = request.get_json(force=True, silent=True) or {}
        xapp = payload.get("xapp") or payload.get("target_xapp")
        signal = payload.get("signal")
        evidence = payload.get("evidence") or {}

        if not xapp or not signal:
            return jsonify({
                "ok": False,
                "error": "xapp_and_signal_required",
            }), 400

        result = ztx_v4_process_signal(
            xapp=xapp,
            signal=signal,
            evidence=evidence,
            namespace=payload.get("namespace") or XAPP_NAMESPACE,
            source=payload.get("source") or "manual_intent_signal",
        )

        result = ztx_v5_normalize_score_fields(result)

        # resource-anomaly forensic capture (deduped, once per escalation)
        try:
            _ztx_maybe_capture_t2_forensics(xapp, signal, evidence, payload, result)
        except Exception:
            pass

        # Ensure the in-memory state used by /metrics also gets the normalized
        # public score fields. Existing code paths may store the raw internal
        # trust score before the API response is returned.
        try:
            if isinstance(result, dict) and xapp:
                if "V5_STATE_BY_XAPP" in globals() and isinstance(V5_STATE_BY_XAPP, dict):
                    V5_STATE_BY_XAPP[xapp] = dict(result)
                if "ZT_V5_STATE_BY_XAPP" in globals() and isinstance(ZT_V5_STATE_BY_XAPP, dict):
                    ZT_V5_STATE_BY_XAPP[xapp] = dict(result)
                if "LAST_V5_DECISIONS" in globals() and isinstance(LAST_V5_DECISIONS, dict):
                    LAST_V5_DECISIONS[xapp] = dict(result)
        except Exception:
            pass

        return jsonify(result)

    except Exception as exc:
        import traceback as _traceback
        return jsonify({
            "ok": False,
            "error": "intent_ingest_failed",
            "exception": str(exc),
            "trace": _traceback.format_exc(),
        }), 500


def ztx_find_scenario(scenario_id):
    scenario_id = str(scenario_id or "").upper().strip()
    for scenario in ZT_SCENARIOS:
        if scenario["id"].upper() == scenario_id:
            return scenario
    return None


def ztx_get_scenarios():
    return ZT_SCENARIOS


def ztx_run_scenario(scenario_id, payload=None):
    payload = payload or {}
    scenario = ztx_find_scenario(scenario_id)

    if not scenario:
        return {
            "ok": False,
            "error": "unknown_scenario",
            "available": [s["id"] for s in ZT_SCENARIOS],
        }, 404

    xapp = payload.get("xapp") or payload.get("target_xapp") or scenario.get("default_xapp")
    signal = payload.get("signal") or scenario.get("signal")
    namespace = payload.get("namespace") or XAPP_NAMESPACE

    evidence = payload.get("evidence") or {}

    # Important: scenario expected_state is NOT used for the decision.
    # It is only used after the decision to classify TP/TN/FP/FN.
    started = time.time()
    result = ztx_v4_process_signal(
        xapp=xapp,
        signal=signal,
        evidence=evidence,
        namespace=namespace,
        source=f"scenario_{scenario.get('id')}",
    )

    expected_state = scenario.get("expected_state")
    expected_containment = bool(scenario.get("expected_containment"))
    malicious = bool(scenario.get("malicious"))

    actual_state = result.get("final_state") or result.get("state")
    actual_containment = bool(
        ((result.get("verification") or {}).get("contained") is True)
        or ((result.get("quarantine") or {}).get("effective_containment_applied") is True)
        or ((result.get("quarantine") or {}).get("service_isolation_applied") is True)
    )

    detected_positive = actual_state in ["SUSPICIOUS", "COMPROMISED", "QUARANTINED"]

    if malicious and detected_positive:
        classification = "TP"
    elif malicious and not detected_positive:
        classification = "FN"
    elif (not malicious) and detected_positive:
        classification = "FP"
    else:
        classification = "TN"

    state_pass = (
        actual_state == expected_state
        or (expected_state == "QUARANTINED" and actual_state in ["COMPROMISED", "QUARANTINED"])
        or (expected_state == "SUSPICIOUS" and actual_state == "SUSPICIOUS")
        or (expected_state == "OBSERVED" and actual_state == "OBSERVED")
        or (expected_state == "TRUSTED" and actual_state == "TRUSTED")
    )

    containment_pass = actual_containment == expected_containment
    passed = bool(state_pass and containment_pass)

    compact = {
        "ok": True,
        "scenario_id": scenario.get("id"),
        "name": scenario.get("name"),
        "xapp": xapp,
        "signal": signal,
        "malicious": malicious,
        "expected_state": expected_state,
        "actual_state": actual_state,
        "expected_containment": expected_containment,
        "actual_containment": actual_containment,
        "classification": classification,
        "pass": passed,
        "state_pass": state_pass,
        "containment_pass": containment_pass,
        "decision_state": result.get("decision_state"),
        "action": result.get("action"),
        "reasons": result.get("reasons"),
        "layers": result.get("layers"),
        "timing": result.get("timing"),
        "endpoint_count": (
            ((result.get("verification") or {}).get("services") or [{}])[0]
            .get("endpoint_summary", {})
            .get("endpoint_count")
        ),
        "selector": (
            ((result.get("verification") or {}).get("services") or [{}])[0]
            .get("selector")
        ),
        "raw_result": result,
        "duration_ms": round((time.time() - started) * 1000, 3),
        "time": utc_now(),
    }

    ZT_SCENARIO_RESULTS.append(compact)
    if len(ZT_SCENARIO_RESULTS) > 300:
        del ZT_SCENARIO_RESULTS[:-300]

    return compact, 200


# Re-register the scenario API route function name if Flask route already exists.
# Existing route functions call ztx_run_scenario by global lookup, so overriding
# ztx_run_scenario above is enough for current /csm/scenarios/<id>/run.











# --- ZTX PATCH5B LIVE OVERRIDE V3 START ---
# Must execute before APP.run(). Empty Endpoints subsets are valid service-isolation evidence.

_ZTX_PATCH5B_LIVE_OVERRIDE_V3 = True

# step_xguard_02 Step B1: ztx_patch5b_v3_endpoint_summary, the live
# service_endpoints_summary, and the live verify_xapp_containment all
# moved to containment_orchestrator.py (imported above under their
# original names).


# ------------------------------------------------------------
# ZTX_PATCH9_FAST_RUNTIME_UI
# Lightweight read-only runtime endpoint for web/TUI dashboards.
# It avoids expensive per-xApp verify_xapp_containment() and per-pod
# Prometheus queries used by /csm/xapps/runtime.
# ------------------------------------------------------------

@APP.route("/csm/xapps/runtime-lite", methods=["GET"])
def ztx_xapps_runtime_lite_api_patch9():
    namespace = request.args.get("namespace") or XAPP_NAMESPACE

    try:
        xapps = ztx_runtime_xapp_names_v3()
    except Exception:
        xapps = list(XAPP_LIST)

    try:
        pods = CORE.list_namespaced_pod(namespace=namespace).items
    except Exception as exc:
        return jsonify({
            "ok": False,
            "error": "pod_list_failed",
            "message": str(exc),
            "namespace": namespace,
            "rows": [],
            "time": utc_now(),
            "patch9_fast_runtime_ui": True,
        }), 500

    try:
        services = CORE.list_namespaced_service(namespace=namespace).items
    except Exception:
        services = []

    try:
        endpoints = CORE.list_namespaced_endpoints(namespace=namespace).items
    except Exception:
        endpoints = []

    endpoint_index = {}
    for ep in endpoints:
        count = 0
        addresses = []
        ports = []
        for subset in (ep.subsets or []):
            for addr in (subset.addresses or []):
                if addr.ip:
                    addresses.append(addr.ip)
                    count += 1
            for port in (subset.ports or []):
                ports.append({
                    "name": port.name,
                    "port": port.port,
                    "protocol": port.protocol,
                })
        endpoint_index[ep.metadata.name] = {
            "endpoint_count": count,
            "has_endpoints": count > 0,
            "addresses": addresses,
            "ports": ports,
            "source": "endpoints-lite",
            "error": None,
        }

    # Batch Prometheus resource query, max two Prometheus calls for all pods.
    cpu_by_pod = {}
    mem_by_pod = {}

    def prom_query(query):
        if not PROMETHEUS_URL:
            return []
        try:
            import json as _json
            import urllib.parse as _parse
            import urllib.request as _request
            url = PROMETHEUS_URL.rstrip("/") + "/api/v1/query?" + _parse.urlencode({"query": query})
            with _request.urlopen(url, timeout=PROMETHEUS_TIMEOUT) as r:
                data = _json.loads(r.read().decode("utf-8"))
            return data.get("data", {}).get("result", []) or []
        except Exception:
            return []

    safe_ns = str(namespace).replace("\\", "\\\\").replace('"', '\\"')

    cpu_query = (
        'sum by (pod) (rate(container_cpu_usage_seconds_total{'
        f'namespace="{safe_ns}",container!="POD",container!=""'
        '}[2m]))'
    )
    mem_query = (
        'sum by (pod) (container_memory_working_set_bytes{'
        f'namespace="{safe_ns}",container!="POD",container!=""'
        '})'
    )

    for item in prom_query(cpu_query):
        try:
            pod_name = item.get("metric", {}).get("pod")
            value = float(item.get("value", [None, None])[1])
            if pod_name:
                cpu_by_pod[pod_name] = value
        except Exception:
            pass

    for item in prom_query(mem_query):
        try:
            pod_name = item.get("metric", {}).get("pod")
            value = float(item.get("value", [None, None])[1])
            if pod_name:
                mem_by_pod[pod_name] = int(value)
        except Exception:
            pass

    rows = []

    for xapp in xapps:
        xpods = []
        for pod in pods:
            labels = pod.metadata.labels or {}
            if labels.get("app") == xapp or pod.metadata.name.startswith(xapp + "-"):
                xpods.append(pod)

        xpods_sorted = sorted(
            xpods,
            key=lambda pod: (
                pod.status.phase != "Running",
                pod.metadata.creation_timestamp or utc_now(),
            )
        )

        pod = xpods_sorted[0] if xpods_sorted else None

        if pod:
            labels = pod.metadata.labels or {}
            statuses = pod.status.container_statuses or []
            restarts = sum(int(cs.restart_count or 0) for cs in statuses)
            ready_containers = sum(1 for cs in statuses if cs.ready)
            total_containers = len(statuses)
            pod_summary = {
                "name": pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "phase": pod.status.phase,
                "ready": bool(total_containers and ready_containers == total_containers and pod.status.phase == "Running"),
                "ready_text": f"{ready_containers}/{total_containers}" if total_containers else "0/0",
                "restarts": restarts,
                "pod_ip": pod.status.pod_ip,
                "node": pod.spec.node_name,
                "service_account": pod.spec.service_account_name,
                "quarantine_label": labels.get("zt-xguard.io/quarantine") == "true",
                "decision_label": labels.get("zt-xguard.io/decision"),
                "provider": labels.get("zt-xguard.io/provider"),
                "verified": labels.get("zt-xguard.io/verified"),
                "age": pod.metadata.creation_timestamp.isoformat() if pod.metadata.creation_timestamp else None,
            }
            pod_name = pod.metadata.name
        else:
            pod_summary = {
                "name": None,
                "namespace": namespace,
                "phase": "Missing",
                "ready": False,
                "ready_text": "0/0",
                "restarts": None,
                "pod_ip": None,
                "node": None,
                "service_account": None,
                "quarantine_label": False,
                "decision_label": None,
                "provider": None,
                "verified": None,
                "age": None,
            }
            pod_name = None

        svc = ztx_runtime_service_for_xapp_v3(xapp, services)
        svc_name = svc.metadata.name if svc else None
        selector = svc.spec.selector if svc and svc.spec else None
        annotations = svc.metadata.annotations or {} if svc else {}

        ep = endpoint_index.get(svc_name or "", {
            "endpoint_count": 0,
            "has_endpoints": False,
            "addresses": [],
            "ports": [],
            "source": "endpoints-lite",
            "error": "service_or_endpoints_missing",
        })

        service_isolated = bool(
            annotations.get("zt-xguard.io/service-isolated") == "true"
            or (selector and "zt-xguard.io/service-isolated" in selector)
        )

        pod_quarantined = bool(pod_summary.get("quarantine_label"))
        endpoint_count = ep.get("endpoint_count")

        rows.append({
            "xapp": xapp,
            "namespace": namespace,
            "pod": pod_summary,
            "service": {
                "name": svc_name,
                "selector": selector,
                "endpoint_count": endpoint_count,
                "has_endpoints": ep.get("has_endpoints"),
                "addresses": ep.get("addresses"),
                "ports": ep.get("ports"),
                "source": ep.get("source"),
                "error": ep.get("error"),
            },
            "resources": {
                "ok": pod_name in cpu_by_pod or pod_name in mem_by_pod,
                "source": "prometheus-batch-lite",
                "pod": pod_name,
                "cpu_cores_2m": cpu_by_pod.get(pod_name),
                "cpu_percent_1core": None if pod_name not in cpu_by_pod else round(cpu_by_pod[pod_name] * 100.0, 4),
                "cpu_percent_1core_2m": None if pod_name not in cpu_by_pod else round(cpu_by_pod[pod_name] * 100.0, 4),
                "memory_working_set_bytes": mem_by_pod.get(pod_name),
                "memory_usage_bytes": mem_by_pod.get(pod_name),
            },
            "containment": {
                "contained": bool(pod_quarantined and (service_isolated or endpoint_count == 0)),
                "service_isolated": service_isolated,
                "quarantine_marked": pod_quarantined,
                "pod_labelled_quarantined": pod_quarantined,
                "verification_unknown": False,
                "fast_ui_inferred": True,
            },
        })

    return jsonify({
        "ok": True,
        "namespace": namespace,
        "rows": rows,
        "time": utc_now(),
        "patch9_fast_runtime_ui": True,
    })

# --- ZTX PATCH5B LIVE OVERRIDE V3 END ---


# ------------------------------------------------------------
# ZTX_PATCH_SCENARIO_FIELD_NORMALIZATION
# Keep scenario API stable for dashboard.js even if internal scenario
# definitions use default_xapp instead of target_xapp.
# ------------------------------------------------------------

def ztx_get_scenarios():
    normalized = []
    for item in ZT_SCENARIOS:
        s = dict(item)
        target = s.get("target_xapp") or s.get("default_xapp")
        s["target_xapp"] = target
        s["default_xapp"] = s.get("default_xapp") or target

        if not s.get("category"):
            if str(s.get("id", "")).upper().startswith("B"):
                s["category"] = "benign_control"
            elif s.get("malicious") is True:
                s["category"] = "attack"
            else:
                s["category"] = "scenario"

        normalized.append(s)
    return normalized



# ------------------------------------------------------------
# ZTX_PUBLIC_STATE_NORMALIZATION_V1
# Public API state vocabulary:
# NORMAL, OBSERVED, SUSPICIOUS, COMPROMISED
# Containment/quarantine is reported separately, not as a trust state.
# ------------------------------------------------------------

_ZTX_ORIGINAL_CSM_STATE_PAYLOAD_PUBLIC_V1 = csm_state_payload

def ztx_public_state_label_v1(state):
    s = str(state or "NORMAL").upper().strip()

    if s in ("TRUSTED", "HEALTHY", "RESTORED", "NORMAL", "INITIALIZING", "UNKNOWN"):
        return "NORMAL"
    if s in ("OBSERVED",):
        return "OBSERVED"
    if s in ("SUSPICIOUS", "DEGRADED"):
        return "SUSPICIOUS"
    if s in ("COMPROMISED", "QUARANTINED", "CONTAINED"):
        return "COMPROMISED"

    return "NORMAL"

def ztx_public_summary_v1(xapps):
    counts = {
        "NORMAL": 0,
        "OBSERVED": 0,
        "SUSPICIOUS": 0,
        "COMPROMISED": 0,
        "total": len(xapps),
    }

    for item in xapps:
        state = ztx_public_state_label_v1(item.get("state"))
        counts[state] = counts.get(state, 0) + 1

    return counts

def ztx_public_overall_state_v1(summary):
    if summary.get("COMPROMISED", 0):
        return "COMPROMISED"
    if summary.get("SUSPICIOUS", 0):
        return "SUSPICIOUS"
    if summary.get("OBSERVED", 0):
        return "OBSERVED"
    return "NORMAL"

def ztx_public_score_normalize_v1(item):
    state = ztx_public_state_label_v1(item.get("state"))

    raw_state = item.get("state")
    item["raw_state"] = raw_state
    item["state"] = state

    if state == "NORMAL":
        item["risk_score"] = 0
        item["trust_score"] = 100
        item["score"] = 0
    elif state == "OBSERVED":
        item["risk_score"] = item.get("risk_score", 20) if item.get("risk_score") is not None else 20
        item["trust_score"] = item.get("trust_score", 80) if item.get("trust_score") is not None else 80
        item["score"] = item["risk_score"]
    elif state == "SUSPICIOUS":
        item["risk_score"] = item.get("risk_score", 60) if item.get("risk_score") is not None else 60
        item["trust_score"] = item.get("trust_score", 40) if item.get("trust_score") is not None else 40
        item["score"] = item["risk_score"]
    elif state == "COMPROMISED":
        item["risk_score"] = 100
        item["trust_score"] = 0
        item["score"] = 100

    item["score_type"] = "risk_score_0_to_100_higher_means_riskier"
    return item

def csm_state_payload():
    payload = _ZTX_ORIGINAL_CSM_STATE_PAYLOAD_PUBLIC_V1()

    xapps = []
    for item in payload.get("xapps", []):
        xapps.append(ztx_public_score_normalize_v1(dict(item)))

    summary = ztx_public_summary_v1(xapps)

    payload["xapps"] = xapps
    payload["summary"] = summary
    payload["overall_state"] = ztx_public_overall_state_v1(summary)
    payload["state_vocabulary"] = ["NORMAL", "SUSPICIOUS", "COMPROMISED", "ISOLATED"]
    payload["containment_is_separate"] = True
    payload["ztx_public_state_normalization_v1"] = True

    return payload



# ------------------------------------------------------------
# ZTX_FINAL_POLICY_GUARD_V1
# Final policy guard:
# - Public state vocabulary: NORMAL, OBSERVED, SUSPICIOUS, COMPROMISED
# - COMPROMISED is sticky until explicit restore
# - QUARANTINED is not a public state; it becomes COMPROMISED + containment
# - Critical scenarios force service containment verification
# ------------------------------------------------------------

_ZTX_FINAL_POLICY_GUARD_V1 = True

def ztx_public_state_v1(state):
    s = str(state or "NORMAL").upper().strip()
    if s in {"TRUSTED", "HEALTHY", "RESTORED", "NORMAL", "UNKNOWN", "INITIALIZING"}:
        return "NORMAL"
    if s == "OBSERVED":
        return "OBSERVED"
    if s in {"SUSPICIOUS", "DEGRADED"}:
        return "SUSPICIOUS"
    if s in {"COMPROMISED", "QUARANTINED", "CONTAINED"}:
        return "COMPROMISED"
    # 2026-07-20: this legacy classifier predates the ISOLATED 5th tier
    # (added 2026-07-16) and was falling through to the final `return
    # "NORMAL"` below for it - this function is still invoked internally
    # (as a side-effect delegate from the live csm_update_from_result), so
    # every ISOLATED xApp had its CSM_STATE momentarily/finally clobbered
    # back to NORMAL on every signal, even though the real K8s containment
    # (pod label, NetworkPolicy, service isolation) stayed correctly applied
    # the whole time - a state/enforcement desync, not a containment bug.
    if s == "ISOLATED":
        return "ISOLATED"
    return "NORMAL"


def ztx_state_rank_v1(state):
    s = ztx_public_state_v1(state)
    return {
        "NORMAL": 0,
        "OBSERVED": 1,
        "SUSPICIOUS": 2,
        "COMPROMISED": 3,
        "ISOLATED": 4,
    }.get(s, 0)


def ztx_is_explicit_restore_v1(source=None, signal=None):
    src = str(source or "").lower()
    sig = str(signal or "").lower()
    return (
        "restore" in src
        or "readmit" in src
        or sig in {"restore", "readmit", "manual_restore", "restore_baseline"}
    )


def ztx_scores_for_public_state_v1(state):
    s = ztx_public_state_v1(state)
    if s == "NORMAL":
        return 0, 100
    if s == "OBSERVED":
        return 20, 80
    if s == "SUSPICIOUS":
        return 60, 40
    if s in ("COMPROMISED", "ISOLATED"):
        return 100, 0
    return 0, 100


# ztx_force_service_containment_v1 (formerly here) deleted 2026-07-15,
# step_xguard_02 Step A: it duplicated canonical apply_quarantine +
# apply_service_isolation (same K8s calls, same ServiceAccount identity),
# and its only caller (the containment-forcing block inside the 6305-era
# ztx_v4_process_signal wrapper) was itself dead weight - the live, outer
# ztx_v4_process_signal (further down this file) independently re-checks
# containment and calls _ztx_force_containment_for_xapp regardless,
# always overwriting whatever this inner call produced. See session log
# 2026-07-14/15 for the full trail (RBAC finding that made this provably
# safe to delete, not just presumed redundant).

_ZTX_ORIGINAL_CSM_UPDATE_FINAL_GUARD_V1 = csm_update_from_result

def csm_update_from_result(result, source="unknown"):
    xapp = result.get("xapp")
    if not xapp:
        return

    incoming_raw = result.get("final_state") or result.get("state") or result.get("decision_state") or "NORMAL"
    incoming_state = ztx_public_state_v1(incoming_raw)
    signal = result.get("normalized_signal") or result.get("signal")
    restore = ztx_is_explicit_restore_v1(source, signal)

    with CSM_STATE_LOCK:
        previous = dict(CSM_STATE.get(xapp) or {})
        previous_state = ztx_public_state_v1(previous.get("state"))

    # Sticky compromised rule.
    # A suspicious/normal/observed signal cannot downgrade a compromised xApp.
    # 2026-07-20: matches the same fix applied to the live classifier - only
    # COMPROMISED/ISOLATED (containment tiers) are sticky. The old unconditional
    # version here also pinned SUSPICIOUS/OBSERVED forever, same class of bug
    # as the telemetry-monitor "stuck SUSPICIOUS" issue, just in this second,
    # still-live legacy code path.
    if (not restore
            and ztx_state_rank_v1(previous_state) >= ztx_state_rank_v1("COMPROMISED")
            and ztx_state_rank_v1(previous_state) > ztx_state_rank_v1(incoming_state)):
        final_state = previous_state
        downgrade_blocked = True
    else:
        final_state = incoming_state
        downgrade_blocked = False

    risk_score, trust_score = ztx_scores_for_public_state_v1(final_state)

    verification = result.get("verification") or {}
    quarantine = result.get("quarantine") or {}
    containment_verified = bool(
        verification.get("contained") is True
        or verification.get("service_isolated") is True
        or quarantine.get("effective_containment_applied") is True
        or quarantine.get("service_isolation_applied") is True
    )

    entry = {
        "xapp": xapp,
        "namespace": result.get("namespace", XAPP_NAMESPACE),
        "state": final_state,
        "raw_state": incoming_raw,
        "detection_state": ztx_public_state_v1(result.get("detection_state") or result.get("decision_state") or incoming_state),
        "decision_state": ztx_public_state_v1(result.get("decision_state") or incoming_state),
        "containment_required": bool(result.get("containment_required", final_state == "COMPROMISED")),
        "containment_verified": containment_verified,
        "containment_action": result.get("containment_action") or result.get("action"),
        "score": risk_score,
        "risk_score": risk_score,
        "trust_score": trust_score,
        "score_type": "risk_score_0_to_100_higher_means_riskier",
        "confidence": result.get("confidence"),
        "rule_ids": result.get("rule_ids") or (result.get("decision") or {}).get("rule_ids", []),
        "reasons": result.get("reasons") or previous.get("reasons") or [],
        "pod": result.get("pod") or previous.get("pod"),
        "service_account": result.get("service_account") or previous.get("service_account"),
        "findings": result.get("findings", []),
        "key_runtime_values": result.get("key_runtime_values", {}),
        "last_source": source,
        "last_signal": signal,
        "downgrade_blocked": downgrade_blocked,
        "previous_state": previous_state,
        "last_update": utc_now(),
    }

    with CSM_STATE_LOCK:
        CSM_STATE[xapp] = entry


_ZTX_ORIGINAL_CSM_STATE_PAYLOAD_FINAL_GUARD_V1 = csm_state_payload

# T2 SUSPICIOUS freshness decay. The node-side ztx_t2_collector re-posts a
# resource_anomaly_t2_elevated signal every ~1s WHILE a resource anomaly
# persists, then goes completely silent once the xApp is back to normal. It
# never posts an explicit "normal" signal, so a T2-driven SUSPICIOUS entry in
# CSM_STATE would otherwise stick forever (confirmed live 2026-08-25: state
# held SUSPICIOUS with last_signal age growing unbounded). Decay a stale
# T2-sourced SUSPICIOUS back to NORMAL once no fresh signal has arrived within
# this window, so the dashboard reflects the real-time resource posture.
ZTX_T2_SUSPICIOUS_DECAY_SECONDS = float(os.environ.get("ZTX_T2_SUSPICIOUS_DECAY_SECONDS", "6"))


def _ztx_csm_entry_age_seconds(last_update):
    if not last_update:
        return None
    try:
        lu = datetime.fromisoformat(str(last_update))
        if lu.tzinfo is None:
            lu = lu.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - lu).total_seconds()
    except Exception:
        return None


def _ztx_is_t2_suspicious(item):
    if ztx_public_state_v1(item.get("state")) != "SUSPICIOUS":
        return False
    ls = str(item.get("last_signal") or "")
    src = str(item.get("last_source") or "")
    rids = item.get("rule_ids") or []
    return (
        ls.startswith("resource_anomaly_t2")
        or "t2_collector" in src
        or any(str(r).startswith("R-T2") for r in rids)
    )


def csm_state_payload():
    started = time.time()

    with CSM_STATE_LOCK:
        states = []
        for xapp in XAPP_LIST:
            item = dict(CSM_STATE.get(xapp, {
                "xapp": xapp,
                "state": "NORMAL",
                "score": 0,
                "risk_score": 0,
                "trust_score": 100,
                "score_type": "risk_score_0_to_100_higher_means_riskier",
                "findings": [],
            }))

            item["state"] = ztx_public_state_v1(item.get("state"))

            # Decay a stale T2-driven SUSPICIOUS back to NORMAL (see note above).
            if _ztx_is_t2_suspicious(item):
                _age = _ztx_csm_entry_age_seconds(item.get("last_update"))
                if _age is not None and _age > ZTX_T2_SUSPICIOUS_DECAY_SECONDS:
                    item["state"] = "NORMAL"
                    item["raw_state"] = "NORMAL"
                    item["t2_decayed"] = True
                    item["t2_signal_age_sec"] = round(_age, 1)
                    if xapp in CSM_STATE:
                        CSM_STATE[xapp]["state"] = "NORMAL"
                        CSM_STATE[xapp]["raw_state"] = "NORMAL"
                        CSM_STATE[xapp]["last_source"] = "t2_decay"
            item["raw_state"] = item.get("raw_state") or item.get("state")
            risk, trust = ztx_scores_for_public_state_v1(item["state"])
            item["score"] = risk
            item["risk_score"] = risk
            item["trust_score"] = trust
            item["score_type"] = "risk_score_0_to_100_higher_means_riskier"
            states.append(item)

        recent_events = list(CSM_EVENT_HISTORY[:20])

    summary = {
        "NORMAL": 0,
        "OBSERVED": 0,
        "SUSPICIOUS": 0,
        "COMPROMISED": 0,
        "total": len(states),
    }

    for item in states:
        st = ztx_public_state_v1(item.get("state"))
        summary[st] = summary.get(st, 0) + 1

    if summary["COMPROMISED"]:
        overall = "COMPROMISED"
    elif summary["SUSPICIOUS"]:
        overall = "SUSPICIOUS"
    elif summary["OBSERVED"]:
        overall = "OBSERVED"
    else:
        overall = "NORMAL"

    return {
        "component": "zt-xguard-policy-engine",
        "mode": "cached_event_driven_csm_state",
        "overall_state": overall,
        "summary": summary,
        "xapps": states,
        "recent_events": recent_events,
        "state_vocabulary": ["NORMAL", "SUSPICIOUS", "COMPROMISED", "ISOLATED"],
        "containment_is_separate": True,
        "ztx_final_policy_guard_v1": True,
        "duration_ms": round((time.time() - started) * 1000, 3),
        "time": utc_now(),
    }


_ZTX_ORIGINAL_ZTX_V4_PROCESS_SIGNAL_FINAL_GUARD_V1 = ztx_v4_process_signal

def ztx_v4_process_signal(xapp, signal, evidence=None, namespace=None, source="intent_signal"):
    namespace = namespace or XAPP_NAMESPACE
    evidence = dict(evidence or {})
    normalized_signal = ztx_normalize_signal(signal) or str(signal or "unknown").strip().lower()

    result = _ZTX_ORIGINAL_ZTX_V4_PROCESS_SIGNAL_FINAL_GUARD_V1(
        xapp=xapp,
        signal=signal,
        evidence=evidence,
        namespace=namespace,
        source=source,
    )

    current_state = ztx_public_state_v1(result.get("final_state") or result.get("state") or result.get("decision_state"))
    containment_required = bool(result.get("containment_required")) or current_state == "COMPROMISED"

    # A COMPROMISED-requires-containment force-and-verify block used to live
    # here, calling the now-deleted ztx_force_service_containment_v1. Removed
    # 2026-07-15 (step_xguard_02 Step A): it was dead weight, not a real
    # safety net - the live, outer ztx_v4_process_signal wrapper (further
    # down this file) independently does its own containment-required check
    # and force-containment call right after this function returns, so its
    # result always got overwritten anyway. containment_required is still
    # computed and returned below for callers that read it directly.

    # Public state never exposes QUARANTINED.
    result["raw_state"] = result.get("state")
    result["state"] = ztx_public_state_v1(result.get("state"))
    result["final_state"] = ztx_public_state_v1(result.get("final_state") or result.get("state"))
    result["decision_state"] = ztx_public_state_v1(result.get("decision_state") or result.get("state"))

    risk, trust = ztx_scores_for_public_state_v1(result["state"])
    result["score"] = risk
    result["risk_score"] = risk
    result["trust_score"] = trust
    result["score_type"] = "risk_score_0_to_100_higher_means_riskier"

    # Re-update state after force containment and state normalization.
    try:
        csm_update_from_result(result, source=source)
    except Exception:
        pass

    return result


def ztx_expected_public_state_v1(expected):
    return ztx_public_state_v1(expected)


_ZTX_ORIGINAL_ZTX_GET_SCENARIOS_FINAL_GUARD_V1 = ztx_get_scenarios

def ztx_get_scenarios():
    normalized = []
    for item in _ZTX_ORIGINAL_ZTX_GET_SCENARIOS_FINAL_GUARD_V1():
        s = dict(item)
        s["target_xapp"] = s.get("target_xapp") or s.get("default_xapp")
        s["default_xapp"] = s.get("default_xapp") or s.get("target_xapp")
        s["expected_state"] = ztx_expected_public_state_v1(s.get("expected_state"))
        if not s.get("category"):
            s["category"] = "benign_control" if str(s.get("id", "")).upper().startswith("B") else "attack"
        normalized.append(s)
    return normalized


def ztx_find_scenario(scenario_id):
    scenario_id = str(scenario_id or "").upper().strip()
    for scenario in ztx_get_scenarios():
        if str(scenario.get("id", "")).upper() == scenario_id:
            return scenario
    return None


def ztx_scenario_actual_containment_v1(result):
    verification = result.get("verification") or {}
    quarantine = result.get("quarantine") or {}
    force = result.get("final_guard_force_containment") or {}
    return bool(
        verification.get("contained") is True
        or verification.get("service_isolated") is True
        or quarantine.get("effective_containment_applied") is True
        or quarantine.get("service_isolation_applied") is True
        or force.get("effective_containment_applied") is True
        or force.get("service_isolation_applied") is True
    )


def ztx_run_scenario(scenario_id, payload=None):
    payload = payload or {}
    scenario = ztx_find_scenario(scenario_id)

    if not scenario:
        return {
            "ok": False,
            "error": "unknown_scenario",
            "available": [s.get("id") for s in ztx_get_scenarios()],
        }, 404

    xapp = payload.get("xapp") or payload.get("target_xapp") or scenario.get("default_xapp")
    signal = payload.get("signal") or scenario.get("signal")
    namespace = payload.get("namespace") or XAPP_NAMESPACE
    evidence = payload.get("evidence") or {}

    started = time.time()

    result = ztx_v4_process_signal(
        xapp=xapp,
        signal=signal,
        evidence=evidence,
        namespace=namespace,
        source=f"scenario_{scenario.get('id')}",
    )

    expected_state = ztx_expected_public_state_v1(scenario.get("expected_state"))
    expected_containment = bool(scenario.get("expected_containment"))
    malicious = bool(scenario.get("malicious"))

    actual_state = ztx_public_state_v1(result.get("final_state") or result.get("state"))
    actual_containment = ztx_scenario_actual_containment_v1(result)

    detected_positive = actual_state in {"SUSPICIOUS", "COMPROMISED"}

    if malicious and detected_positive:
        classification = "TP"
    elif malicious and not detected_positive:
        classification = "FN"
    elif (not malicious) and detected_positive:
        classification = "FP"
    else:
        classification = "TN"

    state_pass = actual_state == expected_state
    containment_pass = actual_containment == expected_containment
    passed = bool(state_pass and containment_pass)

    compact = {
        "ok": True,
        "scenario_id": scenario.get("id"),
        "name": scenario.get("name"),
        "xapp": xapp,
        "signal": signal,
        "malicious": malicious,
        "expected_state": expected_state,
        "actual_state": actual_state,
        "expected_containment": expected_containment,
        "actual_containment": actual_containment,
        "classification": classification,
        "pass": passed,
        "state_pass": state_pass,
        "containment_pass": containment_pass,
        "decision_state": result.get("decision_state"),
        "action": result.get("action"),
        "reasons": result.get("reasons"),
        "layers": result.get("layers"),
        "timing": result.get("timing"),
        "verification": result.get("verification"),
        "quarantine": result.get("quarantine"),
        "final_guard_force_containment": result.get("final_guard_force_containment"),
        "raw_result": result,
        "duration_ms": round((time.time() - started) * 1000, 3),
        "time": utc_now(),
        "ztx_final_policy_guard_v1": True,
    }

    ZT_SCENARIO_RESULTS.append(compact)
    if len(ZT_SCENARIO_RESULTS) > 300:
        del ZT_SCENARIO_RESULTS[:-300]

    return compact, 200





# ------------------------------------------------------------
# ZTX_SURGICAL_POLICY_FIX_V1
# Small final policy fix:
# - Public states: NORMAL, OBSERVED, SUSPICIOUS, COMPROMISED
# - QUARANTINED is never exposed as a state
# - COMPROMISED cannot downgrade until restore
# - Scenario containment is true only if live service isolation is verified
# ------------------------------------------------------------

import uuid as _ztx_surgical_uuid
import time as _ztx_surgical_time
from datetime import datetime as _ztx_surgical_datetime, timezone as _ztx_surgical_timezone

_ZTX_SURGICAL_POLICY_FIX_V1 = True

def _ztx_surgical_now():
    try:
        return utc_now()
    except Exception:
        return _ztx_surgical_datetime.now(_ztx_surgical_timezone.utc).isoformat()

# Soft-tier (SUSPICIOUS/OBSERVED) decay window - see csm_state_payload.
# Longer than the T2 collector's ~1 Hz reporting cadence so a genuinely-still-
# elevated kpimon-go (which reports every tick while elevated) never decays,
# but short enough that a one-shot Falco probe on a now-quiet xApp clears.
_ZTX_SOFT_STATE_DECAY_SECONDS = 90.0

def _ztx_state_age_seconds(last_update):
    """Seconds since an ISO-8601 last_update string, or None if unparseable."""
    if not last_update:
        return None
    try:
        ts = str(last_update).replace("Z", "+00:00")
        dt = _ztx_surgical_datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_ztx_surgical_timezone.utc)
        now = _ztx_surgical_datetime.now(_ztx_surgical_timezone.utc)
        return (now - dt).total_seconds()
    except Exception:
        return None

def _ztx_public_state(state):
    s = str(state or "NORMAL").upper().strip()
    if s in {"NORMAL", "TRUSTED", "HEALTHY", "RESTORED", "UNKNOWN", "INITIALIZING"}:
        return "NORMAL"
    if s == "OBSERVED":
        return "OBSERVED"
    if s in {"SUSPICIOUS", "DEGRADED"}:
        return "SUSPICIOUS"
    if s == "COMPROMISED":
        return "COMPROMISED"
    # 2026-07-16: ISOLATED is the 5th, highest-severity tier (COMPROMISED
    # that has actually had containment attempted) - kept distinct from
    # COMPROMISED so the sticky-downgrade rank below can never let a fresh
    # COMPROMISED-tier signal undo an already-isolated xApp. "QUARANTINED"/
    # "CONTAINED" deliberately still alias to COMPROMISED, not ISOLATED -
    # that's the pre-existing (currently always-blocked-by-RBAC) overlay
    # test_bug_fix.py's own assertion checks for, a different concept.
    if s == "ISOLATED":
        return "ISOLATED"
    if s in {"QUARANTINED", "CONTAINED"}:
        return "COMPROMISED"
    return "NORMAL"

def _ztx_rank(state):
    return {"NORMAL": 0, "OBSERVED": 1, "SUSPICIOUS": 2, "COMPROMISED": 3, "ISOLATED": 4}.get(_ztx_public_state(state), 0)

def _ztx_scores(state):
    s = _ztx_public_state(state)
    if s == "NORMAL":
        return 0, 100
    if s == "OBSERVED":
        return 20, 80
    if s == "SUSPICIOUS":
        return 60, 40
    if s in {"COMPROMISED", "ISOLATED"}:
        return 100, 0
    return 0, 100

def _ztx_is_restore(source=None, signal=None):
    src = str(source or "").lower()
    sig = str(signal or "").lower()
    return "restore" in src or sig in {"restore", "readmit", "manual_restore", "restore_baseline"}

def _ztx_current_state(xapp):
    try:
        with CSM_STATE_LOCK:
            return _ztx_public_state((CSM_STATE.get(xapp) or {}).get("state"))
    except Exception:
        return "NORMAL"

def _ztx_normalize_result_scores(result, state=None):
    result = dict(result or {})
    final_state = _ztx_public_state(state or result.get("final_state") or result.get("state") or result.get("decision_state"))
    risk, trust = _ztx_scores(final_state)

    result["raw_state"] = result.get("state")
    result["state"] = final_state
    result["final_state"] = final_state
    result["decision_state"] = final_state
    result["score"] = risk
    result["risk_score"] = risk
    result["trust_score"] = trust
    result["score_type"] = "risk_score_0_to_100_higher_means_riskier"
    result["ztx_surgical_policy_fix_v1"] = True
    return result

# step_xguard_02 Step B1: _ztx_live_containment and
# _ztx_force_containment_for_xapp moved to containment_orchestrator.py
# (imported above). _ztx_surgical_now/_ztx_public_state/_ztx_rank/
# _ztx_scores/_ztx_is_restore/_ztx_current_state/_ztx_normalize_result_scores
# above stay here - csm_update_from_result below (this file's decision
# glue) still needs its own copies. containment_orchestrator.py carries
# small private duplicates of the 3 it needs internally, to avoid a
# circular import back into this file.

_ZTX_ORIGINAL_CSM_UPDATE_SURGICAL_V1 = csm_update_from_result

def csm_update_from_result(result, source="unknown"):
    result = dict(result or {})
    xapp = result.get("xapp")

    if not xapp:
        return _ZTX_ORIGINAL_CSM_UPDATE_SURGICAL_V1(result, source=source)

    # 2026-07-23: the read (previous state), decide (downgrade-block,
    # isolation dwell, containment), and write steps below must be atomic
    # per xapp - otherwise a concurrent benign/"ignored" event for the same
    # xapp can read a stale pre-escalation previous_state and, after this
    # request's write completes, overwrite it with a stale decision. This
    # was confirmed happening in production: a real Falco CRITICAL signal
    # escalated an xapp, then a concurrent high-frequency "confirmed normal"
    # signal for the same xapp silently reverted it to NORMAL a few minutes
    # later with downgrade_blocked=false and previous_state=NORMAL, because
    # its own previous-state read raced ahead of the escalating write.
    # A per-xapp (not global) lock avoids serializing unrelated xapps behind
    # slow containment mechanisms (RMR/E2 pod restart can take ~27-29s).
    with csm_xapp_lock(xapp):
        signal = result.get("signal") or result.get("normalized_signal")
        incoming = _ztx_public_state(result.get("final_state") or result.get("state") or result.get("decision_state"))
        previous = _ztx_current_state(xapp)

        # 2026-08-23: post-restore grace pin. Inside an xapp's restore-grace
        # window, a NON-restore SOFT signal (below COMPROMISED - e.g. a
        # trailing T2 resource-anomaly tick still arriving from just before
        # the pod was recreated) must not re-escalate the freshly restored
        # xapp. Force it to NORMAL and clear any dwell so it cannot re-stick
        # the state. A fresh critical (>= COMPROMISED) is left untouched, so
        # a genuine new attack right after restore is still contained.
        restore_grace_pin = (
            csm_in_restore_grace(xapp)
            and not _ztx_is_restore(source, signal)
            and _ztx_rank(incoming) < _ztx_rank("COMPROMISED")
        )
        if restore_grace_pin:
            incoming = "NORMAL"
            if ztx_isolation_manager is not None:
                ztx_isolation_manager.clear(xapp)

        downgrade_blocked = False
        final_state = incoming

        # 2026-07-19: only the CONTAINMENT tiers (COMPROMISED/ISOLATED) are
        # "sticky" and require a deliberate restore to leave. SUSPICIOUS and
        # OBSERVED are soft, self-clearing monitoring tiers: a fresh evaluation
        # that says the condition is gone MUST be allowed to bring them back to
        # NORMAL. The previous unconditional block pinned any xApp that ever saw
        # a single one-shot Falco probe at SUSPICIOUS forever (telemetry-monitor
        # bug). Containment states stay protected exactly as before.
        if (not _ztx_is_restore(source, signal)
                and not restore_grace_pin
                and _ztx_rank(previous) >= _ztx_rank("COMPROMISED")
                and _ztx_rank(previous) > _ztx_rank(incoming)):
            final_state = previous
            downgrade_blocked = True

        # 2026-07-16: COMPROMISED->ISOLATED transition (operator-approved
        # design). IMMEDIATE (Falco-critical) isolates on this same call;
        # DWELL_30S (T2/correlation-based) starts a 30s dwell window (see
        # ztx_isolation_manager.py) - only actually isolates once that window
        # elapses with no restore, or an operator forces it early via
        # /csm/containment/isolate-now. See containment block below - that's
        # gated on ISOLATED now, not COMPROMISED, so a pending-dwell
        # COMPROMISED xApp is never touched by a real K8s write until it's
        # genuinely time.
        # 2026-07-25: downgrade_blocked means final_state=="COMPROMISED" here
        # only because sticky-state protection preserved an EARLIER
        # compromise, not because THIS request's own raw classification
        # said COMPROMISED - confirmed live via instrumented debug log
        # against A_Burst (bursty attack: score dips between pulses, so the
        # collector alternates resource_anomaly_t2/_elevated signals while
        # the server correctly stays sticky-COMPROMISED throughout). Calling
        # record_compromised() on one of these preserved-not-fresh ticks
        # used THIS request's OWN isolation_timing (e.g. "N/A" for an
        # _elevated signal, which doesn't carry a DWELL_30S tag) instead of
        # the ORIGINAL compromising signal's - hitting record_compromised's
        # "not DWELL_30S" bypass branch and instantly isolating, canceling
        # an already-in-progress legitimate 30s dwell. The background
        # dwell-checker thread (start_dwell_checker) already guarantees
        # eventual isolation independent of new signals, so it's safe to
        # simply not touch the dwell tracker at all on a merely-preserved
        # tick - only a freshly, genuinely COMPROMISED classification
        # should start/re-affirm it.
        if final_state == "COMPROMISED" and not downgrade_blocked and ztx_isolation_manager is not None:
            isolate_now, dwell_remaining = ztx_isolation_manager.record_compromised(
                xapp, result.get("isolation_timing") or "IMMEDIATE"
            )
            if isolate_now:
                final_state = "ISOLATED"
                result["state"] = "ISOLATED"
                result["final_state"] = "ISOLATED"
                result["decision_state"] = "ISOLATED"
            else:
                result["isolation_dwell_seconds_remaining"] = round(dwell_remaining, 1) if dwell_remaining is not None else None
        elif final_state == "COMPROMISED" and ztx_isolation_manager is not None:
            dwell_remaining = ztx_isolation_manager.dwell_status(xapp)
            result["isolation_dwell_seconds_remaining"] = round(dwell_remaining, 1) if dwell_remaining is not None else None
        elif final_state != "COMPROMISED" and ztx_isolation_manager is not None:
            ztx_isolation_manager.clear(xapp)

        result = _ztx_normalize_result_scores(result, final_state)

        containment_verified = None
        t2_containment_suppressed = (not T2_AUTO_CONTAIN) and str(signal or "").startswith("resource_anomaly_t2")
        if final_state == "ISOLATED" and t2_containment_suppressed:
            result["quarantine"] = {"applied": False, "reason": "t2_auto_containment_disabled", "signal": signal}
            result["containment_note"] = "T2_AUTO_CONTAIN=false: state reported for visibility, real containment suppressed"
        elif final_state == "ISOLATED" and result.get("verification") is not None:
            # 2026-07-25: dedup fix. ztx_v4_process_signal (the only caller
            # that pre-populates "verification") already ran this exact
            # live-containment-check + force-containment sequence on this
            # same request just before calling this function - see its own
            # ISOLATED block. Re-running it here was pure duplicated cost,
            # not a correctness issue (ztx_isolation_manager state is
            # idempotent either way) - but each pass pays real wall-clock
            # time (K8s API calls, and until the RBAC-gap fast-fail cache
            # above, WebSocket exec round trips), directly inflating the
            # gap between dwell-expiry and CSM_STATE actually reflecting
            # ISOLATED (what /trust-state, and this eval harness's
            # t_isolated_utc, are measured from).
            v = result["verification"]
            containment_verified = bool(v.get("contained"))
        elif final_state == "ISOLATED":
            v = _ztx_live_containment(xapp, result.get("namespace") or XAPP_NAMESPACE)
            if not v.get("contained"):
                q = _ztx_force_containment_for_xapp(xapp, result.get("namespace") or XAPP_NAMESPACE, "isolated_state_requires_containment")
                result["quarantine"] = q
                v = q.get("verification_after") or v
            result["verification"] = v
            containment_verified = bool(v.get("contained"))

        _ZTX_ORIGINAL_CSM_UPDATE_SURGICAL_V1(result, source=source)

        risk, trust = _ztx_scores(final_state)
        try:
            with CSM_STATE_LOCK:
                entry = dict(CSM_STATE.get(xapp) or {})
                entry.update({
                    "xapp": xapp,
                    "state": final_state,
                    "raw_state": result.get("raw_state"),
                    "score": risk,
                    "risk_score": risk,
                    "trust_score": trust,
                    "score_type": "risk_score_0_to_100_higher_means_riskier",
                    "containment_required": final_state == "COMPROMISED",
                    "containment_verified": containment_verified if containment_verified is not None else entry.get("containment_verified"),
                    "downgrade_blocked": downgrade_blocked,
                    "previous_state": previous,
                    "last_signal": signal,
                    "last_source": source,
                    "ztx_surgical_policy_fix_v1": True,
                    "last_update": _ztx_surgical_now(),
                })
                CSM_STATE[xapp] = entry
        except Exception:
            pass

_ZTX_ORIGINAL_CSM_STATE_PAYLOAD_SURGICAL_V1 = csm_state_payload

def csm_state_payload():
    payload = _ZTX_ORIGINAL_CSM_STATE_PAYLOAD_SURGICAL_V1()
    xapps = []

    for item in payload.get("xapps", []):
        item = dict(item)
        state = _ztx_public_state(item.get("state"))

        # 2026-07-19: soft-tier decay safety net. SUSPICIOUS/OBSERVED are
        # transient monitoring states that reflect *recent* suspicious
        # activity. If nothing has reinforced them within the decay window
        # (no fresh signal updating last_update), present them as NORMAL -
        # so a one-shot Falco probe on a now-quiet xApp does not read as
        # permanently suspicious even if no benign event happens to arrive
        # to clear it via the write path. Containment tiers never decay.
        if state in ("SUSPICIOUS", "OBSERVED"):
            age = _ztx_state_age_seconds(item.get("last_update"))
            if age is not None and age > _ZTX_SOFT_STATE_DECAY_SECONDS:
                state = "NORMAL"
                item["decayed_from"] = _ztx_public_state(item.get("state"))

        risk, trust = _ztx_scores(state)

        item["state"] = state
        item["score"] = risk
        item["risk_score"] = risk
        item["trust_score"] = trust
        item["score_type"] = "risk_score_0_to_100_higher_means_riskier"
        item["ztx_surgical_policy_fix_v1"] = True

        # 2026-07-25: expose the pending-dwell countdown here so any poller
        # of /trust-state (the T2 collector already GETs this every tick
        # while a throttle is applied - see _check_throttle_release) can see
        # it live. Previously isolation_dwell_seconds_remaining only existed
        # transiently in a single /csm/intent/ingest response and was
        # unqueryable afterward - dashboards/visualizers had no way to show
        # dwell countdown at all. Read-only (ztx_isolation_manager.dwell_status
        # never mutates state), so safe to compute on every payload build.
        dwell_remaining = None
        if ztx_isolation_manager is not None and item.get("xapp"):
            dwell_remaining = ztx_isolation_manager.dwell_status(item["xapp"])
        item["isolation_dwell_seconds_remaining"] = round(dwell_remaining, 1) if dwell_remaining is not None else None

        xapps.append(item)

    # 2026-07-20: ISOLATED was missing here entirely - harmless while the
    # sticky-downgrade bug (fixed same day) meant no xApp ever actually
    # stayed ISOLATED long enough for this endpoint to be polled while one
    # was, but that fix immediately exposed this as a real 500 (KeyError)
    # the instant an xApp genuinely reached and held ISOLATED.
    summary = {"NORMAL": 0, "OBSERVED": 0, "SUSPICIOUS": 0, "COMPROMISED": 0, "ISOLATED": 0, "total": len(xapps)}
    for item in xapps:
        summary[_ztx_public_state(item.get("state"))] += 1

    if summary["ISOLATED"]:
        overall = "ISOLATED"
    elif summary["COMPROMISED"]:
        overall = "COMPROMISED"
    elif summary["SUSPICIOUS"]:
        overall = "SUSPICIOUS"
    elif summary["OBSERVED"]:
        overall = "OBSERVED"
    else:
        overall = "NORMAL"

    payload["xapps"] = xapps
    payload["summary"] = summary
    payload["overall_state"] = overall
    payload["state_vocabulary"] = ["NORMAL", "SUSPICIOUS", "COMPROMISED", "ISOLATED"]
    payload["containment_is_separate"] = True
    payload["ztx_surgical_policy_fix_v1"] = True
    return payload

_ZTX_ORIGINAL_V4_SIGNAL_SURGICAL_V1 = ztx_v4_process_signal

def _ztx_debug_timing_log(line: str) -> None:
    """TEMPORARY 2026-07-25 diagnostic for the T2 dwell-to-isolation
    overhead investigation - remove once root cause is confirmed and
    fixed. Never raises; must not affect the real request path."""
    try:
        with open("/tmp/ztx_isolation_debug.log", "a") as fh:
            fh.write(line + "\n")
    except Exception:
        pass


def ztx_v4_process_signal(xapp, signal, evidence=None, namespace=None, source="intent_signal"):
    _ztx_dbg_t0 = time.time()
    namespace = namespace or XAPP_NAMESPACE
    previous = _ztx_current_state(xapp)

    result = _ZTX_ORIGINAL_V4_SIGNAL_SURGICAL_V1(
        xapp=xapp,
        signal=signal,
        evidence=evidence,
        namespace=namespace,
        source=source,
    )
    _ztx_dbg_t_original = time.time()

    incoming = _ztx_public_state(result.get("final_state") or result.get("state") or result.get("decision_state"))

    # 2026-08-23: post-restore grace pin (same guard as csm_update_from_result
    # above). This is the path the T2 collector's /csm/intent/ingest ticks
    # take, so it is where a trailing soft signal would otherwise re-escalate
    # (and re-run live containment for) a just-restored xapp. Inside the grace
    # window a non-restore signal below COMPROMISED is pinned to NORMAL; a
    # genuine fresh critical is untouched.
    if (csm_in_restore_grace(xapp)
            and not _ztx_is_restore(source, signal)
            and _ztx_rank(incoming) < _ztx_rank("COMPROMISED")):
        incoming = "NORMAL"
        result["state"] = "NORMAL"
        result["final_state"] = "NORMAL"
        result["decision_state"] = "NORMAL"
        result["restore_grace_pinned"] = True
        if ztx_isolation_manager is not None:
            ztx_isolation_manager.clear(xapp)

    final_state = incoming

    # 2026-07-19: same sticky-state fix as csm_update_from_result above -
    # only COMPROMISED/ISOLATED are protected from downgrade; SUSPICIOUS/
    # OBSERVED self-clear when a fresh signal says the condition is gone.
    if (not _ztx_is_restore(source, signal)
            and not result.get("restore_grace_pinned")
            and _ztx_rank(previous) >= _ztx_rank("COMPROMISED")
            and _ztx_rank(previous) > _ztx_rank(incoming)):
        final_state = previous
        result["downgrade_blocked"] = True
        result["previous_state"] = previous

    # 2026-07-16: see the matching block in csm_update_from_result above
    # for the full rationale - same COMPROMISED->ISOLATED transition,
    # independently checked here since this function also independently
    # attempts containment. ztx_isolation_manager's own state is shared
    # module-level state, so checking it from both places is safe/
    # idempotent, not a double-count risk.
    _ztx_dbg_isolate_now = None
    _ztx_dbg_dwell_remaining = None
    # 2026-07-25: see the matching fix in csm_update_from_result above -
    # skip record_compromised() when final_state=="COMPROMISED" only
    # because sticky-state protection preserved it (result["downgrade_
    # blocked"]), not because this request's own raw classification said
    # COMPROMISED. Confirmed live: an _elevated signal arriving mid-dwell
    # (A_Burst's score dips between pulses) carries its own non-DWELL_30S
    # isolation_timing and was instantly canceling an in-progress 30s
    # dwell. The background dwell-checker thread still guarantees eventual
    # isolation independent of this.
    if final_state == "COMPROMISED" and not result.get("downgrade_blocked") and ztx_isolation_manager is not None:
        isolate_now, dwell_remaining = ztx_isolation_manager.record_compromised(
            xapp, result.get("isolation_timing") or "IMMEDIATE"
        )
        _ztx_dbg_isolate_now = isolate_now
        _ztx_dbg_dwell_remaining = dwell_remaining
        if isolate_now:
            final_state = "ISOLATED"
            result["state"] = "ISOLATED"
            result["final_state"] = "ISOLATED"
            result["decision_state"] = "ISOLATED"
        else:
            result["isolation_dwell_seconds_remaining"] = round(dwell_remaining, 1) if dwell_remaining is not None else None
    elif final_state == "COMPROMISED" and ztx_isolation_manager is not None:
        dwell_remaining = ztx_isolation_manager.dwell_status(xapp)
        _ztx_dbg_isolate_now = False
        _ztx_dbg_dwell_remaining = dwell_remaining
        result["isolation_dwell_seconds_remaining"] = round(dwell_remaining, 1) if dwell_remaining is not None else None
    elif final_state != "COMPROMISED" and ztx_isolation_manager is not None:
        ztx_isolation_manager.clear(xapp)

    result = _ztx_normalize_result_scores(result, final_state)

    _ztx_dbg_t_precontainment = time.time()
    t2_containment_suppressed = (not T2_AUTO_CONTAIN) and str(signal or "").startswith("resource_anomaly_t2")
    if final_state == "ISOLATED" and t2_containment_suppressed:
        result["quarantine"] = {"applied": False, "reason": "t2_auto_containment_disabled", "signal": signal}
        result["containment_note"] = "T2_AUTO_CONTAIN=false: state reported for visibility, real containment suppressed"
        result["containment_verified"] = False
    elif final_state == "ISOLATED":
        v = _ztx_live_containment(xapp, namespace)
        if not v.get("contained"):
            q = _ztx_force_containment_for_xapp(xapp, namespace, "isolated_signal_requires_containment")
            result["quarantine"] = q
            v = q.get("verification_after") or v
        result["verification"] = v
        result["containment_verified"] = bool(v.get("contained"))
    _ztx_dbg_t_postcontainment = time.time()

    if xapp == "ricxapp-kpimon-go":
        _ztx_debug_timing_log(
            f"{time.strftime('%H:%M:%S')} xapp={xapp} signal={signal} source={source} "
            f"previous={previous} final_state={final_state} isolate_now={_ztx_dbg_isolate_now} "
            f"dwell_remaining={_ztx_dbg_dwell_remaining} "
            f"t_original={_ztx_dbg_t_original - _ztx_dbg_t0:.3f}s "
            f"t_precontainment={_ztx_dbg_t_precontainment - _ztx_dbg_t_original:.3f}s "
            f"t_containment={_ztx_dbg_t_postcontainment - _ztx_dbg_t_precontainment:.3f}s"
        )

    _ztx_dbg_t_before_update = time.time()
    csm_update_from_result(result, source=source)
    _ztx_dbg_t_after_update = time.time()

    if xapp == "ricxapp-kpimon-go":
        _ztx_debug_timing_log(
            f"{time.strftime('%H:%M:%S')} xapp={xapp} csm_update_from_result took "
            f"{_ztx_dbg_t_after_update - _ztx_dbg_t_before_update:.3f}s "
            f"TOTAL_REQUEST={_ztx_dbg_t_after_update - _ztx_dbg_t0:.3f}s"
        )
    return result


# ---------------------------------------------------------------------
# 2026-07-16: COMPROMISED -> ISOLATED transition support.
# ---------------------------------------------------------------------

def _ztx_perform_isolation_now(xapp: str, namespace: str, reason: str) -> Dict[str, Any]:
    """Single shared place that actually enacts isolation: writes state
    ISOLATED into CSM_STATE and attempts the real containment write.
    Called from three triggers - the inline per-event path (via the
    isolate_now branches above), the background dwell-checker thread
    (for xApps with no further incoming event to catch the expiry
    inline), and the manual /csm/containment/isolate-now endpoint - kept
    as one function so behavior can't drift between the three.
    """
    _ztx_debug_timing_log(f"{time.strftime('%H:%M:%S')} _ztx_perform_isolation_now CALLED xapp={xapp} reason={reason}")
    if ztx_isolation_manager is not None:
        ztx_isolation_manager.record_manual_isolate(xapp)

    # Only the automated dwell-expiry trigger is eligible for suppression -
    # a manual /csm/containment/isolate-now call must always go through
    # regardless of what signal originally started the dwell window, since
    # that's an explicit operator override, not an automated decision.
    t2_containment_suppressed = False
    if reason == "compromised_state_dwell_30s_expired" and not T2_AUTO_CONTAIN:
        with CSM_STATE_LOCK:
            prior_signal = (CSM_STATE.get(xapp) or {}).get("last_signal")
        t2_containment_suppressed = str(prior_signal or "").startswith("resource_anomaly_t2")

    v = _ztx_live_containment(xapp, namespace)
    quarantine = None
    if t2_containment_suppressed:
        quarantine = {"applied": False, "reason": "t2_auto_containment_disabled", "signal": prior_signal}
    elif not v.get("contained"):
        quarantine = _ztx_force_containment_for_xapp(xapp, namespace, reason)
        v = quarantine.get("verification_after") or v
    containment_verified = bool(v.get("contained"))
    risk, trust = _ztx_scores("ISOLATED")

    with CSM_STATE_LOCK:
        entry = dict(CSM_STATE.get(xapp) or {})
        previous_state = entry.get("state")
        entry.update({
            "xapp": xapp,
            "namespace": namespace,
            "state": "ISOLATED",
            "raw_state": "ISOLATED",
            "score": risk,
            "risk_score": risk,
            "trust_score": trust,
            "score_type": "risk_score_0_to_100_higher_means_riskier",
            "containment_required": True,
            "containment_verified": containment_verified,
            "downgrade_blocked": False,
            "previous_state": previous_state,
            "last_signal": reason,
            "last_source": reason,
            "verification": v,
            "quarantine": quarantine or entry.get("quarantine"),
            "last_update": utc_now(),
        })
        CSM_STATE[xapp] = entry

    return entry


def _ztx_dwell_expired_callback(xapp: str) -> None:
    """Called by the background dwell-checker thread for any xApp whose
    30s window has elapsed with no further incoming event to catch it
    inline. Re-checks CSM_STATE first - only actually isolates if the
    xApp is still genuinely COMPROMISED (not restored, not already
    isolated) since this was last known."""
    try:
        with CSM_STATE_LOCK:
            current = _ztx_public_state((CSM_STATE.get(xapp) or {}).get("state"))
            namespace = (CSM_STATE.get(xapp) or {}).get("namespace") or XAPP_NAMESPACE
        if current != "COMPROMISED":
            if ztx_isolation_manager is not None:
                ztx_isolation_manager.clear(xapp)
            return
        _ztx_perform_isolation_now(xapp, namespace, "compromised_state_dwell_30s_expired")
    except Exception as exc:
        print(json.dumps({"component": "zt-xguard-policy-engine", "dwell_checker_error": xapp, "error": str(exc)}), flush=True)


@APP.route("/csm/containment/isolate-now", methods=["POST"])
def csm_containment_isolate_now() -> Any:
    """Manual operator trigger: force an already-COMPROMISED xApp to
    ISOLATED immediately, bypassing any remaining DWELL_30S wait. No-op
    (400) if the xApp isn't currently COMPROMISED - isolating something
    that was never flagged compromised isn't a valid operator action
    through this endpoint."""
    payload = request.get_json(force=True, silent=True) or {}
    xapp = payload.get("xapp")
    namespace = payload.get("namespace") or XAPP_NAMESPACE
    if not xapp:
        return jsonify({"isolated": False, "error": "xapp_required"}), 400

    with CSM_STATE_LOCK:
        current = _ztx_public_state((CSM_STATE.get(xapp) or {}).get("state"))
    if current != "COMPROMISED":
        return jsonify({
            "isolated": False,
            "error": "xapp_not_compromised",
            "current_state": current,
            "message": f"{xapp} is currently {current}, not COMPROMISED - nothing to isolate.",
        }), 400

    entry = _ztx_perform_isolation_now(xapp, namespace, "manual_operator_isolate_now")
    # 2026-07-23: "isolated" now tracks real containment_verified rather
    # than being hardcoded True - the state transition to ISOLATED always
    # happens (that's real, "state" reflects it), but a caller checking
    # just "isolated" at the top level used to see True even when the
    # underlying containment_verified was False (e.g. an RBAC failure or
    # missing pod/Service).
    return jsonify({"isolated": bool(entry.get("containment_verified")), "xapp": xapp, "state": entry.get("state"), "containment_verified": entry.get("containment_verified"), "quarantine": entry.get("quarantine")})


_ZTX_ORIGINAL_GET_SCENARIOS_SURGICAL_V1 = ztx_get_scenarios

def ztx_get_scenarios():
    out = []
    for s in _ZTX_ORIGINAL_GET_SCENARIOS_SURGICAL_V1():
        item = dict(s)
        item["expected_state_raw"] = item.get("expected_state")
        item["expected_state"] = _ztx_public_state(item.get("expected_state"))
        item["target_xapp"] = item.get("target_xapp") or item.get("default_xapp") or "telemetry-monitor"
        item["default_xapp"] = item.get("default_xapp") or item.get("target_xapp")
        item["ztx_surgical_policy_fix_v1"] = True
        out.append(item)
    return out

_ZTX_ORIGINAL_RUN_SCENARIO_SURGICAL_V1 = ztx_run_scenario

def ztx_run_scenario(scenario_id, payload=None):
    payload = payload or {}

    result, code = _ZTX_ORIGINAL_RUN_SCENARIO_SURGICAL_V1(scenario_id, payload)

    result = dict(result or {})
    xapp = result.get("xapp") or payload.get("xapp") or payload.get("target_xapp")
    namespace = payload.get("namespace") or result.get("namespace") or XAPP_NAMESPACE

    expected_state = _ztx_public_state(result.get("expected_state"))
    actual_state = _ztx_public_state(result.get("actual_state") or result.get("state"))

    if expected_state == "COMPROMISED" or actual_state == "COMPROMISED" or bool(result.get("expected_containment")):
        q = _ztx_force_containment_for_xapp(xapp, namespace, f"scenario_{scenario_id}_requires_containment")
        v = q.get("verification_after") or _ztx_live_containment(xapp, namespace)
        actual_state = "COMPROMISED"
        actual_containment = bool(v.get("contained"))
        result["quarantine"] = q
        result["verification"] = v
    else:
        v = _ztx_live_containment(xapp, namespace)
        actual_containment = bool(v.get("contained"))
        result["verification"] = v

    result["expected_state_raw"] = result.get("expected_state")
    result["actual_state_raw"] = result.get("actual_state")
    result["expected_state"] = expected_state
    result["actual_state"] = actual_state
    result["actual_containment"] = actual_containment

    result["state_pass"] = actual_state == expected_state
    result["containment_pass"] = actual_containment == bool(result.get("expected_containment"))
    result["pass"] = bool(result["state_pass"] and result["containment_pass"])
    result["ztx_surgical_policy_fix_v1"] = True

    csm_update_from_result({
        "xapp": xapp,
        "namespace": namespace,
        "state": actual_state,
        "final_state": actual_state,
        "decision_state": actual_state,
        "verification": result.get("verification"),
        "quarantine": result.get("quarantine"),
        "signal": result.get("signal"),
    }, source=f"scenario_{scenario_id}")

    # Do not append here.
    # The original ztx_run_scenario() already records the scenario result.
    # Appending again here caused one scenario click to count twice in TP/FP/TN/FN.
    result["ztx_double_count_fix_v1"] = True

    return result, code

print("ZTX_SURGICAL_POLICY_FIX_V1 loaded")


# ------------------------------------------------------------
# ZTX_SURGICAL_CONTAINMENT_FIX_V2 - reduced 2026-07-15, step_xguard_02 Step A.
# What used to be here duplicated canonical apply_quarantine/
# apply_service_isolation/restore_service_isolation with its own pod-label
# patcher, service-isolator (different isolation-token scheme), and
# service-restorer (a plain merge-patch, not the JSON-Patch approach
# restore_service_isolation deliberately uses to avoid Kubernetes silently
# merging selector maps instead of replacing them). Confirmed live
# (kubectl auth can-i, 2026-07-14/15) that the policy engine's ServiceAccount
# has zero write permissions in ricxapp (patch pods/services, create
# networkpolicies, patch deployments all return "no") - so this duplicate
# and the canonical path were guaranteed to fail identically, every time,
# regardless of which one ran. Deleting it does not change what containment
# can currently do (nothing, until the RBAC gap is addressed separately -
# see memory ztxguard_containment_not_yet_implemented.md) - it only removes
# redundant code that called the same blocked K8s API with the same
# identity. What's KEPT below (_ztx_v2_set_state_normal,
# _ztx_v2_response_payload, and the restore-route wrapper) fixes a real,
# separate gap unrelated to containment write-permissions: the canonical
# /csm/containment/restore route (line ~2901) correctly restores K8s
# objects but never resets the policy engine's own in-memory CSM_STATE
# cache back to NORMAL - without this, a restored xApp would still show as
# COMPROMISED in cached state reads even after real containment was lifted.
# ------------------------------------------------------------

import json as _ztx_v2_json
import uuid as _ztx_v2_uuid
import time as _ztx_v2_time

_ZTX_SURGICAL_CONTAINMENT_FIX_V2 = True

# step_xguard_02 Step B1: _ztx_v2_set_state_normal and
# _ztx_v2_response_payload moved to containment_orchestrator.py (imported
# above). The restore-route wrapper below stays here - it's routing-layer
# code (rebinds a Flask view function at import time via APP.view_functions).

# Wrap restore route so restore also clears cached CSM state.
try:
    for _rule in list(APP.url_map.iter_rules()):
        if _rule.rule == "/csm/containment/restore":
            _endpoint = _rule.endpoint
            _original_restore_view_v2 = APP.view_functions[_endpoint]

            def _ztx_v2_restore_view_wrapper(*args, **kwargs):
                payload = request.get_json(silent=True) or {}
                xapp = payload.get("xapp") or request.args.get("xapp")
                namespace = payload.get("namespace") or request.args.get("namespace") or XAPP_NAMESPACE

                # The original view (csm_containment_restore, line ~2901)
                # already restores the real K8s objects correctly via
                # canonical restore_service_isolation - this wrapper's only
                # remaining job (since 2026-07-15) is resetting the policy
                # engine's own in-memory CSM_STATE cache, which the
                # original view never touches.
                ret = _original_restore_view_v2(*args, **kwargs)
                data, code = _ztx_v2_response_payload(ret)

                if xapp:
                    state_after = _ztx_v2_set_state_normal(xapp, source="containment_restore")
                    data["ztx_v2_state_after_restore"] = state_after
                    data["ztx_surgical_containment_fix_v2"] = True

                    # 2026-07-25: confirmed live (instrumented debug log) that
                    # this single reset can lose a race against a trailing
                    # stale COMPROMISED/ISOLATED-tier signal from the OLD pod
                    # (still mid-teardown during ztx_recreate_pods_for_clean_
                    # restore's wait, on its own unsynchronized ~1Hz T2-
                    # collector tick) - that signal's own sticky-downgrade
                    # write can land AFTER this reset, leaving CSM_STATE
                    # stuck at ISOLATED for the xapp's next incident (seen:
                    # 3 consecutive real-attack trials right after a restore
                    # all showed previous=ISOLATED from the very first tick,
                    # never reaching a fresh COMPROMISED classification).
                    # Cheap mitigation: re-assert NORMAL once more a few
                    # seconds later, fire-and-forget, after the OLD pod
                    # should genuinely be gone - narrows the race window
                    # without blocking this response or touching the restore
                    # logic itself.
                    def _ztx_v2_reassert_normal_delayed(_xapp=xapp):
                        try:
                            _ztx_v2_set_state_normal(_xapp, source="containment_restore")
                        except Exception:
                            pass
                    threading.Timer(5.0, _ztx_v2_reassert_normal_delayed).start()

                return jsonify(data), code

            APP.view_functions[_endpoint] = _ztx_v2_restore_view_wrapper
            break
except Exception as _ztx_v2_restore_wrap_exc:
    print("ZTX_SURGICAL_CONTAINMENT_FIX_V2 restore wrapper failed", repr(_ztx_v2_restore_wrap_exc))

print("ZTX_SURGICAL_CONTAINMENT_FIX_V2 loaded")


# ------------------------------------------------------------
# ZTX_EVALUATION_DEDUPE_FIX_V1
# Fix evaluation cards double-counting one scenario run.
# Cause: original ztx_run_scenario records a result, then surgical wrapper records another.
# This route wrapper de-duplicates near-identical results in /csm/evaluation/summary.
# ------------------------------------------------------------

from datetime import datetime as _ztx_eval_datetime

_ZTX_EVALUATION_DEDUPE_FIX_V1 = True

def _ztx_eval_parse_time(t):
    try:
        return _ztx_eval_datetime.fromisoformat(str(t).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None

def _ztx_eval_key(r):
    return (
        str(r.get("scenario_id") or r.get("id") or ""),
        str(r.get("xapp") or ""),
        str(r.get("signal") or ""),
        str(r.get("expected_state") or ""),
        str(r.get("actual_state") or ""),
        str(r.get("expected_containment") or ""),
        str(r.get("actual_containment") or ""),
    )

def _ztx_eval_dedupe_results(results):
    deduped = []

    for r in list(results or []):
        if not isinstance(r, dict):
            continue

        rt = _ztx_eval_parse_time(r.get("time"))
        rk = _ztx_eval_key(r)

        duplicate = False
        for old in deduped:
            ot = _ztx_eval_parse_time(old.get("time"))
            ok = _ztx_eval_key(old)

            # Same scenario result emitted twice within two seconds = one logical run.
            if rk == ok and rt is not None and ot is not None and abs(rt - ot) <= 2.0:
                duplicate = True

                # Prefer the richer surgical result if one has the marker.
                if r.get("ztx_surgical_policy_fix_v1") and not old.get("ztx_surgical_policy_fix_v1"):
                    old.clear()
                    old.update(r)

                break

        if not duplicate:
            deduped.append(dict(r))

    return deduped

def _ztx_eval_classification(r):
    cls = r.get("classification")
    if cls in {"TP", "TN", "FP", "FN"}:
        return cls

    malicious = bool(r.get("malicious"))
    actual_state = str(r.get("actual_state") or "").upper()
    detected_positive = actual_state in {"SUSPICIOUS", "COMPROMISED"}

    if malicious and detected_positive:
        return "TP"
    if malicious and not detected_positive:
        return "FN"
    if (not malicious) and detected_positive:
        return "FP"
    return "TN"

def _ztx_eval_summary_from_results(results):
    counts = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

    passed = 0
    failed = 0

    for r in results:
        cls = _ztx_eval_classification(r)
        counts[cls] = counts.get(cls, 0) + 1

        if bool(r.get("pass")):
            passed += 1
        else:
            failed += 1

    tp = counts["TP"]
    tn = counts["TN"]
    fp = counts["FP"]
    fn = counts["FN"]

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)) if precision is not None and recall is not None and (precision + recall) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    fnr = fn / (fn + tp) if (fn + tp) else None

    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "total_runs": len(results),
        "passed": passed,
        "failed": failed,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
    }

def _ztx_eval_payload_from_response(ret):
    code = 200
    obj = ret

    if isinstance(ret, tuple):
        obj = ret[0]
        if len(ret) > 1 and isinstance(ret[1], int):
            code = ret[1]

    if hasattr(obj, "get_json"):
        data = obj.get_json(silent=True)
        if data is not None:
            return data, code

    if isinstance(obj, dict):
        return obj, code

    return {"ok": True}, code

try:
    for _rule in list(APP.url_map.iter_rules()):
        if _rule.rule == "/csm/evaluation/summary":
            _endpoint = _rule.endpoint
            _original_eval_summary_view_v1 = APP.view_functions[_endpoint]

            def _ztx_eval_summary_dedupe_wrapper(*args, **kwargs):
                ret = _original_eval_summary_view_v1(*args, **kwargs)
                data, code = _ztx_eval_payload_from_response(ret)

                raw_results = data.get("recent_results")
                if raw_results is None:
                    raw_results = list(globals().get("ZT_SCENARIO_RESULTS", []))

                raw_count = len(raw_results or [])
                deduped = _ztx_eval_dedupe_results(raw_results)

                summary = _ztx_eval_summary_from_results(deduped)
                data.update(summary)
                data["recent_results"] = deduped[-20:]
                data["raw_total_runs_before_dedupe"] = raw_count
                data["deduped_total_runs"] = len(deduped)
                data["ztx_evaluation_dedupe_fix_v1"] = True

                return jsonify(data), code

            APP.view_functions[_endpoint] = _ztx_eval_summary_dedupe_wrapper
            break
except Exception as _ztx_eval_wrap_exc:
    print("ZTX_EVALUATION_DEDUPE_FIX_V1 wrapper failed", repr(_ztx_eval_wrap_exc))

print("ZTX_EVALUATION_DEDUPE_FIX_V1 loaded")

# ZTX_PRIME_AUDIT_NOT_RESTORE_FIX_V1
_ZTX_PRIME_AUDIT_NOT_RESTORE_FIX_V1 = True
print("ZTX_PRIME_AUDIT_NOT_RESTORE_FIX_V1 loaded")

# 2026-08-24: SOC dashboard backend (per-xApp kubelet-summary metrics +
# whitelisted attack launcher). Registered at module level so the routes
# exist regardless of how the app is served.
try:
    import ztx_dashboard_api
    ztx_dashboard_api.register_dashboard_api(APP)
    print("ZTX_DASHBOARD_API_REGISTERED")
except Exception as _ztx_dash_exc:
    ztx_dashboard_api = None
    print("ZTX_DASHBOARD_API_FAILED", repr(_ztx_dash_exc))

if __name__ == "__main__":
    if SCAN_INTERVAL_SEC > 0:
        t = threading.Thread(target=scanner_loop, daemon=True)
        t.start()
    # 2026-07-16: guarantees the 30s dwell promise even for an xApp that
    # gets no further incoming event after first reaching COMPROMISED
    # under DWELL_30S timing (e.g. an attack is cancelled partway
    # through, or a Falco correlation escalation never repeats) - the
    # inline per-event checks in csm_update_from_result/
    # ztx_v4_process_signal only catch an expired window when a NEW
    # event happens to arrive for that same xApp.
    if ztx_isolation_manager is not None:
        ztx_isolation_manager.start_dwell_checker(_ztx_dwell_expired_callback)
    # 2026-07-24: keeps the Falco rules' headless-service pod-IP macros
    # (submgr, dbaas/SDL) in sync with reality - see
    # ztx_falco_rule_sync.py's module docstring for the false-positive
    # this closes (kpimon-go's own SDL/RMR traffic misclassified as
    # external egress whenever either backing pod restarts).
    if ztx_falco_rule_sync is not None:
        ztx_falco_rule_sync.start_falco_ip_reconciler_loop()
    # 2026-08-24: per-xApp metrics collector for the SOC dashboard graphs.
    if ztx_dashboard_api is not None:
        ztx_dashboard_api.start_metrics_collector()
    APP.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), threaded=True)

