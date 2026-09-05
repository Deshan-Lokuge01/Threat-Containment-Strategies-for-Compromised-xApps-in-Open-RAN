"""
ZT-XGuard Policy Engine - Event Normalization component.

Extracted verbatim from app.py during step_xguard_02 Step B1 (2026-07-15).
Turns a raw Falco alert into (xapp, pod_name, namespace) identity plus a
normalized signal string from the fixed signal vocabulary - the first
stage of the pipeline, before the Policy Decision Engine (ztx_state_engine.py
plus the decision glue remaining in app.py) and the Containment
Orchestrator (containment_orchestrator.py) ever see it.

This is a pure, mechanical move - no behavior changes. Every function here
is re-imported into app.py under the same name so every existing call site
(live and dead) keeps resolving exactly as before.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from ztx_config import XAPP_NAMESPACE, XAPP_LIST

# ------------------------------------------------------------
# ZT_XGUARD_INTENT_ENGINE_V4
# Per-xApp declared intent profiles - what each xApp is expected to do.
# ------------------------------------------------------------

ZT_INTENT_PROFILES_V4 = {
    "telemetry-monitor": {
        "role": "telemetry-monitoring",
        "expected_shell": False,
        "expected_sensitive_file_access": False,
        "expected_serviceaccount_token_access": False,
        "expected_external_egress": False,
        "expected_cross_xapp_comm": False,
        "expected_high_workload": False,
        "expected_control_output": False,
        "allowed_peers": [],
        "allowed_ric_services": [],
    },
    "qos-optimizer": {
        "role": "qos-optimization",
        "expected_shell": False,
        "expected_sensitive_file_access": False,
        "expected_serviceaccount_token_access": False,
        "expected_external_egress": False,
        "expected_cross_xapp_comm": False,
        "expected_high_workload": False,
        "expected_control_output": True,
        "allowed_peers": [],
        "allowed_ric_services": [],
    },
    "traffic-analyzer": {
        "role": "traffic-analysis",
        "expected_shell": False,
        "expected_sensitive_file_access": False,
        "expected_serviceaccount_token_access": False,
        "expected_external_egress": False,
        "expected_cross_xapp_comm": False,
        "expected_high_workload": True,
        "expected_control_output": False,
        "allowed_peers": [],
        "allowed_ric_services": [],
    },
    "resource-optimizer": {
        "role": "resource-optimization",
        "expected_shell": False,
        "expected_sensitive_file_access": False,
        "expected_serviceaccount_token_access": False,
        "expected_external_egress": False,
        "expected_cross_xapp_comm": False,
        "expected_high_workload": False,
        "expected_control_output": True,
        "allowed_peers": [],
        "allowed_ric_services": [],
    },
    "security-observer": {
        "role": "security-observation",
        "expected_shell": False,
        "expected_sensitive_file_access": False,
        "expected_serviceaccount_token_access": False,
        "expected_external_egress": False,
        "expected_cross_xapp_comm": False,
        "expected_high_workload": False,
        "expected_control_output": False,
        "allowed_peers": [],
        "allowed_ric_services": [],
    },
}


# ------------------------------------------------------------
# ZT_XGUARD_EVENT_SCOPE_FILTER_MARKER
# Falco event scope filter
# ------------------------------------------------------------

def _ztx_get_output_fields(event: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(event, dict):
        return {}
    fields = event.get("output_fields") or event.get("outputFields") or {}
    return fields if isinstance(fields, dict) else {}


def _ztx_get_event_namespace(event: Dict[str, Any]) -> Optional[str]:
    fields = _ztx_get_output_fields(event)

    candidates = [
        fields.get("k8s.ns.name"),
        fields.get("k8s.namespace.name"),
        fields.get("k8s.ns"),
        fields.get("namespace"),
        event.get("namespace"),
        event.get("k8s_ns_name"),
    ]

    for value in candidates:
        if value:
            return str(value)

    return None


def _ztx_get_event_pod(event: Dict[str, Any]) -> Optional[str]:
    fields = _ztx_get_output_fields(event)

    candidates = [
        fields.get("k8s.pod.name"),
        fields.get("k8s.pod"),
        fields.get("pod"),
        event.get("pod"),
        event.get("pod_name"),
        event.get("k8s_pod_name"),
    ]

    for value in candidates:
        if value:
            return str(value)

    # Last-resort extraction from output string.
    output = str(event.get("output") or "")
    for token in output.replace(",", " ").split():
        if token.startswith("pod="):
            return token.split("=", 1)[1].strip()

    return None


def _ztx_xapp_list() -> List[str]:
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


def _ztx_xapp_from_pod_name(pod_name: Optional[str]) -> Optional[str]:
    pod_name = str(pod_name or "")
    if not pod_name:
        return None

    for xapp in _ztx_xapp_list():
        if pod_name == xapp or pod_name.startswith(xapp + "-"):
            return xapp

    return None


def _ztx_event_scope_decision(event: Dict[str, Any]) -> Dict[str, Any]:
    namespace = _ztx_get_event_namespace(event)
    pod_name = _ztx_get_event_pod(event)
    xapp = _ztx_xapp_from_pod_name(pod_name)

    rule = str(event.get("rule") or event.get("Rule") or "")
    priority = str(event.get("priority") or event.get("Priority") or "")

    # If namespace is known and it is not ricxapp, ignore it.
    # This prevents policy-engine/Falco/Kubernetes-control-plane events from
    # polluting the xApp trust state.
    if namespace and namespace != XAPP_NAMESPACE:
        return {
            "process": False,
            "reason": "outside_xapp_namespace",
            "namespace": namespace,
            "pod_name": pod_name,
            "xapp": xapp,
            "rule": rule,
            "priority": priority,
        }

    # If pod name does not map to a known ZT-XGuard xApp, ignore it.
    if not xapp:
        return {
            "process": False,
            "reason": "pod_not_in_ztx_xapp_list",
            "namespace": namespace,
            "pod_name": pod_name,
            "xapp": None,
            "rule": rule,
            "priority": priority,
        }

    return {
        "process": True,
        "reason": "in_scope_xapp_event",
        "namespace": namespace or XAPP_NAMESPACE,
        "pod_name": pod_name,
        "xapp": xapp,
        "rule": rule,
        "priority": priority,
    }


def ztx_v4_event_identity(event):
    try:
        scope = _ztx_event_scope_decision(event)
        return scope.get("xapp"), scope.get("pod_name"), scope.get("namespace") or XAPP_NAMESPACE
    except Exception:
        pass

    fields = (event or {}).get("output_fields") or {}
    ns = fields.get("k8s.ns.name") or XAPP_NAMESPACE
    pod = fields.get("k8s.pod.name") or ""
    xapp = None
    for candidate in ZT_INTENT_PROFILES_V4:
        if pod == candidate or pod.startswith(candidate + "-"):
            xapp = candidate
            break
    return xapp, pod, ns


_ZTX_FALCO_SIGNAL_RE = re.compile(r"\bztx(?:_|\.)signal=([a-z0-9_]+)\b", re.IGNORECASE)


def _ztx_v4_embedded_signal(*parts: Any) -> Optional[str]:
    for part in parts:
        text = str(part or "")
        if not text:
            continue
        match = _ZTX_FALCO_SIGNAL_RE.search(text)
        if match:
            return str(match.group(1)).strip().lower()
    return None


def ztx_v4_signal_from_event(event):
    event = event or {}
    fields = event.get("output_fields") or {}
    rule = str(event.get("rule") or "")
    output = str(event.get("output") or "")
    proc = str(fields.get("proc.name") or "")
    cmdline = str(fields.get("proc.cmdline") or "")
    fd_name = str(fields.get("fd.name") or "")

    blob = " ".join([rule, output, proc, cmdline, fd_name]).lower()

    if event.get("ztx_signal"):
        return str(event.get("ztx_signal")).strip().lower()

    if fields.get("ztx.signal"):
        return str(fields.get("ztx.signal")).strip().lower()

    if fields.get("ztx_signal"):
        return str(fields.get("ztx_signal")).strip().lower()

    embedded_signal = _ztx_v4_embedded_signal(output, rule, json.dumps(fields, sort_keys=True, default=str))
    if embedded_signal:
        return embedded_signal

    if "shell" in blob or proc in ["sh", "bash", "dash", "zsh"] or "/bin/sh" in blob:
        return "unexpected_shell"

    if "/etc/shadow" in blob or "sensitive file" in blob:
        return "sensitive_file_access"

    if "serviceaccount" in blob or "service account" in blob or "/var/run/secrets/kubernetes.io" in blob:
        return "serviceaccount_token_access"

    if "external" in blob or "egress" in blob or "attacker" in blob:
        return "external_egress"

    if "ric service" in blob or "ricplt" in blob or "e2mgr" in blob or "appmgr" in blob:
        return "ric_service_probe"

    if "cross-xapp" in blob or "inter-xapp" in blob or ".ricxapp.svc" in blob:
        return "unexpected_peer_contact"

    if "integrity" in blob or "digest mismatch" in blob or "profile hash" in blob:
        return "integrity_mismatch"

    if "cpu" in blob or "stress" in blob or "stress-ng" in blob:
        return "high_cpu"

    if "output drift" in blob or "profile drift" in blob:
        return "profile_output_drift"

    return "falco_observed"
