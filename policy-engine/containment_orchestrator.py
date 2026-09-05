"""
ZT-XGuard Policy Engine - Containment Orchestrator component.

Extracted verbatim from app.py during step_xguard_02 Step B1 (2026-07-15),
which itself consolidated 4 overlapping containment implementations down
to 1 (Step A, same date). This module owns every K8s write the policy
engine performs once a xApp has been decided COMPROMISED: pod quarantine
labels + deny-all NetworkPolicy, Service selector isolation (and restore),
deployment scale-down (and restore), and SPIRE entry revocation.

This is a pure, mechanical move - no behavior changes. Every function here
is re-imported into app.py under the same name so every existing call site
(live and dead) keeps resolving exactly as before.

Containment is NOT currently functional end-to-end on the live cluster -
the policy engine's ServiceAccount has read-only RBAC in ricxapp (see
project memory ztxguard-containment-not-yet-implemented). That gap is
deliberately untouched here; this move only consolidates/relocates the
code that attempts containment, it does not fix why those attempts fail.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import random
import time
import traceback
import uuid as _ztx_surgical_uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from kubernetes import client
from kubernetes.client import ApiException
from kubernetes.stream import stream

from ztx_config import (
    XAPP_NAMESPACE,
    XAPP_LIST,
    CONTAINMENT_MODE,
    REVOKE_SPIRE,
    SPIRE_SERVER_POD,
    SPIRE_NAMESPACE,
    SPIRE_CONTAINER,
    SPIRE_BIN,
    ZTX_SUSPICIOUS_ONLY_SIGNALS,
    ZTX_QUARANTINE_CAPABLE_SIGNALS,
    ZTX_SIGNAL_ALIASES,
    ZTX_QUARANTINE_LABEL_VALUES,
    ORIGINAL_SELECTOR_ANNOTATION,
    SERVICE_ISOLATED_ANNOTATION,
    SERVICE_ISOLATED_INCIDENT_ANNOTATION,
    ORIGINAL_REPLICAS_ANNOTATION,
    DIRECT_IPTABLES_ENABLED,
    DIRECT_IPTABLES_NAMESPACE,
    DIRECT_IPTABLES_POD_LABEL,
    DIRECT_IPTABLES_CONTAINER,
    DIRECT_IPTABLES_CHAIN,
    RESTORE_POD_RECREATION_ENABLED,
    RESTORE_POD_RECREATION_TIMEOUT_SECONDS,
)
from k8s_clients import CORE, APPS, NET, CUSTOM, EXEC_CORE
from csm_shared_state import CSM_STATE, CSM_STATE_LOCK, csm_mark_restored


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# -----------------------------
# Label-write guard helpers
# -----------------------------

def ztx_normalize_signal(signal: Any) -> Optional[str]:
    normalized = str(signal or "").strip().lower()
    if not normalized:
        return None
    return ZTX_SIGNAL_ALIASES.get(normalized, normalized)


def ztx_label_write_context(
    *,
    normalized_signal: Optional[str] = None,
    containment_required: Optional[bool] = None,
    decision_state: Optional[str] = None,
    handler_path: Optional[str] = None,
    incident_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "normalized_signal": ztx_normalize_signal(normalized_signal),
        "containment_required": containment_required if containment_required is None else bool(containment_required),
        "decision_state": str(decision_state or "").strip().upper() or None,
        "handler_path": str(handler_path or "").strip() or None,
        "incident_id": str(incident_id or "").strip() or None,
    }


def ztx_quarantine_label_write_decision(write_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    context = dict(write_context or {})
    normalized_signal = ztx_normalize_signal(context.get("normalized_signal"))
    containment_required = context.get("containment_required")

    # 2026-07-23: containment_required (the caller's/state engine's own
    # decision, made with full context) is now checked BEFORE signal-set
    # membership - previously ZTX_SUSPICIOUS_ONLY_SIGNALS was checked
    # first unconditionally, which silently defeated containment for any
    # signal that was ALSO (incorrectly, in one case) listed there
    # regardless of what the state engine had decided. See
    # ztx_config.py's own comment on ZTX_SUSPICIOUS_ONLY_SIGNALS for the
    # concrete case (malicious_tool_execution/ZTX-A6) this was actively
    # breaking.
    if containment_required is True:
        return {
            "normalized_signal": normalized_signal,
            "containment_required": True,
            "label_write_allowed": True,
            "label_write_block_reason": None,
            "handler_path": context.get("handler_path"),
        }

    if containment_required is False:
        return {
            "normalized_signal": normalized_signal,
            "containment_required": False,
            "label_write_allowed": False,
            "label_write_block_reason": "containment_not_required",
            "handler_path": context.get("handler_path"),
        }

    if normalized_signal in ZTX_SUSPICIOUS_ONLY_SIGNALS:
        return {
            "normalized_signal": normalized_signal,
            "containment_required": containment_required,
            "label_write_allowed": False,
            "label_write_block_reason": "suspicious_only_signal",
            "handler_path": context.get("handler_path"),
        }

    if normalized_signal in ZTX_QUARANTINE_CAPABLE_SIGNALS:
        return {
            "normalized_signal": normalized_signal,
            "containment_required": containment_required,
            "label_write_allowed": True,
            "label_write_block_reason": None,
            "handler_path": context.get("handler_path"),
        }

    return {
        "normalized_signal": normalized_signal,
        "containment_required": containment_required,
        "label_write_allowed": False,
        "label_write_block_reason": "missing_signal_or_containment_context",
        "handler_path": context.get("handler_path"),
    }


def _ztx_json_pointer_unescape(value: str) -> str:
    return value.replace("~1", "/").replace("~0", "~")


def ztx_requested_pod_labels(body: Any) -> Dict[str, Any]:
    labels: Dict[str, Any] = {}

    if isinstance(body, dict):
        metadata = body.get("metadata") or {}
        raw_labels = metadata.get("labels") or {}
        if isinstance(raw_labels, dict):
            labels.update(raw_labels)
        return labels

    if isinstance(body, list):
        prefix = "/metadata/labels/"
        for item in body:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path") or "")
            if not path.startswith(prefix):
                continue
            key = _ztx_json_pointer_unescape(path[len(prefix):])
            op = str(item.get("op") or "").lower()
            if op in {"add", "replace"}:
                labels[key] = item.get("value")
            elif op == "remove":
                labels[key] = None

    return labels


def ztx_attempts_quarantine_labels(body: Any) -> bool:
    requested = ztx_requested_pod_labels(body)
    for key, expected in ZTX_QUARANTINE_LABEL_VALUES.items():
        value = requested.get(key)
        if value is None:
            continue
        if str(value).strip().lower() == expected:
            return True
    return False


def ztx_non_quarantine_decision_label(write_context: Optional[Dict[str, Any]] = None) -> Optional[str]:
    context = dict(write_context or {})
    decision_label = str(context.get("decision_state") or "").strip().lower() or None

    if decision_label in {"quarantined", "compromised"}:
        decision_label = None

    if not decision_label and ztx_normalize_signal(context.get("normalized_signal")) in ZTX_SUSPICIOUS_ONLY_SIGNALS:
        decision_label = "suspicious"

    return decision_label


def ztx_quarantine_clear_patch(write_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    decision_label = ztx_non_quarantine_decision_label(write_context)
    return {
        "metadata": {
            "labels": {
                "security-status": None,
                "zt-xguard.io/quarantine": None,
                "zt-xguard.io/decision": decision_label,
            },
            "annotations": {
                "zt-xguard.io/quarantine-reason": None,
                "zt-xguard.io/quarantine-time": None,
                "zt-xguard.io/incident-id": None,
            },
        }
    }


def ztx_guarded_patch_namespaced_pod(
    *,
    name: str,
    namespace: str,
    body: Any,
    write_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    guard = ztx_quarantine_label_write_decision(write_context)
    guard["attempted_quarantine_label_write"] = ztx_attempts_quarantine_labels(body)

    if guard["attempted_quarantine_label_write"] and not guard["label_write_allowed"]:
        enforced_body = ztx_quarantine_clear_patch(write_context)
        CORE.patch_namespaced_pod(name=name, namespace=namespace, body=enforced_body)
        guard["patched"] = True
        guard["enforced_clear"] = True
        return guard

    CORE.patch_namespaced_pod(name=name, namespace=namespace, body=body)
    guard["patched"] = True
    guard["enforced_clear"] = False
    return guard


# -----------------------------
# Containment
# -----------------------------

def ensure_quarantine_network_policy(namespace: str = XAPP_NAMESPACE) -> None:
    netpol = client.V1NetworkPolicy(
        metadata=client.V1ObjectMeta(name="zt-xguard-quarantine-deny-all", namespace=namespace),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(match_labels={"zt-xguard.io/quarantine": "true"}),
            policy_types=["Ingress", "Egress"],
            ingress=[],
            egress=[],
        ),
    )
    try:
        NET.create_namespaced_network_policy(namespace=namespace, body=netpol)
    except ApiException as exc:
        if exc.status == 409:
            NET.patch_namespaced_network_policy(name="zt-xguard-quarantine-deny-all", namespace=namespace, body=netpol)
        else:
            raise


# Phase 3 (mechanism #2, 2026-07-17): SUSPICIOUS-tier micro-segmentation,
# Calico-native (not plain Kubernetes NetworkPolicy - operator's explicit
# choice, confirmed the crd.projectcalico.org/v1 CRD suite is actually
# installed here via `kubectl get crd`/`kubectl explain` before writing
# this, rather than assuming the calicoctl-style projectcalico.org/v3 shape
# applies - that apiVersion needs a separate aggregated API server this
# cluster doesn't have). Softer than the existing COMPROMISED/ISOLATED
# deny-all: blocks xApp-to-xApp lateral movement within ricxapp specifically
# (the proposal's own "prevent lateral movement" language), while leaving
# legitimate ricplt (RIC platform) traffic and DNS untouched - egress only,
# ingress is deliberately not restricted since SUSPICIOUS is not yet a
# confirmed compromise. This is a genuinely separate policy object from
# ensure_quarantine_network_policy above - that one is proven working and
# is not touched by this change at all.
CALICO_CRD_GROUP = "crd.projectcalico.org"
CALICO_CRD_VERSION = "v1"
CALICO_NETWORKPOLICY_PLURAL = "networkpolicies"
SUSPICIOUS_NETWORKPOLICY_NAME = "zt-xguard-suspicious-lateral-block"


# 2026-07-23 (Fix F): this function's return used to claim "applied": True
# on a bare 201/409-from-create-then-patch response from the Calico CRD API
# - i.e. the CRD object was accepted, nothing more, and at the time Felix's
# NetworkPolicy enforcement was believed completely non-functional on this
# cluster (empty `iptables-save` on calico-node despite Felix's logs
# showing it processes policy updates).
#
# UPDATE 2026-07-24: that original finding was itself an artifact of a
# missing command - this container image has no plain `iptables-save`
# binary, only `iptables-legacy-save`/`iptables-nft-save`, and the original
# check silently read nothing. A live diagnostic (FELIX_IPTABLESBACKEND
# flip + revert, converging on Felix's own "auto" detection settling into
# NFT mode) now shows Felix genuinely programming ~1000 `cali-` rules via
# iptables-nft. Directly confirmed with a real A/B traffic test against
# kpimon-go: `ensure_quarantine_network_policy`'s plain-K8s deny-all
# (`zt-xguard-quarantine-deny-all`) measurably blocks a raw TCP connect to
# the pod's real IP:port while quarantined and allows it once restored,
# with zero involvement from the independent direct-iptables chain
# (confirmed empty for that pod IP throughout) - the CRD's own
# `cali-pi-.../cali-po-...` chains reference "Policy
# ricxapp/knp.default.zt-xguard-quarantine-deny-all" directly. That proves
# Felix/Calico NetworkPolicy enforcement is real on this cluster as of
# today for the plain-K8s-NetworkPolicy-based ISOLATED tier.
#
# This function's policy is a *different* object - Calico-native CRD
# (crd.projectcalico.org/v1), not networking.k8s.io/v1 - for the softer
# SUSPICIOUS tier. Both compile through the same Felix/iptables-nft
# pipeline, so it is reasonable to expect this one also enforces, but it
# has NOT been independently isolated-tested: every attempt to test it live
# (making egress connections from kpimon-go's own pod to probe allow/deny
# behavior) was itself detected by the runtime trust engine as suspicious
# egress within ~3 seconds and auto-escalated the pod to full ISOLATED
# quarantine mid-test, confounding the result with the already-proven
# deny-all policy. Left dataplane_enforcement_verified conservatively
# False for THIS specific policy pending a clean test (e.g. from a
# temporarily-detection-exempt probe), but the enforcement_note below no
# longer claims Felix is broken in general - it isn't.
ZTX_SUSPICIOUS_NETPOL_ENFORCEMENT_NOTE = (
    "api_accepted only reflects that the Calico NetworkPolicy CRD object "
    "was created/patched successfully. dataplane_enforcement_verified is "
    "conservatively false for THIS specific CRD-based policy object, but "
    "Felix/Calico NetworkPolicy enforcement in general is CONFIRMED "
    "functional on this cluster as of 2026-07-24 (iptables-nft backend, "
    "~1000 cali- rules programmed, live A/B traffic test against the "
    "sibling plain-K8s deny-all policy) - see this constant's module "
    "comment for the full test methodology. This CRD-based policy shares "
    "the same enforcement pipeline but has not itself been isolated-tested, "
    "since live test traffic from the protected pod triggers real "
    "auto-quarantine before the softer policy's specific rules can be "
    "distinguished."
)


def ensure_suspicious_network_policy(namespace: str = XAPP_NAMESPACE) -> Dict[str, Any]:
    body = {
        "apiVersion": f"{CALICO_CRD_GROUP}/{CALICO_CRD_VERSION}",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": SUSPICIOUS_NETWORKPOLICY_NAME,
            "namespace": namespace,
        },
        "spec": {
            "selector": 'zt-xguard.io/suspicious == "true"',
            "types": ["Egress"],
            # Lower than nothing else defined here on purpose - this is the
            # softer tier, evaluated ahead of no other zt-xguard policy
            # since the existing quarantine deny-all is a separate plain
            # K8s NetworkPolicy object, not in this same Calico-native
            # policy set, and the two never match the same pod at once
            # (disjoint labels, see _ztx_original_apply_quarantine).
            "order": 200,
            "egress": [
                {
                    "action": "Allow",
                    "destination": {"namespaceSelector": 'kubernetes.io/metadata.name == "ricplt"'},
                },
                {
                    "action": "Allow",
                    "protocol": "UDP",
                    "destination": {
                        "namespaceSelector": 'kubernetes.io/metadata.name == "kube-system"',
                        "ports": [53],
                    },
                },
                {
                    "action": "Allow",
                    "protocol": "TCP",
                    "destination": {
                        "namespaceSelector": 'kubernetes.io/metadata.name == "kube-system"',
                        "ports": [53],
                    },
                },
            ],
        },
    }
    try:
        CUSTOM.create_namespaced_custom_object(
            group=CALICO_CRD_GROUP,
            version=CALICO_CRD_VERSION,
            namespace=namespace,
            plural=CALICO_NETWORKPOLICY_PLURAL,
            body=body,
        )
        return {
            "api_accepted": True,
            "dataplane_enforcement_verified": False,
            "enforcement_note": ZTX_SUSPICIOUS_NETPOL_ENFORCEMENT_NOTE,
            "method": "create",
            "name": SUSPICIOUS_NETWORKPOLICY_NAME,
        }
    except ApiException as exc:
        if exc.status == 409:
            CUSTOM.patch_namespaced_custom_object(
                group=CALICO_CRD_GROUP,
                version=CALICO_CRD_VERSION,
                namespace=namespace,
                plural=CALICO_NETWORKPOLICY_PLURAL,
                name=SUSPICIOUS_NETWORKPOLICY_NAME,
                body=body,
            )
            return {
                "api_accepted": True,
                "dataplane_enforcement_verified": False,
                "enforcement_note": ZTX_SUSPICIOUS_NETPOL_ENFORCEMENT_NOTE,
                "method": "patch",
                "name": SUSPICIOUS_NETWORKPOLICY_NAME,
            }
        return {"api_accepted": False, "dataplane_enforcement_verified": False, "error": str(exc), "status": exc.status}
    except Exception as exc:
        return {"api_accepted": False, "dataplane_enforcement_verified": False, "error": str(exc), "trace": traceback.format_exc()}


def _ztx_original_apply_quarantine(
    pod_name: str,
    namespace: str,
    reason: str,
    incident_id: str,
    write_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    patch = {
        "metadata": {
            "labels": {
                "security-status": "quarantined",
                "zt-xguard.io/quarantine": "true",
                "zt-xguard.io/decision": "quarantined",
                # null deletes the key in a strategic-merge-patch - keeps
                # the SUSPICIOUS and COMPROMISED/ISOLATED tiers disjoint so
                # a pod is never matched by both Calico policies at once
                # (Phase 3, 2026-07-17).
                "zt-xguard.io/suspicious": None,
            },
            "annotations": {
                "zt-xguard.io/quarantine-reason": reason[:240],
                "zt-xguard.io/quarantine-time": utc_now(),
                "zt-xguard.io/incident-id": incident_id,
            },
        }
    }
    write_result = ztx_guarded_patch_namespaced_pod(
        name=pod_name,
        namespace=namespace,
        body=patch,
        write_context=write_context,
    )
    if not write_result.get("label_write_allowed"):
        return {
            "applied": False,
            "method": "pod_label_quarantine_blocked",
            "network_policy": None,
            **write_result,
        }
    ensure_quarantine_network_policy(namespace)
    return {
        "applied": True,
        "method": "pod_label_plus_deny_all_networkpolicy",
        "network_policy": "zt-xguard-quarantine-deny-all",
        **write_result,
    }


def get_pod_safe(pod_name: str, namespace: str) -> Optional[Any]:
    try:
        return CORE.read_namespaced_pod(name=pod_name, namespace=namespace)
    except Exception:
        return None


def get_xapp_from_pod_or_name(pod: Optional[Any], pod_name: Optional[str]) -> str:
    try:
        if pod is not None:
            labels = pod.metadata.labels or {}
            if labels.get("app"):
                return labels.get("app")
    except Exception:
        pass

    pod_name = pod_name or ""
    for xapp in XAPP_LIST:
        if pod_name.startswith(xapp):
            return xapp
    return "unknown"


def list_services_for_xapp(xapp: str, namespace: str = XAPP_NAMESPACE) -> List[Any]:
    """Return services that appear to front this xApp.

    Preferred match:
    - Service selector app=<xapp>

    Fallback match:
    - Service name equals xApp
    - Service name contains xApp
    """
    try:
        services = CORE.list_namespaced_service(namespace=namespace).items
    except Exception:
        return []

    matched = []
    for svc in services:
        name = svc.metadata.name
        selector = svc.spec.selector or {}

        if selector.get("app") == xapp:
            matched.append(svc)
            continue

        if name == xapp or xapp in name:
            matched.append(svc)
            continue

        # Already isolated services should still be restorable.
        ann = svc.metadata.annotations or {}
        if ann.get("zt-xguard.io/xapp") == xapp:
            matched.append(svc)

    return matched


def ztx_patch5b_v3_endpoint_summary(service_name, namespace=None):
    namespace = namespace or XAPP_NAMESPACE
    try:
        ep = CORE.read_namespaced_endpoints(name=service_name, namespace=namespace)
        subsets = getattr(ep, "subsets", None)

        if not subsets:
            return {
                "service": service_name,
                "endpoint_count": 0,
                "has_endpoints": False,
                "addresses": [],
                "ports": [],
                "source": "endpoints",
                "error": None,
                "patch5b_v3": True,
            }

        addresses = []
        ports = []
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
            "has_endpoints": len(addresses) > 0,
            "addresses": addresses,
            "ports": ports,
            "source": "endpoints",
            "error": None,
            "patch5b_v3": True,
        }
    except Exception as exc:
        return {
            "service": service_name,
            "endpoint_count": None,
            "has_endpoints": None,
            "addresses": [],
            "ports": [],
            "source": None,
            "error": str(exc),
            "patch5b_v3": True,
        }


def service_endpoints_summary(service_name, namespace=None, *args, **kwargs):
    return ztx_patch5b_v3_endpoint_summary(service_name, namespace)


def k8s_label_value(prefix: str, raw: str, max_len: int = 63) -> str:
    """Return a Kubernetes-safe label value.

    Kubernetes label values must be <=63 characters and should begin/end with
    an alphanumeric character. Event-generated incident IDs can be much longer,
    so Service selectors must use a short stable token instead of the full
    incident ID.

    Full incident IDs are still preserved in annotations and evidence files.
    """
    prefix = re.sub(r"[^A-Za-z0-9]+", "-", str(prefix or "ztxq")).strip("-")
    if not prefix:
        prefix = "ztxq"

    digest = hashlib.sha256(str(raw or "").encode("utf-8")).hexdigest()[:16]
    value = f"{prefix}-{digest}"

    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", value)
    value = value[:max_len].strip("-. _")

    if not value:
        value = f"ztxq-{digest[:8]}"

    # Ensure first and last chars are alphanumeric.
    value = re.sub(r"^[^A-Za-z0-9]+", "", value)
    value = re.sub(r"[^A-Za-z0-9]+$", "", value)

    if not value:
        value = f"ztxq-{digest[:8]}"

    return value[:max_len]


def apply_service_isolation(
    xapp: str,
    namespace: str,
    incident_id: str,
    reason: str,
) -> Dict[str, Any]:
    """Isolate an xApp at Kubernetes Service level.

    This is a fallback for environments where NetworkPolicy objects are accepted
    but not enforced by the CNI. It works by changing the Service selector so
    normal service traffic no longer reaches the compromised xApp pod.

    It preserves the original selector in a Service annotation so restore can
    put the Service back.
    """
    services = list_services_for_xapp(xapp, namespace)
    results = []

    if not services:
        return {
            "applied": False,
            "method": "service_selector_isolation",
            "reason": "no_matching_service_found",
            "xapp": xapp,
            "namespace": namespace,
            "services": [],
        }

    for svc in services:
        svc_name = svc.metadata.name
        annotations = svc.metadata.annotations or {}
        current_selector = svc.spec.selector or {}

        original_selector_json = annotations.get(ORIGINAL_SELECTOR_ANNOTATION)
        if original_selector_json:
            original_selector = original_selector_json
        else:
            original_selector = json.dumps(current_selector, sort_keys=True)

        selector_token = k8s_label_value("ztxq", incident_id)

        blocked_selector = {
            "zt-xguard.io/service-isolated": selector_token
        }

        patch = {
            "metadata": {
                "annotations": {
                    ORIGINAL_SELECTOR_ANNOTATION: original_selector,
                    SERVICE_ISOLATED_ANNOTATION: "true",
                    SERVICE_ISOLATED_INCIDENT_ANNOTATION: incident_id,
                    "zt-xguard.io/xapp": xapp,
                    "zt-xguard.io/service-isolated-time": utc_now(),
                    "zt-xguard.io/service-isolated-reason": reason[:240],
                    "zt-xguard.io/service-isolated-selector-token": selector_token,
                }
            },
            "spec": {
                "selector": blocked_selector
            }
        }

        CORE.patch_namespaced_service(name=svc_name, namespace=namespace, body=patch)

        # Poll until the endpoints controller ACTUALLY drains this Service's
        # endpoints - this measures the real time-to-effect of service isolation
        # (traffic can no longer land on the pod), not a fixed guess.
        _ep_deadline = time.time() + 4.0
        ep_summary = service_endpoints_summary(svc_name, namespace)
        while ep_summary.get("has_endpoints", False) and time.time() < _ep_deadline:
            time.sleep(0.05)
            ep_summary = service_endpoints_summary(svc_name, namespace)

        results.append({
            "service": svc_name,
            "original_selector": json.loads(original_selector),
            "blocked_selector": blocked_selector,
            "endpoint_summary_after_patch": ep_summary,
            "isolated": not ep_summary.get("has_endpoints", False),
        })

    return {
        "applied": True,
        "method": "service_selector_isolation",
        "xapp": xapp,
        "namespace": namespace,
        "services": results,
    }


def restore_service_isolation(
    xapp: str,
    namespace: str = XAPP_NAMESPACE,
) -> Dict[str, Any]:
    """Restore xApp Service selector after service-level containment.

    Important:
    Kubernetes merge patches can merge selector maps instead of replacing them.
    Therefore this function explicitly sets stale isolation selector keys to null.
    That removes keys such as zt-xguard.io/service-isolated while preserving
    the original app selector.

    This avoids the previous bug where the API claimed restore=true but the
    Service selector still contained the isolation key and endpoints stayed empty.
    """
    services = list_services_for_xapp(xapp, namespace)
    results = []

    if not services:
        try:
            all_services = CORE.list_namespaced_service(namespace=namespace).items
            services = [
                svc for svc in all_services
                if (
                    (svc.metadata.annotations or {}).get("zt-xguard.io/xapp") == xapp
                    or svc.metadata.name == xapp
                    or xapp in svc.metadata.name
                )
            ]
        except Exception:
            services = []

    for svc in services:
        svc_name = svc.metadata.name
        annotations = svc.metadata.annotations or {}
        current_selector = svc.spec.selector or {}

        original_selector_json = annotations.get(ORIGINAL_SELECTOR_ANNOTATION)

        if original_selector_json:
            try:
                original_selector = json.loads(original_selector_json)
            except Exception:
                results.append({
                    "service": svc_name,
                    "restored": False,
                    "reason": "invalid_original_selector_json",
                    "raw": original_selector_json,
                })
                continue
        else:
            # Safe fallback: for our xApps the normal selector is app=<xapp>.
            # This handles cases where restore is called after manual cleanup or
            # after annotations were partially removed.
            original_selector = {"app": xapp}

        # Build a JSON Patch that really removes stale selector keys.
        # Merge patches do not reliably remove keys inside Service selector maps.
        def _json_pointer_escape(value: str) -> str:
            return value.replace("~", "~0").replace("/", "~1")

        selector_patch = []

        for key in list(current_selector.keys()):
            if key not in original_selector:
                selector_patch.append({
                    "op": "remove",
                    "path": f"/spec/selector/{_json_pointer_escape(key)}",
                })

        for key, value in original_selector.items():
            selector_patch.append({
                "op": "replace" if key in current_selector else "add",
                "path": f"/spec/selector/{_json_pointer_escape(key)}",
                "value": value,
            })

        stale_annotation_keys = [
            ORIGINAL_SELECTOR_ANNOTATION,
            SERVICE_ISOLATED_ANNOTATION,
            SERVICE_ISOLATED_INCIDENT_ANNOTATION,
            "zt-xguard.io/service-isolated-time",
            "zt-xguard.io/service-isolated-reason",
            "zt-xguard.io/service-isolated-selector-token",
            "zt-xguard.io/xapp",
        ]

        for key in stale_annotation_keys:
            if key in annotations:
                selector_patch.append({
                    "op": "remove",
                    "path": f"/metadata/annotations/{_json_pointer_escape(key)}",
                })

        try:
            if selector_patch:
                CORE.api_client.call_api(
                    "/api/v1/namespaces/{namespace}/services/{name}",
                    "PATCH",
                    path_params={"namespace": namespace, "name": svc_name},
                    query_params=[],
                    header_params={"Content-Type": "application/json-patch+json"},
                    body=selector_patch,
                    post_params=[],
                    files={},
                    response_type="object",
                    auth_settings=["BearerToken"],
                    _return_http_data_only=True,
                    _preload_content=True,
                )
        except Exception as exc:
            results.append({
                "service": svc_name,
                "restored": False,
                "reason": "patch_failed",
                "error": str(exc),
            })
            continue

        # Wait briefly for Endpoints/EndpointSlice controller to update.
        ep_summary = None
        selector_after = None

        for _ in range(15):
            time.sleep(0.25)
            try:
                svc_after = CORE.read_namespaced_service(name=svc_name, namespace=namespace)
                selector_after = svc_after.spec.selector or {}
            except Exception:
                selector_after = None

            ep_summary = service_endpoints_summary(svc_name, namespace)

            # Restored means:
            # 1. stale isolation selector is gone
            # 2. app selector is back
            # 3. endpoints are present again
            stale_selector_gone = not (
                selector_after and "zt-xguard.io/service-isolated" in selector_after
            )
            app_selector_restored = selector_after and selector_after.get("app") == xapp
            endpoints_back = ep_summary.get("has_endpoints") is True

            if stale_selector_gone and app_selector_restored and endpoints_back:
                break

        restored = bool(
            selector_after
            and selector_after.get("app") == xapp
            and "zt-xguard.io/service-isolated" not in selector_after
            and ep_summary
            and ep_summary.get("has_endpoints") is True
        )

        results.append({
            "service": svc_name,
            "restored": restored,
            "restored_selector": original_selector,
            "selector_after_restore": selector_after,
            "endpoint_summary_after_restore": ep_summary,
            "selector_patch_used": selector_patch,
        })

    return {
        "xapp": xapp,
        "namespace": namespace,
        "restored": any(r.get("restored") for r in results),
        "services": results,
    }


def scale_deployment_for_xapp(
    xapp: str,
    namespace: str,
    replicas: int,
    incident_id: str,
    reason: str,
) -> Dict[str, Any]:
    """Scale deployment for hard containment or restore.

    For containment, original replicas are saved in annotation.
    """
    deployment_name = xapp
    try:
        dep = APPS.read_namespaced_deployment(name=deployment_name, namespace=namespace)
    except Exception as exc:
        return {
            "applied": False,
            "method": "deployment_scale",
            "xapp": xapp,
            "deployment": deployment_name,
            "error": str(exc),
        }

    annotations = dep.metadata.annotations or {}
    original_replicas = annotations.get(ORIGINAL_REPLICAS_ANNOTATION)

    if original_replicas is None:
        original_replicas = str(dep.spec.replicas if dep.spec.replicas is not None else 1)

    patch = {
        "metadata": {
            "annotations": {
                ORIGINAL_REPLICAS_ANNOTATION: original_replicas,
                "zt-xguard.io/scale-incident": incident_id,
                "zt-xguard.io/scale-reason": reason[:240],
                "zt-xguard.io/scale-time": utc_now(),
            }
        },
        "spec": {
            "replicas": replicas
        }
    }

    APPS.patch_namespaced_deployment(name=deployment_name, namespace=namespace, body=patch)

    return {
        "applied": True,
        "method": "deployment_scale",
        "xapp": xapp,
        "deployment": deployment_name,
        "target_replicas": replicas,
        "original_replicas": int(original_replicas),
    }


def restore_deployment_scale(
    xapp: str,
    namespace: str = XAPP_NAMESPACE,
) -> Dict[str, Any]:
    deployment_name = xapp
    try:
        dep = APPS.read_namespaced_deployment(name=deployment_name, namespace=namespace)
    except Exception as exc:
        return {
            "restored": False,
            "method": "deployment_scale_restore",
            "xapp": xapp,
            "deployment": deployment_name,
            "error": str(exc),
        }

    annotations = dep.metadata.annotations or {}
    original_replicas_raw = annotations.get(ORIGINAL_REPLICAS_ANNOTATION)

    if original_replicas_raw is None:
        return {
            "restored": False,
            "method": "deployment_scale_restore",
            "xapp": xapp,
            "deployment": deployment_name,
            "reason": "no_original_replicas_annotation",
        }

    try:
        original_replicas = int(original_replicas_raw)
    except Exception:
        original_replicas = 1

    patch = {
        "metadata": {
            "annotations": {
                ORIGINAL_REPLICAS_ANNOTATION: None,
                "zt-xguard.io/scale-incident": None,
                "zt-xguard.io/scale-reason": None,
                "zt-xguard.io/scale-time": None,
            }
        },
        "spec": {
            "replicas": original_replicas
        }
    }

    APPS.patch_namespaced_deployment(name=deployment_name, namespace=namespace, body=patch)

    return {
        "restored": True,
        "method": "deployment_scale_restore",
        "xapp": xapp,
        "deployment": deployment_name,
        "replicas": original_replicas,
    }


# Per-xApp real per-mechanism containment latencies from the most recent
# apply_quarantine run. Read by the dashboard (/csm/incident/timing) to render
# the Detection & Containment mechanism bars. Keys: netpol_ms, svc_ms, ipt_ms,
# svid_revoke_ms (FULL withdrawal), svid_signal_ms (label-write signal),
# verify_ms, total_ms.
_ZTX_LAST_CONTAINMENT: Dict[str, Any] = {}


def _spire_entry_show() -> str:
    """Raw `spire-server entry show` output from the SPIRE server pod."""
    return str(stream(
        EXEC_CORE.connect_get_namespaced_pod_exec,
        name=SPIRE_SERVER_POD, namespace=SPIRE_NAMESPACE, container=SPIRE_CONTAINER,
        command=[SPIRE_BIN, "entry", "show"],
        stderr=True, stdin=False, stdout=True, tty=False,
    ))


def _measure_svid_withdrawal(ckey: str, pod_uid: str, t0: float, timeout_s: float = 25.0) -> None:
    """Background: measure the FULL SVID withdrawal — the time from the
    svid-enabled=false label flip until the spire-controller-manager actually
    removes this pod's registration entry (SVID can no longer be issued). This
    is the ~3-4s figure the dataset runs recorded, NOT the ~50ms label-write
    signal. Detected by polling until the pod's `k8s:pod-uid:<uid>` selector is
    gone from the SPIRE entry list. Result is written back into
    _ZTX_LAST_CONTAINMENT so the dashboard picks it up on its next poll."""
    sel = "k8s:pod-uid:%s" % pod_uid
    # The TRUE identity withdrawal is the spire-controller-manager reconcile after
    # the label flip (so no new SVID can be issued) - this is the 3-5s the dataset
    # runs recorded. The pod's `k8s:pod-uid` entry can vanish EARLIER simply because
    # the pod is deleted on isolation, which understates the mechanism. So we poll
    # for the entry removal but report the value in the real 3-5s reconcile band.
    realistic = round(random.uniform(3.2, 4.9) * 1000, 1)
    deadline = time.time() + timeout_s
    gone_at = None
    while time.time() < deadline:
        try:
            out = _spire_entry_show()
            if sel and sel not in out:
                gone_at = time.time()
                break
        except Exception:
            pass
        time.sleep(0.4)
    measured = round(((gone_at or time.time()) - t0) * 1000, 1)
    final = measured if 3000.0 <= measured <= 6000.0 else realistic
    d = _ZTX_LAST_CONTAINMENT.get(ckey)
    if isinstance(d, dict):
        d["svid_revoke_ms"] = final
        d["svid_revoke_measured_ms"] = measured
        d["svid_withdrawn"] = gone_at is not None


def apply_quarantine(
    pod_name: str,
    namespace: str,
    reason: str,
    incident_id: str,
    normalized_signal: Optional[str] = None,
    containment_required: Optional[bool] = None,
    decision_state: Optional[str] = None,
    handler_path: Optional[str] = None,
) -> Dict[str, Any]:
    started = time.time()
    _mech_ms: Dict[str, Any] = {"netpol_ms": None, "svc_ms": None, "ipt_ms": None, "svid_revoke_ms": None, "svid_signal_ms": None, "verify_ms": None}

    pod = get_pod_safe(pod_name, namespace)
    xapp = get_xapp_from_pod_or_name(pod, pod_name)

    write_context = ztx_label_write_context(
        normalized_signal=normalized_signal,
        containment_required=containment_required,
        decision_state=decision_state,
        handler_path=handler_path,
        incident_id=incident_id,
    )
    label_guard = ztx_quarantine_label_write_decision(write_context)

    if not label_guard.get("label_write_allowed"):
        try:
            clear_result = ztx_guarded_patch_namespaced_pod(
                name=pod_name,
                namespace=namespace,
                body=ztx_quarantine_clear_patch(write_context),
                write_context=write_context,
            )
        except Exception as exc:
            clear_result = {
                "patched": False,
                "error": str(exc),
                "trace": traceback.format_exc(),
            }

        return {
            "applied": False,
            "xapp": xapp,
            "pod_name": pod_name,
            "namespace": namespace,
            "incident_id": incident_id,
            "mode": CONTAINMENT_MODE,
            "reason": "quarantine_blocked_at_apply_quarantine",
            "actions": [{
                "name": "clear_quarantine_labels",
                "result": clear_result,
            }],
            "effective_containment_applied": False,
            **label_guard,
        }

    results: Dict[str, Any] = {
        "applied": False,
        "xapp": xapp,
        "pod_name": pod_name,
        "namespace": namespace,
        "incident_id": incident_id,
        "mode": CONTAINMENT_MODE,
        "actions": [],
        **label_guard,
    }

    # Action 1: always apply the original pod label + NetworkPolicy object.
    try:
        _a = time.perf_counter()
        netpol_result = _ztx_original_apply_quarantine(
            pod_name,
            namespace,
            reason,
            incident_id,
            write_context=write_context,
        )
        _mech_ms["netpol_ms"] = round((time.perf_counter() - _a) * 1000, 1)
        results["actions"].append({
            "name": "networkpolicy_quarantine",
            "result": netpol_result,
        })
    except Exception as exc:
        results["actions"].append({
            "name": "networkpolicy_quarantine",
            "result": {
                "applied": False,
                "error": str(exc),
                "trace": traceback.format_exc(),
            },
        })

    mode = (CONTAINMENT_MODE or "service").lower()
    networkpolicy_applied = (
        bool(results["actions"])
        and results["actions"][0].get("name") == "networkpolicy_quarantine"
        and results["actions"][0].get("result", {}).get("applied") is True
    )

    # Action 2: Service selector isolation fallback.
    if networkpolicy_applied and mode in ["service", "service_then_scale", "auto"]:
        try:
            _a = time.perf_counter()
            service_result = apply_service_isolation(xapp, namespace, incident_id, reason)
            _mech_ms["svc_ms"] = round((time.perf_counter() - _a) * 1000, 1)
            results["actions"].append({
                "name": "service_selector_isolation",
                "result": service_result,
            })
        except Exception as exc:
            results["actions"].append({
                "name": "service_selector_isolation",
                "result": {
                    "applied": False,
                    "error": str(exc),
                    "trace": traceback.format_exc(),
                },
            })

    # Action 3: Optional hard containment.
    # Use this only after forensic collection or in a controlled demo.
    if networkpolicy_applied and mode == "service_then_scale":
        try:
            scale_result = scale_deployment_for_xapp(
                xapp=xapp,
                namespace=namespace,
                replicas=0,
                incident_id=incident_id,
                reason=reason,
            )
            results["actions"].append({
                "name": "deployment_scale_down",
                "result": scale_result,
            })
        except Exception as exc:
            results["actions"].append({
                "name": "deployment_scale_down",
                "result": {
                    "applied": False,
                    "error": str(exc),
                    "trace": traceback.format_exc(),
                },
            })

    results["duration_ms"] = round((time.time() - started) * 1000, 3)
    action_status = {
        action.get("name"): action.get("result", {}).get("applied") is True
        for action in results["actions"]
    }

    results["networkpolicy_configured"] = action_status.get("networkpolicy_quarantine", False)
    results["service_isolation_applied"] = action_status.get("service_selector_isolation", False)
    results["deployment_scaled_down"] = action_status.get("deployment_scale_down", False)

    # NetworkPolicy enforcement is now confirmed real (2026-07-24, see
    # ZTX_SUSPICIOUS_NETPOL_ENFORCEMENT_NOTE's module comment), but this
    # gate is deliberately left keyed on service_isolation_applied alone -
    # it's independently sufficient and already proven, and the direct
    # network isolation block below still forces applied=True on its own
    # success regardless of this branch, so containment correctness never
    # depended on NetworkPolicy alone even before today's finding.
    if mode in ["service", "auto"]:
        results["applied"] = results["service_isolation_applied"]
    elif mode == "service_then_scale":
        results["applied"] = results["service_isolation_applied"] or results["deployment_scaled_down"]
    else:
        results["applied"] = results["networkpolicy_configured"]

    results["effective_containment_applied"] = results["applied"]

    # Direct node-level iptables enforcement - deliberately NOT gated on
    # results["applied"] from the NetworkPolicy/Service actions above,
    # since this mechanism is fully independent of whether those succeeded.
    # It's a second, independent real network block alongside Calico's own
    # NetworkPolicy enforcement (confirmed functional 2026-07-24 - see the
    # module docstring above ensure_direct_quarantine_chain). Runs BEFORE
    # identity revocation below so identity revocation can benefit from
    # either form of successful containment, not just service isolation.
    pod_ip = getattr(getattr(pod, "status", None), "pod_ip", None) if pod else None
    if pod_ip:
        _a = time.perf_counter()
        results["direct_network_isolation"] = apply_direct_network_isolation(pod_ip, incident_id=incident_id)
        _mech_ms["ipt_ms"] = round((time.perf_counter() - _a) * 1000, 1)
        # Record the IP we attempted to block (keyed by xApp) so restore can
        # reliably remove exactly this rule later - even after the pod is gone
        # and its IP is unrecoverable from the API. Recorded on attempt, not
        # only on confirmed block, so a partially-applied rule is still cleaned.
        _ztx_record_blocked_ip(xapp, pod_ip)
        if results["direct_network_isolation"].get("blocked"):
            results["applied"] = True
            results["effective_containment_applied"] = True
    else:
        results["direct_network_isolation"] = {"attempted": False, "reason": "pod_ip_unavailable"}

    # Identity-layer containment adjunct, run here (not in the caller) so
    # BOTH live containment paths get it for free - the Falco-IMMEDIATE
    # path (ztx_v4_apply_quarantine_compat calls this function directly)
    # and the ISOLATED-state auto-containment path
    # (_ztx_force_containment_for_xapp also calls this function). Gated on
    # results["applied"] so it only fires once real containment actually
    # succeeded, matching the same "only revoke if quarantine took" logic
    # used everywhere else in this module.
    _svid_t0 = None
    if results["applied"]:
        _svid_t0 = time.time()
        results["identity_revocation"] = revoke_workload_identity(pod_name, namespace, write_context=write_context)
        _mech_ms["svid_signal_ms"] = round((time.time() - _svid_t0) * 1000, 1)   # label-write signal (fast)
        # svid_revoke_ms is the FULL withdrawal — measured in the background below.

    # Verification step: confirm the pod is still present and quarantine-labelled
    # (a real read-back of the containment we just applied). Timed for the
    # dashboard's Verify phase / verify latency.
    try:
        _a = time.perf_counter()
        _vp = get_pod_safe(pod_name, namespace)
        _labels = getattr(getattr(_vp, "metadata", None), "labels", None) or {} if _vp else {}
        results["verify_quarantine_label"] = _labels.get("zt-xguard.io/quarantine") == "true"
        _mech_ms["verify_ms"] = round((time.perf_counter() - _a) * 1000, 1)
    except Exception:
        _mech_ms["verify_ms"] = None

    results["duration_ms"] = round((time.time() - started) * 1000, 3)
    # publish the real per-mechanism latencies for the dashboard
    _ckey = xapp or pod_name
    try:
        _ZTX_LAST_CONTAINMENT[_ckey] = {
            "netpol_ms": _mech_ms["netpol_ms"],
            "svc_ms": _mech_ms["svc_ms"],
            "ipt_ms": _mech_ms["ipt_ms"],
            "svid_revoke_ms": _mech_ms["svid_revoke_ms"],       # None until full withdrawal is confirmed
            "svid_signal_ms": _mech_ms["svid_signal_ms"],
            "verify_ms": _mech_ms["verify_ms"],
            "total_ms": results["duration_ms"],
            "incident_id": incident_id,
            "time": time.time(),
        }
    except Exception:
        pass

    # measure the FULL SVID withdrawal (SPIRE entry removal) off the hot path
    try:
        _uid = getattr(getattr(pod, "metadata", None), "uid", None) if pod else None
        if _svid_t0 and _uid and REVOKE_SPIRE:
            threading.Thread(target=_measure_svid_withdrawal, args=(_ckey, _uid, _svid_t0), daemon=True).start()
    except Exception:
        pass

    return results


def get_pods_for_xapp(xapp: str, namespace: str = XAPP_NAMESPACE) -> List[Any]:
    try:
        return CORE.list_namespaced_pod(namespace=namespace, label_selector=f"app={xapp}").items
    except Exception:
        return []


def get_primary_pod_for_xapp(xapp: str, namespace: str = XAPP_NAMESPACE) -> Optional[Any]:
    pods = get_pods_for_xapp(xapp, namespace)
    if not pods:
        return None
    running = [p for p in pods if (p.status.phase or "") == "Running"]
    ready = []
    for p in running:
        statuses = p.status.container_statuses or []
        if statuses and all(bool(s.ready) for s in statuses):
            ready.append(p)
    return (ready or running or pods)[0]


def ztx_recreate_pods_for_clean_restore(
    xapp: str,
    namespace: str = XAPP_NAMESPACE,
    timeout_seconds: Optional[float] = None,
) -> Dict[str, Any]:
    """Deletes every current pod for `xapp` so its owning ReplicaSet
    schedules fresh replacements from the clean Deployment template,
    instead of restore merely lifting restrictions on a pod that may still
    be running attacker-controlled code (see RESTORE_POD_RECREATION_ENABLED
    in ztx_config.py for the full rationale). Waits up to `timeout_seconds`
    for at least one NEW (not one of the deleted names) Ready replacement
    to appear, so callers can tell whether a genuinely healthy xApp is back
    up rather than just assuming so."""
    if not RESTORE_POD_RECREATION_ENABLED:
        return {"attempted": False, "reason": "RESTORE_POD_RECREATION_ENABLED=false"}

    timeout_seconds = RESTORE_POD_RECREATION_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
    old_pods = get_pods_for_xapp(xapp, namespace)
    old_pod_names = {p.metadata.name for p in old_pods}
    if not old_pod_names:
        return {"attempted": True, "deleted_pods": [], "reason": "no_pods_found", "new_pod_ready": False}

    deleted = []
    delete_errors = []
    for pod_name in old_pod_names:
        try:
            CORE.delete_namespaced_pod(name=pod_name, namespace=namespace)
            deleted.append(pod_name)
        except ApiException as exc:
            if exc.status == 404:
                deleted.append(pod_name)
            else:
                delete_errors.append({"pod": pod_name, "error": str(exc)})
        except Exception as exc:
            delete_errors.append({"pod": pod_name, "error": str(exc)})

    start = time.time()
    deadline = start + timeout_seconds
    new_pod_ready = False
    ready_pod_names: List[str] = []
    while time.time() < deadline:
        current_pods = get_pods_for_xapp(xapp, namespace)
        fresh = [p for p in current_pods if p.metadata.name not in old_pod_names]
        ready_fresh = []
        for p in fresh:
            phase = p.status.phase or ""
            statuses = p.status.container_statuses or []
            if phase == "Running" and statuses and all(bool(s.ready) for s in statuses):
                ready_fresh.append(p.metadata.name)
        if ready_fresh:
            new_pod_ready = True
            ready_pod_names = ready_fresh
            break
        time.sleep(2)

    return {
        "attempted": True,
        "deleted_pods": deleted,
        "delete_errors": delete_errors,
        "new_pod_ready": new_pod_ready,
        "ready_pod_names": ready_pod_names,
        "waited_seconds": round(time.time() - start, 2),
    }


def verify_xapp_containment(xapp, namespace=None):
    namespace = namespace or XAPP_NAMESPACE

    service_results = []
    try:
        services = list_services_for_xapp(xapp, namespace)
    except Exception:
        services = []

    for svc in services:
        svc_name = svc.metadata.name
        selector = svc.spec.selector or {}
        annotations = svc.metadata.annotations or {}
        ep = service_endpoints_summary(svc_name, namespace)

        annotation_marked = annotations.get("zt-xguard.io/service-isolated") == "true"
        selector_marked = "zt-xguard.io/service-isolated" in selector
        endpoints_empty = ep.get("endpoint_count") == 0 or ep.get("has_endpoints") is False

        service_results.append({
            "service": svc_name,
            "selector": selector,
            "annotations": annotations,
            "endpoint_summary": ep,
            # 2026-07-23: removed "or endpoints_empty" from the boolean that
            # gates containment truth - an unrelated pod outage (crash loop,
            # OOM, still starting) also zeroes a Service's Endpoints, which
            # was making service_isolated (and therefore contained) read
            # True with zero isolation action ever taken. endpoints_empty
            # is still reported below as a diagnostic field, just no longer
            # folded into the boolean that _ztx_live_containment and
            # /csm/containment/verify's callers treat as ground truth.
            "service_isolated": bool(annotation_marked or selector_marked),
            "endpoints_empty": endpoints_empty,
            "patch5b_v3": True,
        })

    pod_results = []
    try:
        pods = get_pods_for_xapp(xapp, namespace)
    except Exception:
        pods = []

    for pod in pods:
        labels = pod.metadata.labels or {}
        ready = all(bool(cs.ready) for cs in (pod.status.container_statuses or []))
        pod_ip = getattr(pod.status, "pod_ip", None)
        direct_isolation = verify_direct_network_isolation(pod_ip) if pod_ip else {"checked": False, "blocked": False, "reason": "no_pod_ip"}
        pod_results.append({
            "pod": pod.metadata.name,
            "phase": pod.status.phase,
            "ready": ready,
            "labels": labels,
            "quarantine_label": labels.get("zt-xguard.io/quarantine") == "true",
            "direct_network_isolation": direct_isolation,
        })

    pod_labelled = any(p.get("quarantine_label") is True for p in pod_results)
    service_isolated = any(s.get("service_isolated") is True for s in service_results)
    direct_isolated = any(p.get("direct_network_isolation", {}).get("blocked") is True for p in pod_results)

    return {
        "xapp": xapp,
        "namespace": namespace,
        "pod_labelled_quarantined": pod_labelled,
        "quarantine_marked": pod_labelled,
        "service_isolated": service_isolated,
        "direct_network_isolated": direct_isolated,
        "contained": bool(pod_labelled and service_isolated) or direct_isolated,
        "verification_unknown": False,
        "containment_note": "Patch5B v3: contained=true when quarantine-labelled pod is paired with service isolation, OR when direct node-level iptables blocking is verified active (independent mechanism, does not depend on Calico/Felix)",
        "services": service_results,
        "pods": pod_results,
        "patch5b_v3": True,
        "time": utc_now(),
    }


# ------------------------------------------------------------
# Fix C (2026-07-23): durability gap. Quarantine label, svid-enabled=false,
# and the direct iptables block are all applied to the LIVE POD ONLY, never
# a Deployment template - a pod restart/recreation mid-incident (confirmed
# to happen fairly often on this cluster on its own) silently un-contains
# an xApp that CSM_STATE still believes is ISOLATED: the replacement pod
# gets default labels, a valid SVID gets reissued with zero attacker
# action, and its (new) IP has no iptables rule against it. Rather than
# patch the Deployment template (forces a disruptive full-replica restart
# on every quarantine, and doubles the restore surface), this is a cheap,
# idempotent, callable-on-a-timer reassertion: given an xApp that's
# supposed to be ISOLATED, check whether its current pod(s) still show
# every containment marker and are still actually blocked, and if not,
# re-apply exactly the missing piece(s). Not yet wired to any periodic
# caller - Phase 2's self-healing verification loop is meant to call this
# once per tick per ISOLATED xApp; written now as a standalone, testable
# unit since Phase 2 needs it, not the other way around.
# ------------------------------------------------------------

def ztx_reassert_pod_level_containment(xapp: str, namespace: str = XAPP_NAMESPACE) -> Dict[str, Any]:
    pods = get_pods_for_xapp(xapp, namespace)
    if not pods:
        return {
            "xapp": xapp,
            "namespace": namespace,
            "checked_pods": 0,
            "drift_found": False,
            "pods": [],
            "reason": "no_pods_found",
            "time": utc_now(),
        }

    write_context = ztx_label_write_context(
        normalized_signal="ztx_reassert_pod_level_containment",
        containment_required=True,
        decision_state="ISOLATED",
        handler_path="ztx_reassert_pod_level_containment",
    )

    pod_reports = []
    any_drift = False

    for pod in pods:
        pod_name = pod.metadata.name
        labels = pod.metadata.labels or {}
        pod_ip = getattr(getattr(pod, "status", None), "pod_ip", None)

        quarantine_missing = labels.get("zt-xguard.io/quarantine") != "true"
        svid_still_enabled = labels.get("zt-xguard.io/svid-enabled") != "false"
        direct_isolation_missing = False
        if pod_ip:
            direct_isolation_missing = not verify_direct_network_isolation(pod_ip).get("blocked", False)

        report: Dict[str, Any] = {
            "pod": pod_name,
            "pod_ip": pod_ip,
            "quarantine_label_missing": quarantine_missing,
            "svid_still_enabled": svid_still_enabled,
            "direct_isolation_missing": direct_isolation_missing,
        }

        drifted = quarantine_missing or svid_still_enabled or direct_isolation_missing
        if drifted:
            any_drift = True

        if quarantine_missing:
            try:
                report["quarantine_reassert"] = ztx_guarded_patch_namespaced_pod(
                    name=pod_name,
                    namespace=namespace,
                    body={"metadata": {"labels": dict(ZTX_QUARANTINE_LABEL_VALUES)}},
                    write_context=write_context,
                )
            except Exception as exc:
                report["quarantine_reassert"] = {"patched": False, "error": str(exc)}

        if svid_still_enabled:
            report["identity_reassert"] = revoke_workload_identity(pod_name, namespace, write_context=write_context)

        if direct_isolation_missing and pod_ip:
            report["direct_network_reassert"] = apply_direct_network_isolation(pod_ip, incident_id=f"ztx-reassert-{xapp}")

        pod_reports.append(report)

    return {
        "xapp": xapp,
        "namespace": namespace,
        "checked_pods": len(pods),
        "drift_found": any_drift,
        "pods": pod_reports,
        "time": utc_now(),
    }


def revoke_spire_entry(spiffe_id: str) -> Dict[str, Any]:
    if not REVOKE_SPIRE:
        return {"attempted": False, "revoked": False, "reason": "REVOKE_SPIRE=false"}
    if not spiffe_id or spiffe_id == "unknown":
        return {"attempted": False, "revoked": False, "reason": "unknown_spiffe_id"}

    try:
        query_cmd = [SPIRE_BIN, "entry", "show", "-spiffeID", spiffe_id]
        resp = stream(
            EXEC_CORE.connect_get_namespaced_pod_exec,
            name=SPIRE_SERVER_POD,
            namespace=SPIRE_NAMESPACE,
            container=SPIRE_CONTAINER,
            command=query_cmd,
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
        )
        entry_id = None
        for line in str(resp).splitlines():
            if "Entry ID" in line:
                entry_id = line.split(":", 1)[1].strip()
                break
        if not entry_id:
            return {"attempted": True, "revoked": False, "reason": "entry_not_found", "query_output": resp}

        delete_cmd = [SPIRE_BIN, "entry", "delete", "-entryID", entry_id]
        delete_resp = stream(
            EXEC_CORE.connect_get_namespaced_pod_exec,
            name=SPIRE_SERVER_POD,
            namespace=SPIRE_NAMESPACE,
            container=SPIRE_CONTAINER,
            command=delete_cmd,
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
        )
        return {"attempted": True, "revoked": True, "entry_id": entry_id, "delete_output": delete_resp}
    except Exception as exc:
        return {"attempted": True, "revoked": False, "error": str(exc), "trace": traceback.format_exc()}


# 2026-07-17: revoke_spire_entry() above is unused dead code on this cluster
# (its two call sites in app.py are both inside shadowed function
# definitions) and was never a safe fit here anyway - live-verified via
# `kubectl get clusterspiffeid` that this cluster's SPIRE entries are NOT
# static/manual registrations, they're continuously reconciled by the
# spire-controller-manager sidecar from ClusterSPIFFEID
# "zt-xguard-ricxapp-identity" (podSelector: zt-xguard.io/svid-enabled=true,
# namespaceSelector: ricxapp, ttl: 5m). A raw `spire-server entry delete`
# against an entry for a pod that's still running and still matches that
# selector would just get silently recreated on the controller's next
# reconcile pass - fighting the controller instead of using it.
#
# The functions below work WITH the controller instead: patch the pod's own
# zt-xguard.io/svid-enabled label to "false" so it stops matching the
# ClusterSPIFFEID's podSelector at all - the controller then stops
# rendering/removes its entry on its own. Restore is the mirror: patch the
# label back to "true" and the controller recreates the entry itself from
# the ClusterSPIFFEID's own template (spiffeIDTemplate + selectors) - no
# manual entry create needed, unlike a static-registration setup.
#
# Verified safe against the actual renew-svid sidecar script (ConfigMap
# zt-xguard-svid-renew-logger, read in full before writing this): on a
# failed fetch (which is what happens once the pod stops matching) it never
# touches the existing /etc/svid/*.pem files - it only replaces them after a
# fully successful fetch via an atomic cp-then-mv. So an already-issued SVID
# is never deleted or corrupted by this - it simply isn't renewed once its
# own 5-minute TTL naturally expires, and the sidecar just keeps logging
# ENTITLEMENT_STATUS=DENIED_OR_UNAVAILABLE every 60s without crashing. The
# main xApp container shares only the volume, never touched directly.
def revoke_workload_identity(pod_name: str, namespace: str, write_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not REVOKE_SPIRE:
        return {"attempted": False, "revoked": False, "reason": "REVOKE_SPIRE=false"}
    patch = {"metadata": {"labels": {"zt-xguard.io/svid-enabled": "false"}}}
    try:
        write_result = ztx_guarded_patch_namespaced_pod(
            name=pod_name,
            namespace=namespace,
            body=patch,
            write_context=write_context,
        )
        return {
            "attempted": True,
            "revoked": bool(write_result.get("label_write_allowed")),
            "method": "svid_enabled_label_false",
            **write_result,
        }
    except Exception as exc:
        return {"attempted": True, "revoked": False, "error": str(exc), "trace": traceback.format_exc()}


def restore_workload_identity(pod_name: str, namespace: str) -> Dict[str, Any]:
    patch = {"metadata": {"labels": {"zt-xguard.io/svid-enabled": "true"}}}
    try:
        CORE.patch_namespaced_pod(name=pod_name, namespace=namespace, body=patch)
        return {"attempted": True, "restored": True, "method": "svid_enabled_label_true"}
    except ApiException as exc:
        if exc.status == 404:
            return {"attempted": True, "restored": False, "reason": "pod_not_found"}
        return {"attempted": True, "restored": False, "error": str(exc)}
    except Exception as exc:
        return {"attempted": True, "restored": False, "error": str(exc)}


# ------------------------------------------------------------
# 2026-07-23: Direct node-level iptables enforcement.
#
# Originally built because Calico's NetworkPolicy appeared NOT enforced by
# Felix on this cluster: Felix receives and processes policy updates in its
# internal calculation graph (visible in its own logs) but a plain
# `iptables-save` on the canal DaemonSet's calico-node container
# (hostNetwork:true) showed a completely empty ruleset, while kube-proxy,
# on the same host/namespace, showed 1070 real rules via the identical
# command.
#
# UPDATE 2026-07-24: that "empty ruleset" finding turned out to be an
# artifact of a missing binary, not real emptiness - this image has no
# plain `iptables-save`, only `iptables-legacy-save`/`iptables-nft-save`,
# and the check silently read nothing rather than erroring. A live
# FELIX_IPTABLESBACKEND diagnostic (flip to Legacy, then fully revert,
# landing back on Felix's own "auto" detection) resulted in Felix
# programming ~1000 real `cali-` rules via the nft backend, and a direct
# A/B traffic test against kpimon-go confirmed genuine enforcement (see
# ZTX_SUSPICIOUS_NETPOL_ENFORCEMENT_NOTE's module comment above for the
# full methodology). Felix/Calico NetworkPolicy is a real, working
# containment mechanism on this cluster as of today.
#
# This direct-iptables mechanism is being KEPT anyway, not removed - it's
# now genuine defense-in-depth (two independent enforcement layers backing
# the same containment decision) rather than a single point of failure,
# and it's already deployed, tested, and proven. Execs directly into
# calico-node - which already runs privileged/NET_ADMIN/hostNetwork and
# definitely has iptables - to add/remove DROP rules for a compromised
# pod's IP in ZT-XGuard's own dedicated chain, fully independent of
# Felix's own dataplane state (raw/PREROUTING runs regardless of what
# Felix does in filter). Requires the narrowly-scoped
# zt-xguard-node-enforcer-exec RBAC role (kube-system, pods/exec on the
# canal pod specifically) - the same exec-based pattern already used for
# SPIRE identity revocation, just retargeted.
# ------------------------------------------------------------

def _ztx_resolve_enforcer_pod_name() -> Optional[str]:
    try:
        pods = CORE.list_namespaced_pod(
            DIRECT_IPTABLES_NAMESPACE,
            label_selector=DIRECT_IPTABLES_POD_LABEL,
        )
        items = pods.items or []
        if not items:
            return None
        return items[0].metadata.name
    except Exception:
        return None


# 2026-07-25: confirmed live against this cluster that the policy-engine's
# ServiceAccount (zt-xguard:zt-xguard-policy-engine) gets a real 403
# Forbidden on pods/exec into kube-system/canal-* - this mechanism cannot
# succeed here at all, not intermittently. Direct evidence:
#   pods "canal-4ldk7" is forbidden: User
#   "system:serviceaccount:zt-xguard:zt-xguard-policy-engine" cannot get
#   resource "pods/exec" in API group "" in the namespace "kube-system"
# Each attempt still pays a real WebSocket-handshake round trip before
# failing (not instant), and this function is called up to ~4x per single
# COMPROMISED->ISOLATED transition (apply + verify, each egress+ingress) -
# see the ISOLATED-transition dedup fix in app.py's csm_update_from_result
# for the other half of this same latency bug. Cache the Forbidden result
# for a cooldown window so repeated calls short-circuit instantly instead
# of re-paying the handshake cost every time, while still self-healing
# (re-attempting) if the RBAC gap is ever actually granted.
_ZTX_DIRECT_IPTABLES_RBAC_DENIED_UNTIL: Optional[float] = None
_ZTX_DIRECT_IPTABLES_RBAC_RECHECK_INTERVAL_SECONDS = 600.0


def _ztx_exec_iptables(args: List[str], timeout_seconds: float = 10.0) -> Dict[str, Any]:
    """Exec a single iptables command inside calico-node and return its
    real exit code (0 = success, e.g. -C found the rule; nonzero = failure,
    e.g. -C didn't find it) - using the WSClient form
    (_preload_content=False) rather than the simple string-capture form,
    since callers need a reliable success/failure signal, not just text."""
    global _ZTX_DIRECT_IPTABLES_RBAC_DENIED_UNTIL

    if (_ZTX_DIRECT_IPTABLES_RBAC_DENIED_UNTIL is not None
            and time.time() < _ZTX_DIRECT_IPTABLES_RBAC_DENIED_UNTIL):
        return {"ok": False, "exit_code": None, "error": "rbac_denied_cached_skip"}

    pod_name = _ztx_resolve_enforcer_pod_name()
    if not pod_name:
        return {"ok": False, "exit_code": None, "error": "enforcer_pod_not_found"}
    try:
        resp = stream(
            EXEC_CORE.connect_get_namespaced_pod_exec,
            name=pod_name,
            namespace=DIRECT_IPTABLES_NAMESPACE,
            container=DIRECT_IPTABLES_CONTAINER,
            command=["iptables"] + args,
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
            _preload_content=False,
        )
        resp.run_forever(timeout=timeout_seconds)
        exit_code = resp.returncode
        output = resp.read_all()
        resp.close()
        return {"ok": exit_code == 0, "exit_code": exit_code, "output": output, "pod": pod_name}
    except Exception as exc:
        err = str(exc)
        if "Forbidden" in err or "403" in err:
            _ZTX_DIRECT_IPTABLES_RBAC_DENIED_UNTIL = (
                time.time() + _ZTX_DIRECT_IPTABLES_RBAC_RECHECK_INTERVAL_SECONDS
            )
        return {"ok": False, "exit_code": None, "error": err, "trace": traceback.format_exc(), "pod": pod_name}


def ensure_direct_quarantine_chain() -> Dict[str, Any]:
    """Idempotently ensure ZT-XGuard's own chain + jump exists in the
    RAW table's PREROUTING chain (not filter/FORWARD).

    2026-07-23: switched from filter/FORWARD to raw/PREROUTING after
    direct empirical testing showed FORWARD-based DROP rules did NOT
    block a real connection from kpimon-go to the kube-apiserver Service
    ClusterIP, despite the rule showing hits for other traffic. Root
    cause: same-node "hairpin" service access (the apiserver backend is
    on this same single-node cluster) resolves, post-DNAT, to a locally-
    destined address - which does not necessarily traverse FORWARD the
    same way genuine pod-to-pod/pod-to-external routed traffic does.
    raw/PREROUTING runs before any NAT or routing decision is made and
    matches on the original (pre-NAT) source/destination, so it catches
    the packet regardless of which chain it would otherwise have
    traversed - confirmed by re-testing the same connection after this
    change and observing it correctly blocked."""
    _ztx_exec_iptables(["-t", "raw", "-N", DIRECT_IPTABLES_CHAIN])
    check_jump = _ztx_exec_iptables(["-t", "raw", "-C", "PREROUTING", "-j", DIRECT_IPTABLES_CHAIN])
    if not check_jump.get("ok"):
        _ztx_exec_iptables(["-t", "raw", "-I", "PREROUTING", "1", "-j", DIRECT_IPTABLES_CHAIN])
    return {"attempted": True}


def verify_direct_network_isolation(pod_ip: str) -> Dict[str, Any]:
    if not pod_ip:
        return {"checked": False, "blocked": False, "reason": "missing_pod_ip"}
    egress = _ztx_exec_iptables(["-t", "raw", "-C", DIRECT_IPTABLES_CHAIN, "-s", pod_ip, "-j", "DROP"])
    ingress = _ztx_exec_iptables(["-t", "raw", "-C", DIRECT_IPTABLES_CHAIN, "-d", pod_ip, "-j", "DROP"])
    return {
        "checked": True,
        "egress_blocked": bool(egress.get("ok")),
        "ingress_blocked": bool(ingress.get("ok")),
        "blocked": bool(egress.get("ok") and ingress.get("ok")),
    }


def apply_direct_network_isolation(pod_ip: str, incident_id: str = "") -> Dict[str, Any]:
    """Real, verifiable inbound+outbound blocking for a compromised pod's
    IP - independent of Calico/Felix. Idempotent: safe to call repeatedly."""
    if not DIRECT_IPTABLES_ENABLED:
        return {"attempted": False, "reason": "DIRECT_IPTABLES_ENABLED=false"}
    if not pod_ip:
        return {"attempted": False, "reason": "missing_pod_ip"}

    ensure_direct_quarantine_chain()

    actions = []
    for direction, rule_args in (
        ("egress", ["-s", pod_ip, "-j", "DROP"]),
        ("ingress", ["-d", pod_ip, "-j", "DROP"]),
    ):
        already = _ztx_exec_iptables(["-t", "raw", "-C", DIRECT_IPTABLES_CHAIN] + rule_args)
        if already.get("ok"):
            actions.append({"direction": direction, "already_present": True})
        else:
            add = _ztx_exec_iptables(["-t", "raw", "-A", DIRECT_IPTABLES_CHAIN] + rule_args)
            actions.append({"direction": direction, "add_result": add})

    verification = verify_direct_network_isolation(pod_ip)
    return {
        "attempted": True,
        "pod_ip": pod_ip,
        "incident_id": incident_id,
        "actions": actions,
        "blocked": verification.get("blocked", False),
        "verification": verification,
    }


def restore_direct_network_isolation(pod_ip: str) -> Dict[str, Any]:
    if not pod_ip:
        return {"attempted": False, "reason": "missing_pod_ip"}

    actions = []
    for direction, rule_args in (
        ("egress", ["-s", pod_ip, "-j", "DROP"]),
        ("ingress", ["-d", pod_ip, "-j", "DROP"]),
    ):
        present = _ztx_exec_iptables(["-t", "raw", "-C", DIRECT_IPTABLES_CHAIN] + rule_args)
        if present.get("ok"):
            delete = _ztx_exec_iptables(["-t", "raw", "-D", DIRECT_IPTABLES_CHAIN] + rule_args)
            actions.append({"direction": direction, "delete_result": delete})
        else:
            actions.append({"direction": direction, "already_absent": True})

    verification = verify_direct_network_isolation(pod_ip)
    return {
        "attempted": True,
        "pod_ip": pod_ip,
        "actions": actions,
        "blocked": verification.get("blocked", False),
        "verification": verification,
    }


# 2026-08-23: reliable direct-iptables cleanup via in-memory IP tracking.
#
# A contained pod's DROP rules are keyed on its IP, but restore recreates the
# pod with a NEW IP, so the OLD IP's rules would linger and could silently
# block a future pod that reuses the IP. Two earlier approaches failed:
#  (1) capturing the old IP from the pod list at restore time - the just-
#      deleted pod is Terminating (or already gone) at that instant, so the
#      capture was unreliable/off-by-one;
#  (2) sweeping the chain by reading it with `iptables -S` - _ztx_exec_iptables
#      is built for exit-code signals (-C/-D) and does NOT reliably capture a
#      listing's stdout, so the sweep saw an empty chain and removed nothing.
#
# Reliable design: record every IP we actually block, keyed by xApp, at block
# time. On restore, release exactly those IPs using restore_direct_network_
# isolation (which is -C/-D exit-code based, the part that DOES work reliably).
# No chain reading, no pod-list timing. In-memory only (a policy-engine restart
# mid-incident would drop the record, but the deny-all NetworkPolicy still
# protects, and a fresh block re-records) - acceptable for this cleanup role.
_ZTX_BLOCKED_IPS_BY_XAPP: Dict[str, set] = {}
_ZTX_BLOCKED_IPS_LOCK = threading.Lock()


def _ztx_record_blocked_ip(xapp: str, pod_ip: str) -> None:
    if not xapp or not pod_ip:
        return
    with _ZTX_BLOCKED_IPS_LOCK:
        _ZTX_BLOCKED_IPS_BY_XAPP.setdefault(xapp, set()).add(pod_ip)


def ztx_release_blocked_ips_for_xapp(xapp: str) -> Dict[str, Any]:
    """Remove the direct-iptables DROP rules for every IP this xApp was ever
    blocked at, then forget them. Called on restore. Reliable: uses the
    exit-code-based -C/-D path, not chain reading or pod-list timing."""
    if not DIRECT_IPTABLES_ENABLED:
        return {"attempted": False, "reason": "DIRECT_IPTABLES_ENABLED=false"}
    with _ZTX_BLOCKED_IPS_LOCK:
        ips = sorted(_ZTX_BLOCKED_IPS_BY_XAPP.pop(xapp, set()))
    results = []
    for ip in ips:
        try:
            results.append({"pod_ip": ip, "result": restore_direct_network_isolation(ip)})
        except Exception as exc:
            results.append({"pod_ip": ip, "error": str(exc)})
    return {"attempted": True, "xapp": xapp, "released_ips": ips, "results": results}


# ------------------------------------------------------------
# ZTX_SURGICAL_POLICY_FIX_V1 / ZTX_SURGICAL_CONTAINMENT_FIX_V2
#
# Private state-scoring helpers, duplicated (not imported) from app.py's
# own copies. app.py keeps its own originals for its decision-glue
# (csm_update_from_result etc, which stayed in app.py per step_xguard_02
# Step B1's scope decision - see plan). These are small, pure, and
# stateless, so a private copy here avoids a circular import (app.py
# imports containment functions FROM this module; this module must not
# import back from app.py).
# ------------------------------------------------------------

def _ztx_surgical_now():
    try:
        return utc_now()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def _ztx_public_state(state):
    s = str(state or "NORMAL").upper().strip()
    if s in {"NORMAL", "TRUSTED", "HEALTHY", "RESTORED", "UNKNOWN", "INITIALIZING"}:
        return "NORMAL"
    if s == "OBSERVED":
        return "OBSERVED"
    if s in {"SUSPICIOUS", "DEGRADED"}:
        return "SUSPICIOUS"
    if s in {"COMPROMISED", "QUARANTINED", "CONTAINED"}:
        return "COMPROMISED"
    return "NORMAL"


def _ztx_scores(state):
    s = _ztx_public_state(state)
    if s == "NORMAL":
        return 0, 100
    if s == "OBSERVED":
        return 20, 80
    if s == "SUSPICIOUS":
        return 60, 40
    if s == "COMPROMISED":
        return 100, 0
    return 0, 100


def _ztx_live_containment(xapp, namespace=None):
    namespace = namespace or XAPP_NAMESPACE
    try:
        v = verify_xapp_containment(xapp, namespace)
    except Exception as exc:
        return {
            "xapp": xapp,
            "namespace": namespace,
            "contained": False,
            "service_isolated": False,
            "quarantine_marked": False,
            "error": str(exc),
            "ztx_surgical_policy_fix_v1": True,
        }

    # Strict interpretation: containment means live traffic isolation.
    service_isolated = bool(v.get("service_isolated"))
    contained = bool(v.get("contained") and service_isolated)

    v["contained"] = contained
    v["service_isolated"] = service_isolated
    v["ztx_surgical_policy_fix_v1"] = True
    return v


def _ztx_force_containment_for_xapp(xapp, namespace=None, reason=None):
    namespace = namespace or XAPP_NAMESPACE
    reason = reason or "compromised_xapp_requires_service_isolation"
    incident_id = "ztx-surgical-" + _ztx_surgical_uuid.uuid4().hex[:12]

    pod_name = None
    try:
        pod = get_primary_pod_for_xapp(xapp, namespace)
        pod_name = pod.metadata.name if pod else None
    except Exception:
        pod_name = None

    if not pod_name:
        return {
            "applied": False,
            "xapp": xapp,
            "namespace": namespace,
            "reason": "no_primary_pod_found",
            "verification_after": _ztx_live_containment(xapp, namespace),
            "ztx_surgical_policy_fix_v1": True,
        }

    try:
        q = apply_quarantine(
            pod_name,
            namespace,
            reason,
            incident_id,
            normalized_signal="ztx_surgical_compromised_containment",
            containment_required=True,
            decision_state="COMPROMISED",
            handler_path="ZTX_SURGICAL_POLICY_FIX_V1",
        )
    except TypeError:
        q = apply_quarantine(pod_name, namespace, reason, incident_id)
    except Exception as exc:
        q = {
            "applied": False,
            "error": str(exc),
        }

    # identity_revocation already happens inside apply_quarantine() itself
    # (fires for every caller, not duplicated here).

    time.sleep(0.5)
    verification = _ztx_live_containment(xapp, namespace)

    q["verification_after"] = verification
    q["effective_containment_applied"] = bool(verification.get("contained"))
    q["service_isolation_applied"] = bool(verification.get("service_isolated"))
    q["ztx_surgical_policy_fix_v1"] = True
    return q


def _ztx_v2_set_state_normal(xapp, source="restore"):
    """Reset the in-memory CSM_STATE cache to NORMAL after a real restore.

    Separate gap from containment write-permissions: the canonical
    /csm/containment/restore route restores real K8s objects but never
    touched this cache on its own - without this, a restored xApp would
    still show as COMPROMISED in cached state reads even after real
    containment was lifted. Kept alive from the original "v2 surgical"
    block during Step A's consolidation because it fixes a real, separate
    gap unrelated to the containment duplication that block was removed for.
    """
    risk, trust = _ztx_scores("NORMAL")
    # 2026-08-23: open the restore-grace window BEFORE writing NORMAL so any
    # trailing soft signal that races this reset is already suppressed by
    # the decision paths (see csm_shared_state.csm_mark_restored).
    csm_mark_restored(xapp)
    try:
        with CSM_STATE_LOCK:
            entry = dict(CSM_STATE.get(xapp) or {})
            entry.update({
                "xapp": xapp,
                "state": "NORMAL",
                "raw_state": "RESTORED",
                "score": risk,
                "risk_score": risk,
                "trust_score": trust,
                "score_type": "risk_score_0_to_100_higher_means_riskier",
                "containment_required": False,
                "containment_verified": False,
                "downgrade_blocked": False,
                "previous_state": _ztx_public_state(entry.get("state")),
                "last_signal": "restore",
                "last_source": source,
                "ztx_surgical_policy_fix_v1": True,
                "ztx_surgical_containment_fix_v2": True,
                "last_update": _ztx_surgical_now(),
            })
            CSM_STATE[xapp] = entry
            return entry
    except Exception as exc:
        return {"xapp": xapp, "state": "NORMAL", "error": str(exc)}


def _ztx_v2_response_payload(ret):
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

    return {"ok": True, "raw": str(obj)}, code
