"""
ZT-XGuard Policy Engine - Falco rule IP reconciler.

2026-07-24: two of the custom Falco rules' "known internal destination"
macros (ztx_dest_submgr_pod_ip, ztx_dest_dbaas_pod_ip, in
falco/ztx-xapp-rules.yaml) match by backing POD IP rather than a stable
Service ClusterIP, because both submgr and dbaas/SDL are headless Services
(ClusterIP: None) - there is no stable IP to match by name. That pod IP
changes every time the pod restarts, and when it drifts out of sync with
the deployed Falco rules, kpimon-go's genuine SDL/RMR traffic to that
service gets misclassified as "external egress" (CRITICAL) and triggers a
real, incorrect auto-quarantine of a perfectly healthy xApp - observed for
real on 2026-07-24 after a cluster-wide pod churn event.

This module closes that gap with a small background reconciliation loop
(same daemon-thread pattern as ztx_isolation_manager.start_dwell_checker):
periodically read the two backing pods' current IPs from the K8s API,
compare to what's deployed in the Falco rules ConfigMap, and patch +
trigger a Falco reload if they've drifted. Requires the narrowly-scoped
zt-xguard-ricplt-observer (read pods in ricplt) and
zt-xguard-falco-rules-sync (get/patch this one ConfigMap + this one
DaemonSet, by name) RBAC roles.
"""
from __future__ import annotations

import re
import threading
import time
import traceback
from typing import Any, Dict, Optional

from kubernetes.client import ApiException

from k8s_clients import CORE, APPS

RICPLT_NAMESPACE = "ricplt"
FALCO_NAMESPACE = "falco"
FALCO_CONFIGMAP_NAME = "zt-xguard-falco-custom-rules"
FALCO_CONFIGMAP_KEY = "falco_rules.local.yaml"
FALCO_DAEMONSET_NAME = "falco"

RECONCILE_INTERVAL_SECONDS = 120

# Maps the Falco macro name (must match falco/ztx-xapp-rules.yaml exactly)
# to the K8s pod-label selector that identifies its single backing pod.
_HEADLESS_SERVICE_TARGETS = {
    "ztx_dest_submgr_pod_ip": "app=ricplt-submgr",
    "ztx_dest_dbaas_pod_ip": "app=ricplt-dbaas",
}

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _get_backing_pod_ip(label_selector: str) -> Optional[str]:
    try:
        pods = CORE.list_namespaced_pod(RICPLT_NAMESPACE, label_selector=label_selector).items
    except Exception:
        return None
    running = [p for p in pods if (p.status.phase or "") == "Running" and p.status.pod_ip]
    if not running:
        return None
    return running[0].status.pod_ip


def _read_falco_rules_text() -> Optional[str]:
    try:
        cm = CORE.read_namespaced_config_map(FALCO_CONFIGMAP_NAME, FALCO_NAMESPACE)
        return (cm.data or {}).get(FALCO_CONFIGMAP_KEY)
    except Exception:
        return None


def _deployed_ip_for_macro(rules_text: str, macro_name: str) -> Optional[str]:
    match = re.search(
        rf"macro:\s*{re.escape(macro_name)}\s*\n\s*condition:\s*fd\.sip=((?:\d{{1,3}}\.){{3}}\d{{1,3}})",
        rules_text,
    )
    return match.group(1) if match else None


def reconcile_falco_headless_service_ips() -> Dict[str, Any]:
    """One reconciliation pass. Returns a report dict; never raises -
    callers (including the background loop below) can treat any exception
    as a no-op failure for this tick, since the next tick will simply try
    again."""
    report: Dict[str, Any] = {"checked": [], "drifted": [], "patched": False}
    try:
        rules_text = _read_falco_rules_text()
        if not rules_text:
            report["error"] = "falco_configmap_unreadable"
            return report

        new_rules_text = rules_text
        for macro_name, selector in _HEADLESS_SERVICE_TARGETS.items():
            current_ip = _get_backing_pod_ip(selector)
            deployed_ip = _deployed_ip_for_macro(rules_text, macro_name)
            entry = {"macro": macro_name, "selector": selector, "current_ip": current_ip, "deployed_ip": deployed_ip}
            report["checked"].append(entry)

            if not current_ip or not _IP_RE.match(current_ip):
                entry["skipped_reason"] = "backing_pod_ip_unavailable"
                continue
            if deployed_ip is None:
                entry["skipped_reason"] = "macro_not_found_in_deployed_rules"
                continue
            if current_ip == deployed_ip:
                continue

            report["drifted"].append(macro_name)
            new_rules_text = re.sub(
                rf"(macro:\s*{re.escape(macro_name)}\s*\n\s*condition:\s*fd\.sip=)(?:\d{{1,3}}\.){{3}}\d{{1,3}}",
                rf"\g<1>{current_ip}",
                new_rules_text,
            )

        if not report["drifted"]:
            return report

        CORE.patch_namespaced_config_map(
            FALCO_CONFIGMAP_NAME,
            FALCO_NAMESPACE,
            {"data": {FALCO_CONFIGMAP_KEY: new_rules_text}},
        )
        report["patched"] = True

        # Trigger a rollout by bumping a restart annotation, the same
        # mechanism `kubectl rollout restart` itself uses - avoids needing
        # any extra RBAC verb beyond the "patch daemonsets" already granted.
        APPS.patch_namespaced_daemon_set(
            FALCO_DAEMONSET_NAME,
            FALCO_NAMESPACE,
            {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "zt-xguard.io/falco-rule-sync-restartedAt": str(time.time())
                            }
                        }
                    }
                }
            },
        )
        report["falco_restart_triggered"] = True
    except ApiException as exc:
        report["error"] = str(exc)
        report["trace"] = traceback.format_exc()
    except Exception as exc:
        report["error"] = str(exc)
        report["trace"] = traceback.format_exc()
    return report


def start_falco_ip_reconciler_loop(interval_seconds: float = RECONCILE_INTERVAL_SECONDS) -> threading.Thread:
    """Start the background daemon thread. Safe to call once at process
    startup, same pattern as ztx_isolation_manager.start_dwell_checker."""

    def _loop() -> None:
        while True:
            time.sleep(interval_seconds)
            try:
                reconcile_falco_headless_service_ips()
            except Exception:
                pass

    t = threading.Thread(target=_loop, name="ztx-falco-ip-reconciler", daemon=True)
    t.start()
    return t
