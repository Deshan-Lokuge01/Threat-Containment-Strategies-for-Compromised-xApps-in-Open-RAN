"""
ZT-XGuard Policy Engine - shared configuration constants.

Extracted from app.py during step_xguard_02 Step B1 (2026-07-15) so that
event_normalization.py, containment_orchestrator.py, and app.py can all
read the same env-derived constants without app.py needing to be imported
by the other two (which would create a circular import, since app.py
imports functions back out of them).
"""
from __future__ import annotations

import os

try:
    from ztx_state_engine import SIGNAL_ALIASES as ZTX_STATE_ENGINE_SIGNAL_ALIASES
except Exception:
    ZTX_STATE_ENGINE_SIGNAL_ALIASES = {}

ENGINE_VERSION = os.environ.get("ENGINE_VERSION", "1.0.0-integrated")
XAPP_NAMESPACE = os.environ.get("XAPP_NAMESPACE", "ricxapp")
TRUST_DOMAIN = os.environ.get("TRUST_DOMAIN", "example.org")
POLICY_NAMESPACE = os.environ.get("POD_NAMESPACE", os.environ.get("POLICY_NAMESPACE", "zt-xguard"))

XAPP_LIST = [
    x.strip()
    for x in os.environ.get(
        "XAPP_LIST",
        "telemetry-monitor,qos-optimizer,traffic-analyzer,resource-optimizer,security-observer",
    ).split(",")
    if x.strip()
]

TRUSTED_PROVIDER = os.environ.get("TRUSTED_PROVIDER", "sp1")
APPROVED_REGISTRY_PREFIX = os.environ.get("APPROVED_REGISTRY_PREFIX", "localhost:5000/zt-")
STRICT_IMAGE_ID_MATCH = os.environ.get("STRICT_IMAGE_ID_MATCH", "false").lower() == "true"
ACTIVITY_TIMEOUT = float(os.environ.get("ACTIVITY_TIMEOUT", "2.0"))
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "2.0"))
AUTO_QUARANTINE = os.environ.get("AUTO_QUARANTINE", "false").lower() == "true"
REVOKE_SPIRE = os.environ.get("REVOKE_SPIRE", "false").lower() == "true"
# 2026-07-17: T2-sourced signals (resource_anomaly_t2/resource_anomaly_t2_elevated)
# were found repeatedly isolating kpimon-go for what looks like a normal
# Go-GC memory sawtooth (m4's 30s OLS slope swinging through a real GC
# cycle), not a real compromise - the frozen model was very likely never
# calibrated against a run with enough full GC cycles to know this is
# normal. Falco-sourced signals are entirely unaffected by this flag - they
# never carry a resource_anomaly_t2* signal name. Temporary until either the
# model is recalibrated or the memory-slope feature is revisited; default
# stays true (containment enabled) unless explicitly disabled.
T2_AUTO_CONTAIN = os.environ.get("T2_AUTO_CONTAIN", "true").lower() == "true"
# CONTAINMENT_MODE values:
#   networkpolicy       = label pod + deny-all NetworkPolicy only
#   service             = NetworkPolicy + Service selector isolation
#   service_then_scale  = Service isolation + scale deployment to 0
#   auto                = service fallback by default in this prototype
CONTAINMENT_MODE = os.environ.get("CONTAINMENT_MODE", "service").lower()
SPIRE_SERVER_POD = os.environ.get("SPIRE_SERVER_POD", "spire-server-0")
SPIRE_NAMESPACE = os.environ.get("SPIRE_NAMESPACE", "spire-system")
SPIRE_CONTAINER = os.environ.get("SPIRE_CONTAINER", "spire-server")
SPIRE_BIN = os.environ.get("SPIRE_BIN", "/opt/spire/bin/spire-server")
MAX_LOG_LINES = int(os.environ.get("MAX_LOG_LINES", "120"))
PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "").rstrip("/")
PROMETHEUS_TIMEOUT = float(os.environ.get("PROMETHEUS_TIMEOUT", "1.5"))

# 2026-07-24: restore previously just lifted network/label restrictions on
# the SAME pod that was contained - if that pod was genuinely compromised
# (e.g. malicious_tool_execution, SVID material access), un-quarantining it
# hands attacker-controlled code full network access back rather than
# remediating anything. Quarantine labels/annotations are patched onto the
# live pod object only (never the Deployment template - see Fix C), so
# deleting the pod and letting its ReplicaSet reschedule a fresh one from
# the clean template is a genuine remediation step, not cosmetic. Default
# on since this is the correct behavior for a real compromise; can be
# disabled for tests that specifically want to keep the same pod identity.
RESTORE_POD_RECREATION_ENABLED = os.environ.get("RESTORE_POD_RECREATION_ENABLED", "true").lower() == "true"
RESTORE_POD_RECREATION_TIMEOUT_SECONDS = float(os.environ.get("RESTORE_POD_RECREATION_TIMEOUT_SECONDS", "60"))

ZTX_SUSPICIOUS_ONLY_SIGNALS = {
    "package_manager_execution",
    "binary_drop",
    "permission_tamper",
    "k8s_api_contact",
    "unexpected_peer_contact",
    "ric_service_probe",
    "high_cpu",
    "high_memory",
}
# 2026-07-23: "suspicious_tool_execution"/"malicious_tool_execution" were
# removed from this set - they were here as leftover from an earlier,
# lower-severity classification, but ztx_state_engine.py's
# FALCO_CRITICAL_SIGNAL_MAP now classifies "malicious_tool_execution" as
# COMPROMISED/contain=True/isolation_timing=IMMEDIATE (one of the 8 real
# evaluated attacks, ZTX-A6). Leaving it in this set meant
# ztx_quarantine_label_write_decision (containment_orchestrator.py) always
# blocked containment for this signal regardless of what the state engine
# decided, since this set was checked before containment_required - see
# the reordered check there.

ZTX_QUARANTINE_CAPABLE_SIGNALS = {
    "unexpected_shell",
    "sensitive_file_access",
    "serviceaccount_token_access",
    "external_egress",
    "integrity_mismatch",
    "svid_material_access",
    "xapp_profile_or_config_tamper",
}

ZTX_SIGNAL_ALIASES = dict(ZTX_STATE_ENGINE_SIGNAL_ALIASES or {})
ZTX_SIGNAL_ALIASES.update({
    "service_account_token_access": "serviceaccount_token_access",
    "unexpected_external_egress": "external_egress",
    "malicious_or_unexpected_tool": "malicious_tool_execution",
    "unexpected_ric_probe": "ric_service_probe",
    "ric_service_probing": "ric_service_probe",
    "cross_xapp_service_probe": "unexpected_peer_contact",
    "unexpected_cross_xapp": "unexpected_peer_contact",
    "output_profile_drift": "profile_output_drift",
})

ZTX_QUARANTINE_LABEL_VALUES = {
    "zt-xguard.io/quarantine": "true",
    "security-status": "quarantined",
    "zt-xguard.io/decision": "quarantined",
}

# Fallback-containment annotation keys (Service/Deployment level).
ORIGINAL_SELECTOR_ANNOTATION = "zt-xguard.io/original-service-selector"
SERVICE_ISOLATED_ANNOTATION = "zt-xguard.io/service-isolated"
SERVICE_ISOLATED_INCIDENT_ANNOTATION = "zt-xguard.io/service-isolated-incident"
ORIGINAL_REPLICAS_ANNOTATION = "zt-xguard.io/original-replicas"

# 2026-07-23: direct node-level iptables enforcement, added because Calico's
# NetworkPolicy is confirmed NOT enforced by Felix on this cluster (Felix
# receives policy updates in its calculation graph but writes zero iptables
# rules - verified directly via iptables-save showing an empty ruleset
# despite kube-proxy, on the same hostNetwork node, showing 1070 real
# rules). Rather than depend on that broken translation layer, this execs
# directly into calico-node (which already runs privileged/NET_ADMIN/
# hostNetwork and definitely has iptables) to add/remove DROP rules for a
# compromised pod's IP in a dedicated chain, independent of whatever
# Felix's own dataplane state is.
DIRECT_IPTABLES_ENABLED = os.environ.get("DIRECT_IPTABLES_ENABLED", "true").lower() == "true"
DIRECT_IPTABLES_NAMESPACE = os.environ.get("DIRECT_IPTABLES_NAMESPACE", "kube-system")
DIRECT_IPTABLES_POD_LABEL = os.environ.get("DIRECT_IPTABLES_POD_LABEL", "k8s-app=canal")
DIRECT_IPTABLES_CONTAINER = os.environ.get("DIRECT_IPTABLES_CONTAINER", "calico-node")
DIRECT_IPTABLES_CHAIN = os.environ.get("DIRECT_IPTABLES_CHAIN", "ZTX-DIRECT-QUARANTINE")
