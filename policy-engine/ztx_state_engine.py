#!/usr/bin/env python3
"""ZT-XGuard V5 state-machine decision engine.

Pure decision logic: no Flask, no Kubernetes API calls.
The Flask policy engine collects evidence, then calls evaluate_state().
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

STATE_ENGINE_VERSION = "6.3-t2-4state-direct-mapping"

# --- Primary Zero-Trust posture states (validated 4-state model) ---
NORMAL = "NORMAL"
SUSPICIOUS = "SUSPICIOUS"
COMPROMISED = "COMPROMISED"
ISOLATED = "ISOLATED"

# --- Internal / non-primary sentinel states ---
# Never returned as detection_state/decision_state by evaluate_state().
# UNKNOWN means "no prior evaluation exists for this xApp yet" - collapsing
# it into NORMAL would let a zero-trust engine claim health it never
# actually checked. IGNORED means "event explicitly out of scope for
# controlled xApps" - collapsing it into NORMAL would let an out-of-scope
# event silently overwrite a real SUSPICIOUS/COMPROMISED posture with a
# false claim of health. Both are kept distinct on purpose.
UNKNOWN = "UNKNOWN"
IGNORED = "IGNORED"

# Legacy aliases, not used inside this module. RESTORED collapses into
# NORMAL (the existing app.py manual-restore endpoint already does this).
# TRUSTED/OBSERVED collapse into NORMAL; QUARANTINED aliases to ISOLATED.
# Kept only as a defensive net for external callers still importing the
# old names.
TRUSTED = NORMAL
OBSERVED = NORMAL
QUARANTINED = ISOLATED
RESTORED = NORMAL

CRITICAL_SIGNALS = {
    "unexpected_shell": "R-CRIT-01",
    "sensitive_file_access": "R-CRIT-02",
    "external_egress": "R-CRIT-04",
    "integrity_mismatch": "R-CRIT-05",
    "image_digest_mismatch": "R-CRIT-06",
    "profile_hash_mismatch": "R-CRIT-07",
    "verified_label_missing": "R-CRIT-08",
}

SIGNAL_ALIASES = {
    "service_account_token_access": "serviceaccount_token_access",
    "suspicious_tool_execution": "malicious_tool_execution",
    "cross_xapp_service_probe": "unexpected_peer_contact",
    "unexpected_cross_xapp": "unexpected_peer_contact",
}

FALCO_CRITICAL_SIGNAL_MAP = {
    "svid_material_access": {
        "rule_id": "ZTX-A11",
        "layer": "L2_identity_svid",
        "reason": "xApp accessed/tampered with SVID/SPIRE identity material",
        "action": "SERVICE_ISOLATION_AND_IDENTITY_CONTAINMENT",
    },
    "xapp_profile_or_config_tamper": {
        "rule_id": "ZTX-A12",
        "layer": "L5_integrity",
        "reason": "xApp tampered with verified profile/config path",
        "action": "SERVICE_ISOLATION_AND_IDENTITY_CONTAINMENT",
    },
    # Lateral-movement / privilege-escalation signals. Explicit decision: a
    # single occurrence goes straight to COMPROMISED and isolates immediately
    # - just two stages (NORMAL -> COMPROMISED=ISOLATED), no waiting, no
    # requiring a second corroborating signal first. These specific
    # techniques (reading a token outside normal client-library use, a known
    # attack tool executing, an attempted container escape) are treated the
    # same way as the other directly-observed critical signals above.
    "serviceaccount_token_access": {
        "rule_id": "ZTX-LM-01",
        "layer": "L2_identity_svid",
        "reason": "serviceaccount_token_accessed_outside_normal_client_library_use",
        "action": "SERVICE_ISOLATION_AND_LATERAL_MOVEMENT_CONTAINMENT",
    },
    "malicious_tool_execution": {
        "rule_id": "ZTX-LM-02",
        "layer": "L1_runtime_exploitation",
        "reason": "known_attack_tool_or_technique_executed_inside_controlled_xapp",
        "action": "SERVICE_ISOLATION_AND_LATERAL_MOVEMENT_CONTAINMENT",
    },
    "privileged_container_escape_attempt": {
        "rule_id": "ZTX-LM-03",
        "layer": "L1_runtime_exploitation",
        "reason": "attempted_container_escape_indicator_docker_socket_or_host_mount_or_capability_abuse",
        "action": "SERVICE_ISOLATION_AND_LATERAL_MOVEMENT_CONTAINMENT",
    },
}

FALCO_SUSPICIOUS_SIGNAL_MAP = {
    "package_manager_execution": {
        "rule_id": "ZTX-A13",
        "layer": "L1_runtime_exploitation",
        "reason": "package manager executed inside controlled xApp",
        "penalty": 35,
    },
    "binary_drop": {
        "rule_id": "ZTX-A14",
        "layer": "L1_runtime_exploitation",
        "reason": "executable-looking artifact written to writable path",
        "penalty": 35,
    },
    "permission_tamper": {
        "rule_id": "ZTX-A15",
        "layer": "L5_integrity",
        "reason": "chmod/chown/setcap executed inside controlled xApp",
        "penalty": 30,
    },
    "k8s_api_contact": {
        "rule_id": "ZTX-A16",
        "layer": "L4_communication",
        "reason": "controlled xApp contacted Kubernetes API",
        "penalty": 30,
    },
}

IDENTITY_CRITICAL_SIGNALS = {
    "spiffe_mismatch": "R-ID-01",
    "identity_mismatch": "R-ID-02",
    "serviceaccount_mismatch": "R-ID-03",
    "svid_missing": "R-ID-04",
    "svid_invalid": "R-ID-05",
    "svid_expired": "R-ID-06",
    "spire_registration_missing": "R-ID-07",
}

BENIGN_SIGNALS = {"clean_baseline", "normal_heartbeat", "normal_qos_activity"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "ok"}
    return bool(value)


def _as_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default


def _get_nested(obj: Dict[str, Any], path: List[str], default: Any = None) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return default if cur is None else cur


def _as_dict(value: Any) -> Dict[str, Any]:
    """Return value only if it is a dictionary.

    xApp /metrics may return Prometheus text, not JSON. The state engine must
    never call .get() on strings/lists/None from endpoint evidence.
    """
    return value if isinstance(value, dict) else {}


def _resource_envelope(profile: Dict[str, Any]) -> Dict[str, Any]:
    return _as_dict(profile.get("resource_envelope"))


def _profile_threshold(profile: Dict[str, Any], keys: Tuple[str, ...]) -> Tuple[Optional[float], Optional[str]]:
    envelope = _resource_envelope(profile)
    for scope_name, scope in (("profile", profile), ("profile.resource_envelope", envelope)):
        for key in keys:
            value = _as_float(scope.get(key))
            if value is not None:
                return value, f"{scope_name}.{key}"
    return None, None


def _cpu_class_name(profile: Dict[str, Any]) -> str:
    envelope = _resource_envelope(profile)
    candidates = [
        profile.get("expected_cpu_class"),
        envelope.get("expected_cpu_class"),
        profile.get("workload_intensity"),
        envelope.get("workload_intensity"),
    ]
    for value in candidates:
        if not isinstance(value, str):
            continue
        normalized = value.strip().lower()
        if normalized in {"low", "medium", "high"}:
            return normalized
        if normalized in {"moderate", "normal"}:
            return "medium"
        if normalized in {"heavy"}:
            return "high"
    return "medium"


def _cpu_threshold(profile: Dict[str, Any]) -> Tuple[float, str]:
    threshold, source = _profile_threshold(profile, ("max_cpu_percent", "cpu_p99_percent", "cpu_p95_percent"))
    if threshold is not None and source:
        return threshold, source
    cpu_class = _cpu_class_name(profile)
    defaults = {"low": 25.0, "medium": 60.0, "high": 85.0}
    return defaults.get(cpu_class, 60.0), f"default_cpu_class:{cpu_class}"


def _memory_threshold(profile: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    return _profile_threshold(profile, ("max_memory_bytes", "memory_p99_bytes", "memory_p95_bytes"))


def _profile_allows_high_resource_usage(profile: Dict[str, Any]) -> bool:
    envelope = _resource_envelope(profile)
    if _as_bool(profile.get("expected_high_workload"), False) or _as_bool(envelope.get("expected_high_workload"), False):
        return True
    if _cpu_class_name(profile) == "high":
        return True
    workload = str(profile.get("workload_intensity") or envelope.get("workload_intensity") or "").strip().lower()
    return workload in {"high", "heavy"}


def _normalize_signal(signal: str) -> str:
    normalized = str(signal or "unknown").strip().lower()
    return SIGNAL_ALIASES.get(normalized, normalized)


@dataclass
class StateDecision:
    xapp: str
    signal: str
    previous_state: str
    detection_state: str
    decision_state: str
    containment_required: bool
    containment_action: str
    action: str
    score: int
    confidence: float
    severity: str
    rule_ids: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    layers: Dict[str, List[str]] = field(default_factory=dict)
    evidence_sources: Dict[str, bool] = field(default_factory=dict)
    transition: Dict[str, str] = field(default_factory=dict)
    snapshot: Dict[str, Any] = field(default_factory=dict)
    isolation_timing: str = "N/A"
    time: str = field(default_factory=utc_now)
    engine_version: str = STATE_ENGINE_VERSION

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)

        # Builder score is a TRUST score internally:
        #   100 = very trusted
        #   0   = very risky / compromised
        #
        # For evaluation, dashboards, and thesis presentation we expose both:
        #   trust_score: higher means more trusted
        #   risk_score:  higher means more dangerous
        trust_score = max(0, min(100, int(self.score)))
        risk_score = max(0, min(100, 100 - trust_score))

        data["trust_score"] = trust_score
        data["risk_score"] = risk_score

        # Backward-compatible state alias.
        data["state"] = self.decision_state

        # From V5.3 onward, public score means RISK score.
        data["score"] = risk_score
        data["score_type"] = "risk_score_0_to_100_higher_means_riskier"

        return data


class DecisionBuilder:
    def __init__(self, xapp: str, signal: str, previous_state: str, snapshot: Dict[str, Any]):
        self.xapp = xapp
        self.signal = signal
        self.previous_state = (previous_state or UNKNOWN).upper()
        self.snapshot = snapshot or {}
        self.score = 100
        self.confidence = 0.50
        self.severity = "INFO"
        self.state = NORMAL
        self.containment_required = False
        self.containment_action = "NONE"
        self.isolation_timing = "N/A"
        self.rule_ids: List[str] = []
        self.reasons: List[str] = []
        self.layers: Dict[str, List[str]] = {
            "L1_runtime_exploitation": [],
            "L2_identity_svid": [],
            "L3_resource_behavior": [],
            "L4_communication": [],
            "L5_integrity": [],
            "L6_correlation": [],
        }

    def add(self, layer: str, rule_id: str, reason: str, penalty: int = 0) -> None:
        if rule_id and rule_id not in self.rule_ids:
            self.rule_ids.append(rule_id)
        self.reasons.append(reason)
        self.layers.setdefault(layer, []).append(reason)
        self.score = max(0, self.score - int(penalty or 0))

    def set_state(self, state: str, severity: str, confidence: float, contain: bool = False, action: str = "NONE", isolation_timing: str = "N/A") -> None:
        self.state = state
        self.severity = severity
        self.confidence = confidence
        self.containment_required = contain
        self.containment_action = action
        self.isolation_timing = isolation_timing

    def result(self, evidence_sources: Dict[str, bool]) -> StateDecision:
        # NORMAL now covers what used to be two distinct states (TRUSTED,
        # severity=INFO, and OBSERVED, severity=LOW) - severity is what
        # still distinguishes them, so key the action off severity rather
        # than the now-collapsed state label, to keep this identical to
        # the pre-4-state behavior.
        action = "FORENSIC_QUARANTINE" if self.containment_required else (
            "EVIDENCE_ONLY" if self.state == SUSPICIOUS else "INCREASE_MONITORING" if self.severity == "LOW" else "MONITOR"
        )
        return StateDecision(
            xapp=self.xapp,
            signal=self.signal,
            previous_state=self.previous_state,
            detection_state=self.state,
            decision_state=self.state,
            containment_required=self.containment_required,
            containment_action=self.containment_action,
            action=action,
            score=self.score,
            confidence=round(float(self.confidence), 3),
            severity=self.severity,
            rule_ids=self.rule_ids,
            reasons=self.reasons,
            layers=self.layers,
            evidence_sources=evidence_sources,
            transition={"from": self.previous_state, "to": self.state},
            snapshot=self.snapshot,
            isolation_timing=self.isolation_timing,
        )


def evaluate_state(
    *,
    xapp: str,
    signal: str,
    profile: Optional[Dict[str, Any]] = None,
    evidence: Optional[Dict[str, Any]] = None,
    snapshot: Optional[Dict[str, Any]] = None,
    previous_state: str = UNKNOWN,
) -> Dict[str, Any]:
    """Return an explainable V5 state-machine decision.

    This function intentionally separates detection_state from containment_action.
    CPU/memory/resource anomalies alone do not quarantine. Critical deterministic
    compromise evidence and identity/integrity violations can quarantine.
    """
    xapp = str(xapp or "unknown")
    signal = _normalize_signal(signal)
    profile = _as_dict(profile)
    evidence = _as_dict(evidence)
    snapshot = _as_dict(snapshot)

    activity = _as_dict(snapshot.get("activity") or evidence.get("activity"))
    metrics = _as_dict(snapshot.get("metrics") or evidence.get("metrics"))
    identity = _as_dict(snapshot.get("identity") or evidence.get("identity"))
    integrity = _as_dict(snapshot.get("integrity") or evidence.get("integrity"))

    cpu_usage_percent = _as_float(metrics.get("cpu_usage_percent"))
    cpu_cores_2m = _as_float(metrics.get("cpu_cores_2m"))
    memory_usage_bytes = _as_float(metrics.get("memory_usage_bytes"))
    memory_working_set_bytes = _as_float(metrics.get("memory_working_set_bytes"))
    effective_memory_bytes = memory_working_set_bytes if memory_working_set_bytes is not None else memory_usage_bytes

    evidence_sources = {
        "falco": bool(evidence.get("raw_event") or evidence.get("falco_event") or evidence.get("source") == "falco"),
        "prometheus": bool(evidence.get("prometheus") or metrics.get("prometheus")),
        "cadvisor": bool(evidence.get("cadvisor") or metrics.get("cadvisor") or metrics.get("resources")),
        "svid": bool(identity or evidence.get("svid") or signal.startswith("svid") or "spiffe" in signal),
        "kubernetes": bool(evidence.get("pod") or evidence.get("kubernetes") or snapshot.get("kubernetes")),
        "xapp_activity": bool(activity),
        "integrity": bool(integrity or "integrity" in signal or "hash" in signal),
    }

    b = DecisionBuilder(
        xapp=xapp,
        signal=signal,
        previous_state=previous_state,
        snapshot={
            "activity_ok": snapshot.get("ok"),
            "heartbeat_ok": activity.get("heartbeat_ok"),
            "heartbeat_age_sec": activity.get("heartbeat_age_sec"),
            "work_units_processed": activity.get("work_units_processed"),
            "cpu_usage_percent": cpu_usage_percent,
            "cpu_cores_2m": cpu_cores_2m,
            "memory_usage_bytes": memory_usage_bytes,
            "memory_working_set_bytes": memory_working_set_bytes,
            "svid_certificate_present": identity.get("svid_certificate_present"),
            "svid_key_present": identity.get("svid_key_present"),
            "expected_spiffe_id": identity.get("expected_spiffe_id") or evidence.get("expected_spiffe_id"),
            "actual_spiffe_id": identity.get("actual_spiffe_id") or evidence.get("actual_spiffe_id"),
        },
    )

    resource_signal = signal in {"high_cpu", "cpu_spike", "high_memory", "memory_spike"}
    explicit_non_resource_signals = {"profile_output_drift", "output_profile_drift", "ric_service_probe", "unexpected_ric_probe", "unexpected_peer_contact"}
    cpu_threshold, cpu_threshold_source = _cpu_threshold(profile)
    memory_threshold, memory_threshold_source = _memory_threshold(profile)
    cpu_threshold_exceeded = cpu_usage_percent is not None and cpu_usage_percent > cpu_threshold
    memory_threshold_exceeded = (
        effective_memory_bytes is not None and
        memory_threshold is not None and
        effective_memory_bytes > memory_threshold
    )
    derived_resource_signal = cpu_threshold_exceeded or memory_threshold_exceeded

    # Explicit out-of-scope / ignored signals.
    if signal in {"ignored", "out_of_scope", "event_not_mapped_to_controlled_xapp"}:
        b.add("L6_correlation", "R-SCOPE-01", "event outside controlled xApp scope", 0)
        b.set_state(IGNORED, "INFO", 0.99, contain=False)
        return b.result(evidence_sources).to_dict()

    # Benign controls.
    if signal in BENIGN_SIGNALS and not derived_resource_signal:
        b.add("L3_resource_behavior", "R-BENIGN-01", f"{signal}_profile_consistent", 0)
        b.set_state(NORMAL, "INFO", 0.90, contain=False)
        return b.result(evidence_sources).to_dict()

    # Critical deterministic runtime signals.
    if signal in CRITICAL_SIGNALS:
        rule_id = CRITICAL_SIGNALS[signal]
        if signal == "external_egress" and _as_bool(profile.get("expected_external_egress"), False):
            b.add("L4_communication", "R-COMM-ALLOW-01", "external egress allowed by xApp profile", 0)
            b.set_state(NORMAL, "LOW", 0.65, contain=False)
        else:
            layer = "L4_communication" if signal == "external_egress" else "L1_runtime_exploitation"
            if "integrity" in signal or "hash" in signal or "digest" in signal or "verified" in signal:
                layer = "L5_integrity"
            b.add(layer, rule_id, f"{signal}_is_high_confidence_compromise_indicator", 100)
            b.set_state(COMPROMISED, "CRITICAL", 0.98, contain=True, action="SERVICE_ISOLATION_AND_IDENTITY_CONTAINMENT", isolation_timing="IMMEDIATE")
        return b.result(evidence_sources).to_dict()

    # Identity/SVID violations.
    if signal in IDENTITY_CRITICAL_SIGNALS:
        rule_id = IDENTITY_CRITICAL_SIGNALS[signal]
        running = _as_bool(evidence.get("running"), True)
        if running:
            b.add("L2_identity_svid", rule_id, f"running_xapp_has_identity_violation:{signal}", 80)
            b.set_state(COMPROMISED, "CRITICAL", 0.94, contain=True, action="SERVICE_ISOLATION_AND_SVID_REVOCATION", isolation_timing="IMMEDIATE")
        else:
            b.add("L2_identity_svid", rule_id, f"identity_violation_observed_before_runtime:{signal}", 40)
            b.set_state(SUSPICIOUS, "HIGH", 0.80, contain=False)
        return b.result(evidence_sources).to_dict()

    if signal in FALCO_CRITICAL_SIGNAL_MAP:
        signal_meta = FALCO_CRITICAL_SIGNAL_MAP[signal]
        b.add(signal_meta["layer"], signal_meta["rule_id"], signal_meta["reason"], 100)
        b.set_state(COMPROMISED, "CRITICAL", 0.97, contain=True, action=signal_meta["action"], isolation_timing="IMMEDIATE")
        return b.result(evidence_sources).to_dict()

    if signal in FALCO_SUSPICIOUS_SIGNAL_MAP:
        signal_meta = FALCO_SUSPICIOUS_SIGNAL_MAP[signal]
        b.add(signal_meta["layer"], signal_meta["rule_id"], signal_meta["reason"], signal_meta["penalty"])
        b.set_state(SUSPICIOUS, "MEDIUM", 0.79, contain=False)

    # step_xguard_02 Step C (2026-07-15): the frozen T2/MEWMA resource
    # detector (src/ztx_model/streaming.py, StreamingScorer) for kpimon-go.
    # Deliberately a distinct signal name, checked before the generic
    # resource_signal branch below, so its own SUSPICIOUS verdict - already
    # confirmed on its own terms via 6-of-8 upper-control-limit states plus
    # a CPU rate-of-exceedance gate (60s window, 15% rate) before the
    # collector ever emits this signal - is trusted directly, rather than
    # being re-derived from the cruder static cpu_usage_percent-vs-profile
    # threshold check the generic branch uses. See session log Section 19
    # for why: feeding this through signal="high_cpu" instead would let the
    # simpler threshold logic silently override the statistical model's own
    # judgment, defeating the point of wiring in a real detector.
    # 2026-07-16: WL-only crossing (score above the warning limit but not yet
    # fully confirmed - i.e. not all of UCL exceedance + 6-of-8 + cpu_gate
    # are true together). The frozen model itself never reports this tier on
    # its own (its own public_state is binary, NORMAL/SUSPICIOUS, and its
    # SUSPICIOUS already means fully confirmed) - the collector derives this
    # signal separately by comparing v3_pressure_score to the warning_limit
    # constant directly, specifically so the 4-state design below has a real
    # SUSPICIOUS tier distinct from COMPROMISED, per the corrected mapping
    # agreed 2026-07-16 (see session log Section 19/20).
    elif signal == "resource_anomaly_t2_elevated":
        t2_score = _as_float(evidence.get("t2_pressure_score"))
        reason = "t2_mewma_resource_pressure_above_warning_limit_not_yet_confirmed"
        if t2_score is not None:
            reason += f":pressure_score={t2_score:.3f}"
        b.add("L3_resource_behavior", "R-T2-02", reason, 20)
        b.set_state(SUSPICIOUS, "LOW", 0.68, contain=False)

    # Fully confirmed: UCL exceedance + 6-of-8 + cpu_gate all true together.
    # 2026-07-16: previously mapped to SUSPICIOUS pending a second occurrence
    # via ztx_repeat_tracker.py's generic repeat-count mechanism (borrowed
    # from the Falco WARNING-tier signals). Corrected per direct agreement
    # with the operator: this condition IS the agreed COMPROMISED trigger -
    # the collector already only emits it once 6-of-8 confirmed states plus
    # the CPU rate-of-exceedance gate all hold, so by the time this signal
    # ever arrives it already represents roughly a minute of corroborated
    # statistical evidence, not a single noisy blip - no second occurrence
    # should be required. isolation_timing="DWELL_30S" (not "IMMEDIATE"),
    # matching the agreed design: COMPROMISED starts a 30s countdown to
    # auto-isolation unless an operator intervenes first via the dashboard -
    # this is what actually implements that 30s dwell requirement, once a
    # containment orchestrator consumes it (still deferred, per standing
    # instruction - this only sets the flag, it does not act on it yet).
    elif signal == "resource_anomaly_t2":
        t2_score = _as_float(evidence.get("t2_pressure_score"))
        reason = "t2_mewma_resource_pressure_confirmed_6of8_with_cpu_rate_gate"
        if t2_score is not None:
            reason += f":pressure_score={t2_score:.3f}"
        b.add("L3_resource_behavior", "R-T2-01", reason, 45)
        b.set_state(COMPROMISED, "HIGH", 0.90, contain=True,
                    action="SERVICE_ISOLATION_AFTER_T2_CONFIRMATION", isolation_timing="DWELL_30S")

    # Resource anomaly: CPU/memory must be correlated, not direct quarantine.
    elif resource_signal or (derived_resource_signal and signal not in explicit_non_resource_signals):
        valid_activity_raw = evidence.get("valid_activity") if "valid_activity" in evidence else activity.get("valid_activity")
        valid_activity = _as_bool(valid_activity_raw, True)
        heartbeat_ok = _as_bool(activity.get("heartbeat_ok"), True)
        work_units = _as_float(activity.get("work_units_processed"), 0.0) or 0.0
        stale_heartbeat = not heartbeat_ok or _as_bool(evidence.get("stale_heartbeat"), False)
        expected_high = _profile_allows_high_resource_usage(profile)

        cpu_signal = signal in {"high_cpu", "cpu_spike"}
        memory_signal = signal in {"high_memory", "memory_spike"}
        cpu_observed = cpu_signal or cpu_threshold_exceeded
        memory_observed = memory_signal or memory_threshold_exceeded
        cpu_threshold_is_explicit = not cpu_threshold_source.startswith("default_cpu_class:")

        if cpu_observed:
            if cpu_threshold_exceeded:
                b.add(
                    "L3_resource_behavior",
                    "RESOURCE_CPU_THRESHOLD_EXCEEDED",
                    f"cpu_usage_percent={cpu_usage_percent:.2f} exceeds threshold={cpu_threshold:.2f} ({cpu_threshold_source})",
                    20,
                )
            elif cpu_usage_percent is not None:
                b.add(
                    "L3_resource_behavior",
                    "R-METRIC-01",
                    f"cpu_anomaly_signal_observed_with_cpu_usage_percent={cpu_usage_percent:.2f}",
                    10,
                )
            else:
                b.add("L3_resource_behavior", "R-METRIC-01", "cpu_anomaly_signal_observed_without_numeric_cpu_metric", 10)

        if memory_observed:
            if memory_threshold_exceeded:
                b.add(
                    "L3_resource_behavior",
                    "RESOURCE_MEMORY_THRESHOLD_EXCEEDED",
                    f"memory_working_set_bytes={effective_memory_bytes:.0f} exceeds threshold={memory_threshold:.0f} ({memory_threshold_source})",
                    20,
                )
            elif effective_memory_bytes is not None:
                b.add(
                    "L3_resource_behavior",
                    "R-METRIC-02",
                    f"memory_anomaly_signal_observed_with_memory_working_set_bytes={effective_memory_bytes:.0f}",
                    10,
                )
            else:
                b.add("L3_resource_behavior", "R-METRIC-02", "memory_anomaly_signal_observed_without_numeric_memory_metric", 10)

        cpu_profile_allowed = False
        if cpu_observed:
            if cpu_threshold_exceeded and cpu_threshold_is_explicit:
                cpu_profile_allowed = False
            else:
                cpu_profile_allowed = expected_high

        memory_profile_allowed = False
        if memory_observed:
            if memory_threshold_exceeded:
                memory_profile_allowed = False
            else:
                memory_profile_allowed = expected_high

        suspicious = False

        if cpu_observed and (not valid_activity or stale_heartbeat or not cpu_profile_allowed):
            suspicious = True
            reason = "cpu_usage_not_profile_consistent_or_activity_invalid"
            if cpu_usage_percent is not None:
                reason += f":cpu={cpu_usage_percent:.2f},threshold={cpu_threshold:.2f}"
            if stale_heartbeat:
                reason += ",heartbeat_degraded"
            b.add("L3_resource_behavior", "RESOURCE_CPU_PROFILE_DEVIATION", reason, 20)

        if memory_observed and (not valid_activity or stale_heartbeat or not memory_profile_allowed):
            suspicious = True
            reason = "memory_usage_not_profile_consistent_or_activity_invalid"
            if effective_memory_bytes is not None and memory_threshold is not None:
                reason += f":memory={effective_memory_bytes:.0f},threshold={memory_threshold:.0f}"
            if stale_heartbeat:
                reason += ",heartbeat_degraded"
            b.add("L3_resource_behavior", "RESOURCE_MEMORY_PROFILE_DEVIATION", reason, 20)

        if suspicious:
            b.set_state(SUSPICIOUS, "MEDIUM", 0.80, contain=False)
        else:
            context = "valid_activity"
            if work_units > 0:
                context += f"_work_units={work_units:.0f}"
            if expected_high:
                context += "_profile_allows_high_workload"
            b.add("L3_resource_behavior", "R-PROFILE-01", f"resource_usage_matches_declared_xapp_intent_and_{context}", 0)
            b.set_state(NORMAL, "LOW", 0.72, contain=False)

    elif signal in {"profile_output_drift", "output_profile_drift"}:
        b.add("L3_resource_behavior", "R-BEH-01", "xapp_output_or_activity_deviates_from_declared_intent", 35)
        b.set_state(SUSPICIOUS, "MEDIUM", 0.78, contain=False)

    elif signal in {"ric_service_probe", "unexpected_ric_probe"}:
        allowed = profile.get("allowed_ric_services") or []
        target = str(evidence.get("target") or "")
        if target and target in allowed:
            b.add("L4_communication", "R-COMM-ALLOW-02", "ric_service_contact_allowed_by_profile", 0)
            b.set_state(NORMAL, "LOW", 0.65, contain=False)
        else:
            b.add("L4_communication", "R-COMM-01", "unexpected_ric_service_probe", 35)
            b.set_state(SUSPICIOUS, "MEDIUM", 0.78, contain=False)

    elif signal == "unexpected_peer_contact":
        allowed = profile.get("allowed_peers") or []
        peer = str(evidence.get("peer") or "")
        if peer and peer in allowed:
            b.add("L4_communication", "R-COMM-ALLOW-03", "peer_contact_allowed_by_profile", 0)
            b.set_state(NORMAL, "LOW", 0.65, contain=False)
        else:
            b.add("L4_communication", "R-COMM-02", "unexpected_cross_xapp_or_peer_contact", 35)
            b.set_state(SUSPICIOUS, "MEDIUM", 0.78, contain=False)

    else:
        b.add("L6_correlation", "R-UNKNOWN-01", f"unclassified_signal_observed:{signal}", 10)
        b.set_state(NORMAL, "LOW", 0.60, contain=False)

    # Correlation escalation. This is what makes the engine a state machine,
    # not only a direct signal mapper.
    correlated = evidence.get("correlated_signals") or []
    if isinstance(correlated, str):
        correlated = [x.strip() for x in correlated.split(",") if x.strip()]

    suspicious_context = 0
    suspicious_context += len(correlated)
    suspicious_context += 1 if _as_bool(evidence.get("stale_heartbeat"), False) else 0
    suspicious_context += 1 if _as_bool(evidence.get("svid_invalid"), False) else 0
    suspicious_context += 1 if _as_bool(evidence.get("unknown_process"), False) else 0
    suspicious_context += 1 if _as_bool(evidence.get("profile_drift"), False) else 0

    # 6th evidence check, added 2026-07-14 (see session log Section 10/11):
    # of the five checks above, only svid_invalid was ever actually
    # populated by app.py, so a WARNING-tier Falco signal could repeat
    # indefinitely and never escalate on its own. repeat_threshold_met is
    # set by app.py via ztx_repeat_tracker.record_and_check() before this
    # function is called - True means this specific signal has already
    # recurred past its own signal-specific threshold (2/3/4 occurrences
    # within 60s, see ztx_repeat_tracker.py) for this xApp. Weighted at 2,
    # not 1, so it can cross the suspicious_context>=2 bar on its own -
    # this is real corroborating evidence in its own right, not something
    # that should additionally require one of the other four (rarely
    # populated) flags to also be true.
    repeat_threshold_met = _as_bool(evidence.get("repeat_threshold_met"), False)
    if repeat_threshold_met:
        suspicious_context += 2

    if b.state == SUSPICIOUS and suspicious_context >= 2:
        # Reached COMPROMISED via corroborated/pieced-together evidence, not one
        # direct deterministic observation (contrast with the CRITICAL_SIGNALS /
        # FALCO_CRITICAL_SIGNAL_MAP / identity branches above, which are
        # isolation_timing="IMMEDIATE" - this includes the lateral-movement/
        # privilege-escalation signals, which are in FALCO_CRITICAL_SIGNAL_MAP
        # and therefore always IMMEDIATE, never reach COMPROMISED via this
        # path). This dwell-or-override path is what the kpimon-go resource
        # detector's correlation escalation already used - unchanged here.
        b.add("L6_correlation", "R-CORR-01", "multiple_suspicious_indicators_within_correlation_window", 30)
        if repeat_threshold_met:
            b.add(
                "L6_correlation",
                "R-CORR-02",
                f"signal_repeated_past_threshold:signal={signal},count={evidence.get('repeat_count')},window_seconds={evidence.get('repeat_window_seconds')}",
                0,
            )
        b.set_state(COMPROMISED, "HIGH", 0.90, contain=True, action="SERVICE_ISOLATION_AFTER_CORRELATION", isolation_timing="DWELL_30S")

    return b.result(evidence_sources).to_dict()
