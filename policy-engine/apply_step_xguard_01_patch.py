#!/usr/bin/env python3
"""
step_xguard_01 in-place patcher.

Run this ONCE, directly on the VM, from inside:
  ~/Desktop/FYP/zt-xguard/ztx-control-plane/policy-engine/

    python3 apply_step_xguard_01_patch.py

It edits ztx_state_engine.py and app.py IN PLACE using exact string
search-and-replace, mirroring precisely what was already tested and
verified on the Windows-side copy (all 18 cases of
scripts/evaluation/state-engine-unit-gate.py passed after this same set
of edits).

Safety: every edit does an EXACT string match first. If any expected
string is not found (e.g. because the live VM file has diverged more than
already known), that specific edit is skipped, reported clearly, and NO
partial/corrupt write happens for that file - either every edit for a
file succeeds and the file is written, or nothing is written to it.

Backs up both files first, with a timestamped name matching this
project's own existing .bak-* convention, before changing anything.
"""
from __future__ import annotations
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
TS = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def backup(path: Path) -> Path:
    bak = path.with_name(f"{path.name}.bak-4state-model-{TS}")
    shutil.copy2(path, bak)
    print(f"  backed up -> {bak.name}")
    return bak


def apply_edits(path: Path, edits: list[tuple[str, str, str]]) -> bool:
    """edits: list of (description, old, new). Returns True if file was written."""
    text = path.read_text(encoding="utf-8")
    original = text
    failures = []
    for desc, old, new in edits:
        count = text.count(old)
        if count == 0:
            failures.append(desc)
            continue
        if count > 1:
            failures.append(f"{desc} (ABORT: matched {count} times, expected exactly 1 - refusing, ambiguous)")
            continue
        text = text.replace(old, new, 1)

    if failures:
        print(f"  [ABORT] {path.name}: {len(failures)} edit(s) could not be safely applied:")
        for f in failures:
            print(f"    - {f}")
        print(f"  No changes written to {path.name}. Paste this output back for a corrected patch.")
        return False

    if text == original:
        print(f"  [NOOP] {path.name}: no changes needed (already patched?)")
        return False

    backup(path)
    path.write_text(text, encoding="utf-8")
    print(f"  [OK] {path.name}: {len(edits)} edit(s) applied and written.")
    return True


# =====================================================================
# ztx_state_engine.py edits
# =====================================================================
STATE_ENGINE_EDITS = [
    (
        "constants block: 8-state -> 4-state model",
        '''STATE_ENGINE_VERSION = "5.3-state-machine"

TRUSTED = "TRUSTED"
OBSERVED = "OBSERVED"
SUSPICIOUS = "SUSPICIOUS"
COMPROMISED = "COMPROMISED"
QUARANTINED = "QUARANTINED"
RESTORED = "RESTORED"
UNKNOWN = "UNKNOWN"
IGNORED = "IGNORED"''',
        '''STATE_ENGINE_VERSION = "6.0-4state-machine"

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
RESTORED = NORMAL''',
    ),
    (
        "DecisionBuilder.__init__: self.state = TRUSTED -> NORMAL",
        '        self.severity = "INFO"\n        self.state = TRUSTED',
        '        self.severity = "INFO"\n        self.state = NORMAL',
    ),
    (
        "DecisionBuilder.result(): action ternary, OBSERVED -> severity-based",
        '''    def result(self, evidence_sources: Dict[str, bool]) -> StateDecision:
        action = "FORENSIC_QUARANTINE" if self.containment_required else (
            "EVIDENCE_ONLY" if self.state == SUSPICIOUS else "INCREASE_MONITORING" if self.state == OBSERVED else "MONITOR"
        )''',
        '''    def result(self, evidence_sources: Dict[str, bool]) -> StateDecision:
        # NORMAL now covers what used to be two distinct states (TRUSTED,
        # severity=INFO, and OBSERVED, severity=LOW) - severity is what
        # still distinguishes them, so key the action off severity rather
        # than the now-collapsed state label, to keep this identical to
        # the pre-4-state behavior.
        action = "FORENSIC_QUARANTINE" if self.containment_required else (
            "EVIDENCE_ONLY" if self.state == SUSPICIOUS else "INCREASE_MONITORING" if self.severity == "LOW" else "MONITOR"
        )''',
    ),
    (
        "benign_controls set_state: TRUSTED -> NORMAL",
        'b.add("L3_resource_behavior", "R-BENIGN-01", f"{signal}_profile_consistent", 0)\n        b.set_state(TRUSTED, "INFO", 0.90, contain=False)',
        'b.add("L3_resource_behavior", "R-BENIGN-01", f"{signal}_profile_consistent", 0)\n        b.set_state(NORMAL, "INFO", 0.90, contain=False)',
    ),
    (
        "external_egress-allowed set_state: OBSERVED -> NORMAL",
        'b.add("L4_communication", "R-COMM-ALLOW-01", "external egress allowed by xApp profile", 0)\n            b.set_state(OBSERVED, "LOW", 0.65, contain=False)',
        'b.add("L4_communication", "R-COMM-ALLOW-01", "external egress allowed by xApp profile", 0)\n            b.set_state(NORMAL, "LOW", 0.65, contain=False)',
    ),
    (
        "resource-profile-consistent set_state: OBSERVED -> NORMAL",
        'b.add("L3_resource_behavior", "R-PROFILE-01", f"resource_usage_matches_declared_xapp_intent_and_{context}", 0)\n            b.set_state(OBSERVED, "LOW", 0.72, contain=False)',
        'b.add("L3_resource_behavior", "R-PROFILE-01", f"resource_usage_matches_declared_xapp_intent_and_{context}", 0)\n            b.set_state(NORMAL, "LOW", 0.72, contain=False)',
    ),
    (
        "ric_service_probe-allowed set_state: OBSERVED -> NORMAL",
        'b.add("L4_communication", "R-COMM-ALLOW-02", "ric_service_contact_allowed_by_profile", 0)\n            b.set_state(OBSERVED, "LOW", 0.65, contain=False)',
        'b.add("L4_communication", "R-COMM-ALLOW-02", "ric_service_contact_allowed_by_profile", 0)\n            b.set_state(NORMAL, "LOW", 0.65, contain=False)',
    ),
    (
        "unexpected_peer_contact-allowed set_state: OBSERVED -> NORMAL",
        'b.add("L4_communication", "R-COMM-ALLOW-03", "peer_contact_allowed_by_profile", 0)\n            b.set_state(OBSERVED, "LOW", 0.65, contain=False)',
        'b.add("L4_communication", "R-COMM-ALLOW-03", "peer_contact_allowed_by_profile", 0)\n            b.set_state(NORMAL, "LOW", 0.65, contain=False)',
    ),
    (
        "unclassified-signal set_state: OBSERVED -> NORMAL",
        'b.add("L6_correlation", "R-UNKNOWN-01", f"unclassified_signal_observed:{signal}", 10)\n        b.set_state(OBSERVED, "LOW", 0.60, contain=False)',
        'b.add("L6_correlation", "R-UNKNOWN-01", f"unclassified_signal_observed:{signal}", 10)\n        b.set_state(NORMAL, "LOW", 0.60, contain=False)',
    ),
]

# =====================================================================
# app.py edit - single compat shim at the funnel point after the one
# call to ztx_v5_evaluate_state(), before the downstream check that
# compares against the literal old-vocabulary set {"COMPROMISED","QUARANTINED"}.
# =====================================================================
APP_PY_EDITS = [
    (
        "compat shim after ztx_v5_evaluate_state() call",
        '''    decision = ztx_v5_evaluate_state(
        xapp=xapp,
        signal=normalized_signal,
        profile=profile,
        evidence=enriched,
        snapshot=v5_snapshot,
        previous_state=previous_state,
    )
    decision["normalized_signal"] = normalized_signal

    if normalized_signal in ZTX_SUSPICIOUS_ONLY_SIGNALS and bool(decision.get("containment_required")):''',
        '''    decision = ztx_v5_evaluate_state(
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

    if normalized_signal in ZTX_SUSPICIOUS_ONLY_SIGNALS and bool(decision.get("containment_required")):''',
    ),
]


def main() -> None:
    print(f"step_xguard_01 patcher, running from: {HERE}")

    se_path = HERE / "ztx_state_engine.py"
    app_path = HERE / "app.py"

    if not se_path.exists() or not app_path.exists():
        print("ERROR: run this script from inside ztx-control-plane/policy-engine/ - "
              "ztx_state_engine.py and/or app.py not found here.")
        sys.exit(1)

    print("\n[1/2] ztx_state_engine.py")
    ok1 = apply_edits(se_path, STATE_ENGINE_EDITS)

    print("\n[2/2] app.py")
    ok2 = apply_edits(app_path, APP_PY_EDITS)

    print("\n" + "=" * 60)
    if ok1 and ok2:
        print("BOTH FILES PATCHED. Next: py_compile check, then restart the pod.")
        print("  python3 -m py_compile ztx_state_engine.py app.py")
    else:
        print("NOT all edits succeeded - see [ABORT]/[NOOP] messages above.")
        print("No file was left partially edited. Paste this full output back.")
    print("=" * 60)


if __name__ == "__main__":
    main()
