#!/usr/bin/env python3
"""ZT-XGuard repeat-count tracker for WARNING-tier Falco signals.

Kept separate from ztx_state_engine.py (pure decision logic) and app.py
(the 7000+ line legacy file this project deliberately stopped extending -
see ZTXGUARD_SESSION_LOG_20260710.md Section 3). This module has exactly
one job: remember, per xApp and per signal type, how many times a signal
has recurred within a rolling time window, and report whether that count
has crossed the signal-specific threshold.

Background (see session log Section 10, 2026-07-13): of the five
"corroborating evidence" flags ztx_state_engine.py's correlation block
originally checked (correlated_signals, stale_heartbeat, svid_invalid,
unknown_process, profile_drift), only svid_invalid was ever actually
populated by app.py - meaning a WARNING-tier Falco signal could repeat
indefinitely and never escalate to COMPROMISED on its own. This module,
plus the repeat_threshold_met evidence flag it feeds into
ztx_state_engine.py, closes that gap.

Thresholds and window (finalized 2026-07-13, not statistically validated
against real attack data the way WL/UCL/6-of-8/T_confirm are for the
resource detector - a documented design choice, not a proven one):
tiered by how plausible an innocent explanation is for the action, not
one flat number for every signal type.
"""
from __future__ import annotations

import threading
from collections import defaultdict, deque
from time import monotonic
from typing import Deque, Dict, Tuple

# Reused from the already-validated resource-detector CPU-gate window, and
# independently matches this cluster's own observed SPIRE
# NEXT_CHECK_IN_SECONDS=60 renewal cadence - two independent reasons
# converging on the same number, not an invented one.
REPEAT_WINDOW_SECONDS = 60

# 2: almost no plausible innocent explanation for either action.
# 3: some ambiguity - could plausibly be a one-off legitimate contact/write.
# 4: an operator might genuinely run this by hand once during debugging.
# Consecutive integers chosen deliberately over "nicer-looking" numbers
# specifically because there is no real false-positive-rate data yet to
# justify more precision than that (honesty over false precision).
REPEAT_THRESHOLDS: Dict[str, int] = {
    "k8s_api_contact": 2,
    "permission_tamper": 2,
    "binary_drop": 3,
    "unexpected_peer_contact": 3,
    "unexpected_ric_probe": 3,
    "package_manager_execution": 4,
    # 2026-07-15: "resource_anomaly_t2" was briefly tracked here (threshold
    # 2) so the T2 resource-anomaly detector's fully-confirmed signal needed
    # to recur once within 60s before reaching COMPROMISED. Removed 2026-07-16:
    # corrected per direct agreement with the operator - the collector only
    # ever emits that signal once 6-of-8 confirmed states plus the CPU
    # rate-of-exceedance gate already hold, which already represents roughly
    # a minute of corroborated statistical evidence, so it now maps directly
    # to COMPROMISED in ztx_state_engine.py without needing a second
    # occurrence. See that file's "resource_anomaly_t2" branch.
}

_lock = threading.Lock()
_occurrences: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)


def record_and_check(xapp: str, signal: str) -> Tuple[bool, int]:
    """Record one occurrence of `signal` for `xapp` now, and report whether
    the signal-specific repeat threshold has been met within the rolling
    REPEAT_WINDOW_SECONDS window.

    Returns (threshold_met, current_count_in_window). Signals not in
    REPEAT_THRESHOLDS always return (False, 0) - this tracker only applies
    to the specific WARNING-tier signals the 2026-07-13 design covers, not
    every signal type indiscriminately. Uses a monotonic clock, not wall
    time, so system clock adjustments (NTP, manual changes) can't distort
    the window.
    """
    threshold = REPEAT_THRESHOLDS.get(signal)
    if threshold is None:
        return False, 0

    now = monotonic()
    key = (str(xapp or "unknown"), signal)
    with _lock:
        window = _occurrences[key]
        window.append(now)
        cutoff = now - REPEAT_WINDOW_SECONDS
        while window and window[0] < cutoff:
            window.popleft()
        count = len(window)

    return count >= threshold, count
