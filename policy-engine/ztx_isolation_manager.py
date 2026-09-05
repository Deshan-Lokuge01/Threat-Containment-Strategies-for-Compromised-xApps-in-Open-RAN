#!/usr/bin/env python3
"""ZT-XGuard COMPROMISED -> ISOLATED transition manager.

Implements the operator-confirmed design (2026-07-16):
- isolation_timing="IMMEDIATE" (direct Falco-critical observations - shell
  spawned, sensitive file read, SVID tamper, etc.): isolate on the same
  event, no wait.
- isolation_timing="DWELL_30S" (T2 resource-anomaly confirmation, and the
  Falco repeat-count correlation escalation): a 30-second dwell window
  starts the moment the xApp first reaches COMPROMISED under this timing.
  Auto-isolate once that window elapses if the xApp is still COMPROMISED
  and nothing has restored it; an operator can force isolation at any
  point during the window via record_manual_isolate().

Kept as its own small, single-job, stateful module - same pattern as
ztx_repeat_tracker.py - rather than folding this into app.py's already
heavily-patched decision-glue code.

Two ways a pending dwell window gets promoted to "isolate now":
1. Inline, via record_compromised() - called on every event that reaches
   COMPROMISED. If a DWELL_30S window happens to have already elapsed by
   the time a NEW event arrives for that xApp, this catches it within
   about a second of expiry (real-world resolution, since both T2 and
   repeat-tracker-escalated Falco signals typically keep re-firing while
   the underlying condition persists).
2. The background thread (start_dwell_checker) - guarantees the 30s
   promise even if no further event ever arrives for that xApp (e.g. an
   attack script is cancelled partway through, or a Falco correlation
   escalation never repeats). Checked every 2 seconds; calls the
   supplied on_expired(xapp) callback for anything past its window that
   hasn't already been isolated or cleared.
"""
from __future__ import annotations

import threading
import time
import traceback
from time import monotonic
from typing import Callable, Dict, Optional, Tuple

DWELL_SECONDS = 30.0
_CHECK_INTERVAL_SECONDS = 2.0

_lock = threading.Lock()
# xapp -> monotonic timestamp when this xapp first became COMPROMISED
# under DWELL_30S timing, still pending isolation.
_dwell_started: Dict[str, float] = {}


def _ztx_dbg_caller(fn_name: str, xapp: str, isolation_timing, outcome: str) -> None:
    """TEMPORARY 2026-07-25 diagnostic - catches every caller of this
    module's mutating functions regardless of which app.py wrapper layer
    invokes it, to find the source of unexplained early isolations that
    don't correspond to any call visible in app.py's own
    ztx_v4_process_signal instrumentation. Logs the immediate caller's
    file:line (frame -2, skipping this helper and its direct caller)."""
    try:
        stack = traceback.extract_stack()
        caller = stack[-3] if len(stack) >= 3 else stack[0]
        with open("/tmp/ztx_isolation_debug.log", "a") as fh:
            fh.write(
                f"{time.strftime('%H:%M:%S')} ISOMGR {fn_name} xapp={xapp} "
                f"isolation_timing={isolation_timing} outcome={outcome} "
                f"caller={caller.filename.split('/')[-1]}:{caller.lineno} in {caller.name}\n"
            )
    except Exception:
        pass


def record_compromised(xapp: str, isolation_timing: str) -> Tuple[bool, Optional[float]]:
    """Call once per decision that reaches COMPROMISED.

    Returns (isolate_now, seconds_remaining). isolate_now=True means the
    caller should perform the actual isolation action immediately -
    either because isolation_timing is IMMEDIATE, or because a
    previously-started DWELL_30S window has now elapsed.
    """
    timing = str(isolation_timing or "IMMEDIATE").upper()
    now = monotonic()
    with _lock:
        started = _dwell_started.get(xapp)

        # 2026-07-25: a non-DWELL_30S call must NEVER cancel a dwell
        # window already in progress for this xapp. Confirmed live
        # (A_Burst): app.py's ztx_v4_process_signal/csm_update_from_result
        # is 3 nested layers deep (base/intermediate/outer wrapper), each
        # independently reading CSM_STATE and each independently able to
        # call this function - and near-simultaneous requests for
        # different signal types (resource_anomaly_t2 vs. _elevated) for
        # the same xapp can race across those layers regardless of
        # caller-side downgrade_blocked guards. Centralizing the guard
        # here, in the one place all callers funnel through, is the only
        # reliable fix: if a dwell is already tracked, ANY call (whatever
        # isolation_timing it carries) just continues checking that
        # existing window instead of bypassing it. Only a genuinely new
        # compromise (no dwell yet tracked) can start a fresh window, and
        # only THEN does a non-DWELL_30S timing mean immediate isolation
        # (the real Falco-IMMEDIATE case).
        if timing != "DWELL_30S" and started is None:
            _ztx_dbg_caller("record_compromised", xapp, isolation_timing, "BYPASS(True,None)")
            return True, None

        if started is None:
            _dwell_started[xapp] = now
            _ztx_dbg_caller("record_compromised", xapp, isolation_timing, "FRESH_START(False,30.0)")
            return False, DWELL_SECONDS
        elapsed = now - started
        if elapsed >= DWELL_SECONDS:
            _ztx_dbg_caller("record_compromised", xapp, isolation_timing, "EXPIRED(True,0.0)")
            return True, 0.0
        return False, DWELL_SECONDS - elapsed


def record_manual_isolate(xapp: str) -> None:
    """Operator forced isolation, or isolation just completed - clears
    any pending dwell window for this xApp so it isn't re-checked."""
    with _lock:
        _dwell_started.pop(xapp, None)
    _ztx_dbg_caller("record_manual_isolate", xapp, None, "CLEARED")


def clear(xapp: str) -> None:
    """Called whenever an xApp's state moves away from COMPROMISED
    through any path other than isolation itself (e.g. a fresh NORMAL/
    SUSPICIOUS re-evaluation, or a restore) - cancels a pending dwell
    window so a stale timer can't fire against a no-longer-compromised
    xApp."""
    with _lock:
        _dwell_started.pop(xapp, None)


def dwell_status(xapp: str) -> Optional[float]:
    """Seconds remaining in xApp's pending dwell window, or None if it
    has no pending window. Read-only - does not mutate state."""
    with _lock:
        started = _dwell_started.get(xapp)
    if started is None:
        return None
    return max(0.0, DWELL_SECONDS - (monotonic() - started))


def start_dwell_checker(on_expired: Callable[[str], None]) -> threading.Thread:
    """Start the background daemon thread that guarantees the 30s
    promise even with no further incoming events for an xApp. Safe to
    call once at process startup; on_expired is responsible for
    re-verifying the xApp is still genuinely COMPROMISED before acting
    (this loop only reports "this xApp's window has elapsed since it was
    last known compromised", not current live truth) and for calling
    record_manual_isolate()/clear() once it's done so this xApp isn't
    reported again on the next check.
    """
    def _loop() -> None:
        while True:
            time.sleep(_CHECK_INTERVAL_SECONDS)
            now = monotonic()
            with _lock:
                expired = [x for x, started in _dwell_started.items() if now - started >= DWELL_SECONDS]
            for xapp in expired:
                try:
                    on_expired(xapp)
                except Exception:
                    pass

    t = threading.Thread(target=_loop, name="ztx-isolation-dwell-checker", daemon=True)
    t.start()
    return t
