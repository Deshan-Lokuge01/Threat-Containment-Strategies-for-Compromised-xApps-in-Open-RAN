"""
ZT-XGuard Policy Engine - shared in-memory CSM state cache.

Extracted from app.py during step_xguard_02 Step B1 (2026-07-15).
CSM_STATE/CSM_STATE_LOCK are mutated from both app.py (the Falco/decision
glue) and containment_orchestrator.py (_ztx_v2_set_state_normal on
restore), so this must be a single shared object both modules import,
never two independently-constructed dicts/locks.
"""
from __future__ import annotations

import threading
from time import monotonic
from typing import Any, Dict

from ztx_config import XAPP_LIST

CSM_STATE_LOCK = threading.Lock()
CSM_STATE: Dict[str, Dict[str, Any]] = {
    xapp: {
        "xapp": xapp,
        "state": "UNKNOWN",
        "score": 0,
        "pod": None,
        "findings": [],
        "last_source": "init",
        "last_update": None,
    }
    for xapp in XAPP_LIST
}

# Per-xapp locks so a full read-decide-write state transition (read previous
# state, decide the new one, persist it) can be made atomic per xapp without
# serializing unrelated xapps behind a single global lock - needed because a
# slow containment mechanism (RMR/E2 pod restart, ~27-29s) can be in progress
# for one xapp while high-frequency benign events keep arriving for others.
_CSM_XAPP_LOCKS: Dict[str, threading.Lock] = {}
_CSM_XAPP_LOCKS_GUARD = threading.Lock()


def csm_xapp_lock(xapp: str) -> threading.Lock:
    with _CSM_XAPP_LOCKS_GUARD:
        lock = _CSM_XAPP_LOCKS.get(xapp)
        if lock is None:
            lock = threading.Lock()
            _CSM_XAPP_LOCKS[xapp] = lock
        return lock


# 2026-08-23: per-xapp restore-grace window.
#
# A real /csm/containment/restore recreates the pod and resets CSM_STATE to
# NORMAL (_ztx_v2_set_state_normal). But the T2 collector keeps POSTing
# ~1 Hz resource-anomaly ticks to /csm/intent/ingest, and a tick still in
# flight (or scraped from the OLD pod moments before it was recreated) can
# be processed AFTER the reset lands, re-escalating the xapp away from
# NORMAL. Confirmed live: this leaves the dashboard stuck showing ISOLATED/
# QUARANTINED after a successful restore, non-deterministically (the single
# 5s re-assert timer in the restore wrapper can lose the race).
#
# Fix: when a restore resets an xapp, mark a short grace window. While it is
# open, the two live decision paths (ztx_v4_process_signal and
# csm_update_from_result) pin any NON-restore SOFT signal (anything below
# COMPROMISED) to NORMAL, so trailing soft chatter cannot override the
# restore. A genuinely fresh critical (COMPROMISED/ISOLATED) classification
# is never suppressed - a real new attack right after a restore is still
# detected and contained normally.
CSM_RESTORE_GRACE_SECONDS = 25.0
_CSM_RESTORE_GRACE: Dict[str, float] = {}
_CSM_RESTORE_GRACE_GUARD = threading.Lock()


def csm_mark_restored(xapp: str, seconds: float = CSM_RESTORE_GRACE_SECONDS) -> None:
    """Open a restore-grace window for xapp (default 25s)."""
    if not xapp:
        return
    with _CSM_RESTORE_GRACE_GUARD:
        _CSM_RESTORE_GRACE[xapp] = monotonic() + seconds


def csm_in_restore_grace(xapp: str) -> bool:
    """True while xapp is within its restore-grace window. Expired entries
    are pruned on read; read-only otherwise."""
    if not xapp:
        return False
    with _CSM_RESTORE_GRACE_GUARD:
        deadline = _CSM_RESTORE_GRACE.get(xapp)
        if deadline is None:
            return False
        if monotonic() >= deadline:
            _CSM_RESTORE_GRACE.pop(xapp, None)
            return False
        return True
