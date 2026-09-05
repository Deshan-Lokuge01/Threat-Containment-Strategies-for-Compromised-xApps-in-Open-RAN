"""
ZT-XGuard - ztx_model/mewma.py (deployment shim, not the frozen source module)

streaming.py only imports warmup_steps() from the real src/ztx_model/mewma.py.
The real module also unconditionally imports scikit-learn (for LedoitWolf
covariance fitting, used only by the offline calibration pipeline, never by
the live streaming scorer) at module top level, which would force installing
scikit-learn into the policy-engine pod for a class that's never called at
runtime here.

This shim contains ONLY warmup_steps(), copied verbatim (byte-identical
logic, not reimplemented) from src/ztx_model/mewma.py as of 2026-07-15. The
real, complete module (with LedoitWolf, t2_scores, etc.) is untouched at
src/ztx_model/mewma.py - this is a deployment-only substitute, not a change
to the frozen model's source of truth.
"""
from __future__ import annotations

import math


def warmup_steps(lam: float, epsilon: float = 0.01) -> int:
    """Number of MEWMA updates to discard at start of each run."""
    if not 0.0 < lam <= 1.0:
        raise ValueError("lambda must be in (0, 1].")
    if not 0.0 < epsilon < 1.0:
        raise ValueError("epsilon must be in (0, 1).")
    return math.ceil(math.log(epsilon) / math.log(1.0 - lam))
