"""
ZT-XGuard — src/ztx_model/streaming.py

Step 77+: online/streaming scorer for live xApp sidecar deployment.

Everything upstream of this module (steps 36-76) is offline, batch analysis
over recorded CSVs. This module is the production path: it consumes one raw
metrics sample at a time (as the KPIMON metrics collector would emit at 1 Hz)
and maintains exactly the state the batch pipeline computes from a full CSV --
directional excess, MEWMA state, T2 pressure score, 6-of-8 UCL confirmation,
and the frozen v5 CPU rate-of-exceedance gate -- so that the same frozen
model produces the same public state online as it would offline.

This module never fits or calibrates anything. All parameters are loaded from
already-frozen artifacts (Step 54 score spec + Step 76 gate manifest). If
those artifacts do not exist yet, construction fails loudly rather than
falling back to any default.

Known gap vs. the batch pipeline: `apply_eligibility_filter` (quality flags,
counter resets, timing) runs before windowing offline; this module does not
yet re-check those flags per sample before feeding the window/MEWMA state.
tests/test_streaming_equivalence.py passes on D4 because its only ineligible
rows are the leading warmup samples, which fall inside this module's own
warmup gate anyway -- but a caller integrating this against live KPIMON
telemetry should skip calling `update()` for any sample that fails the same
conditions as `ztx_model.quality.ELIGIBILITY_CONDITIONS` until that check is
added here directly.
"""
from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

from ztx_model.transforms import apply_transform
from ztx_model.mewma import warmup_steps


@dataclass(frozen=True)
class FrozenDetectorSpec:
    """Everything the streaming scorer needs, loaded once from frozen artifacts."""

    feature_ids: list[str]
    columns: list[str]
    transform_names: list[str]
    transform_lambdas: list[float | None]
    centers: np.ndarray
    effective_scales: np.ndarray
    precision: np.ndarray
    window_seconds: int
    lambda_value: float
    warmup_states: int
    upper_control_limit: float
    confirmation_l: int
    confirmation_k: int
    cpu_column: str
    cpu_gate_floor: float
    cpu_gate_window_l: int
    cpu_gate_rate_r: float

    @staticmethod
    def load(step54_dir: Path, step76_dir: Path) -> "FrozenDetectorSpec":
        v3_spec = yaml.safe_load((step54_dir / "v3_frozen_model_spec.yaml").read_text(encoding="utf-8"))
        precision = pd.read_csv(step54_dir / "v3_pressure_state_precision.csv", index_col=0).to_numpy(dtype=float)
        floor_params = pd.read_csv(step54_dir / "v3_effective_center_scale.csv").set_index("feature_id")

        gate_manifest = json.loads((step76_dir / "v5_frozen_gate_manifest.json").read_text(encoding="utf-8"))
        if gate_manifest["decision_gates"] != ["cpu"]:
            raise ValueError(
                "Streaming scorer only implements the CPU-only v5 decision gate. "
                f"Frozen manifest declares decision_gates={gate_manifest['decision_gates']!r}."
            )
        cpu_gate = gate_manifest["gates"]["cpu"]

        feature_ids = list(v3_spec["features"])
        columns, transform_names, transform_lambdas = [], [], []
        for feature_id in feature_ids:
            row = floor_params.loc[feature_id]
            columns.append(str(row["column"]))
            transform_names.append(str(row["selected_transform"]))
            transform_lambdas.append(None)  # v3 features (log1p/identity) never need a fitted lambda

        centers = floor_params.loc[feature_ids, "center"].to_numpy(dtype=float)
        scales = floor_params.loc[feature_ids, "effective_scale"].to_numpy(dtype=float)

        return FrozenDetectorSpec(
            feature_ids=feature_ids,
            columns=columns,
            transform_names=transform_names,
            transform_lambdas=transform_lambdas,
            centers=centers,
            effective_scales=scales,
            precision=precision,
            window_seconds=int(v3_spec["window_seconds"]),
            lambda_value=float(v3_spec["lambda_value"]),
            warmup_states=warmup_steps(float(v3_spec["lambda_value"])),
            upper_control_limit=float(v3_spec["upper_limit"]),
            confirmation_l=8,
            confirmation_k=6,
            cpu_column="m1_cpu_millicores",
            cpu_gate_floor=float(cpu_gate["per_sample_floor"]),
            cpu_gate_window_l=int(cpu_gate["window_l"]),
            cpu_gate_rate_r=float(cpu_gate["rate_r"]),
        )


@dataclass
class ScoreResult:
    """Full, loggable output for one incoming sample. Log every field."""

    elapsed_s: float
    ready: bool  # False during warmup: no public state should be acted on yet
    directional_excess: dict[str, float] | None
    v3_pressure_score: float | None
    sample_upper: bool | None
    confirmed_upper_6of8: bool | None
    cpu_gate_hit: bool | None
    public_state: str  # "NORMAL" or "SUSPICIOUS" (COMPROMISED is never set here)
    # Read-only exposure of the two rolling counts already tracked internally
    # (_upper_history, _cpu_exceed_history) - added 2026-08-25 purely for live
    # dashboard visualization (e.g. "5/8", "12/60"). Does not change the frozen
    # decision logic: confirmed_upper_6of8/cpu_gate_hit above are still computed
    # exactly as before; these fields just surface the counts behind them.
    upper_hits: int | None = None
    upper_window: int | None = None
    cpu_exceed_hits: int | None = None
    cpu_exceed_window: int | None = None


@dataclass
class StreamingScorer:
    """Maintains all rolling state for one KPIMON pod's live resource stream.

    Construct one instance per monitored pod. Never share state across pods
    or across a pod restart (that would be a cross-run state carry-over,
    exactly what Step 39's assert_no_cross_run_window forbids offline).
    """

    spec: FrozenDetectorSpec
    _window_buffer: deque = field(default_factory=deque)
    _mewma_state: np.ndarray | None = None
    _states_seen: int = 0
    _upper_history: deque = field(default_factory=deque)
    _cpu_exceed_history: deque = field(default_factory=deque)

    @classmethod
    def from_frozen_artifacts(cls, step54_dir: Path, step76_dir: Path) -> "StreamingScorer":
        spec = FrozenDetectorSpec.load(step54_dir, step76_dir)
        return cls(spec=spec)

    def reset(self) -> None:
        """Call on pod restart. Never carry MEWMA/window/confirmation state across restarts."""
        self._window_buffer.clear()
        self._mewma_state = None
        self._states_seen = 0
        self._upper_history.clear()
        self._cpu_exceed_history.clear()

    def _directional_excess(self, sample: dict[str, float]) -> np.ndarray:
        values = np.array([float(sample[col]) for col in self.spec.columns], dtype=float)
        transformed = np.empty_like(values)
        for i, (name, lam) in enumerate(zip(self.spec.transform_names, self.spec.transform_lambdas)):
            transformed[i] = apply_transform(np.array([values[i]]), name, lambda_value=lam)[0]
        standardized = (transformed - self.spec.centers) / self.spec.effective_scales
        return np.maximum(0.0, standardized)

    def update(self, sample: dict[str, float]) -> ScoreResult:
        """Feed one new 1 Hz sample. Must be called in strict elapsed_s order."""
        elapsed_s = float(sample["elapsed_s"])
        excess = self._directional_excess(sample)
        self._window_buffer.append(excess)
        if len(self._window_buffer) > self.spec.window_seconds:
            self._window_buffer.popleft()

        if len(self._window_buffer) < self.spec.window_seconds:
            return ScoreResult(elapsed_s, False, None, None, None, None, None, "NORMAL")

        window_mean = np.mean(np.stack(self._window_buffer), axis=0)
        prev = self._mewma_state if self._mewma_state is not None else np.zeros_like(window_mean)
        self._mewma_state = self.spec.lambda_value * window_mean + (1.0 - self.spec.lambda_value) * prev
        self._states_seen += 1

        if self._states_seen <= self.spec.warmup_states:
            return ScoreResult(
                elapsed_s, False,
                dict(zip(self.spec.feature_ids, excess.tolist())),
                None, None, None, None, "NORMAL",
            )

        score = float(self._mewma_state @ self.spec.precision @ self._mewma_state)
        sample_upper = score >= self.spec.upper_control_limit

        self._upper_history.append(bool(sample_upper))
        if len(self._upper_history) > self.spec.confirmation_l:
            self._upper_history.popleft()
        confirmed = sum(self._upper_history) >= self.spec.confirmation_k

        cpu_exceeds = float(sample[self.spec.cpu_column]) > self.spec.cpu_gate_floor
        self._cpu_exceed_history.append(bool(cpu_exceeds))
        if len(self._cpu_exceed_history) > self.spec.cpu_gate_window_l:
            self._cpu_exceed_history.popleft()
        cpu_rate = sum(self._cpu_exceed_history) / len(self._cpu_exceed_history)
        cpu_gate_hit = (
            len(self._cpu_exceed_history) >= self.spec.cpu_gate_window_l and cpu_rate > self.spec.cpu_gate_rate_r
        )

        public_state = "SUSPICIOUS" if (confirmed and cpu_gate_hit) else "NORMAL"

        return ScoreResult(
            elapsed_s=elapsed_s,
            ready=True,
            directional_excess=dict(zip(self.spec.feature_ids, excess.tolist())),
            v3_pressure_score=score,
            sample_upper=sample_upper,
            confirmed_upper_6of8=confirmed,
            cpu_gate_hit=cpu_gate_hit,
            public_state=public_state,
            upper_hits=sum(self._upper_history),
            upper_window=len(self._upper_history),
            cpu_exceed_hits=sum(self._cpu_exceed_history),
            cpu_exceed_window=len(self._cpu_exceed_history),
        )
