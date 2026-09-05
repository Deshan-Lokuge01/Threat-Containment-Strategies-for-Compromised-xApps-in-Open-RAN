#!/usr/bin/env python3
"""Dependency-light self-tests for the scalability detector harness."""
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("run_detector_capacity.py")
SPEC = importlib.util.spec_from_file_location("capacity", SCRIPT)
capacity = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(capacity)


def main() -> None:
    rows, rejected = capacity.read_admissible_trace(capacity.DEFAULT_TRACE)
    assert len(rows) == 1772, len(rows)
    assert rejected == {"sample_quality:memory_slope_warmup": 28}, rejected
    spec = capacity.load_frozen_spec()
    assert spec.window_seconds == 8
    assert spec.confirmation_l == 8 and spec.confirmation_k == 6
    assert spec.cpu_gate_window_l == 60
    assert abs(spec.cpu_gate_rate_r - 0.15) < 1e-12
    _, scorer_type, _ = capacity.load_streaming_types()
    scorer = scorer_type(spec=spec)
    results = []
    for tick, source in enumerate(rows[:100], 1):
        sample = dict(source)
        sample["elapsed_s"] = float(tick)
        results.append(scorer.update(sample))
    assert not results[0].ready
    assert results[-1].ready
    assert all(result.public_state in {"NORMAL", "SUSPICIOUS"} for result in results)
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "worker.json"
        args = type("Args", (), {
            "trace": str(capacity.DEFAULT_TRACE), "workloads": 3, "ticks": 80,
            "seed": 17, "repetition": 1, "started_utc": capacity.utc_now(),
            "worker_output": str(out),
        })()
        assert capacity.worker(args) == 0
        data = __import__("json").loads(out.read_text())
        assert data["expected_updates"] == data["observed_updates"] == 240
        assert len(data["cycles"]) == 80
        assert len(data["accounting"]) == 3
        assert all(row["updates"] == 80 for row in data["accounting"])
    print("detector capacity harness self-test: PASS")


if __name__ == "__main__":
    main()
