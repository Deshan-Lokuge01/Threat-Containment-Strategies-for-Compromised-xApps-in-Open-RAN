#!/usr/bin/env python3
"""Offline response-validation tests for the evaluator load harness."""
import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).with_name("run_evaluator_open_loop.py")
SPEC = importlib.util.spec_from_file_location("evaluator_bench", SCRIPT)
module = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(module)

valid = {"ok": True, "result": {
    "xapp": "x1", "state": "SUSPICIOUS", "containment_required": False,
    "containment_action": "NONE", "reasons": ["r"], "rule_ids": ["R-1"],
}}
assert module.validate_response(valid, "x1") == (True, "", "SUSPICIOUS")
bad_state = {"ok": True, "result": {**valid["result"], "state": "QUARANTINED"}}
assert module.validate_response(bad_state, "x1")[0] is False
bad_containment = {"ok": True, "result": {**valid["result"], "containment_required": True}}
assert module.validate_response(bad_containment, "x1")[0] is False
bad_identity = {"ok": True, "result": {**valid["result"], "xapp": "x2"}}
assert module.validate_response(bad_identity, "x1")[0] is False
print("evaluator open-loop harness offline tests: PASS")
