#!/usr/bin/env python3
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN_ID = datetime.now(timezone.utc).strftime("live-lifecycle-audit-%Y%m%dT%H%M%SZ")
OUT = ROOT / "evidence" / "framework-implementation" / "phase2-live-lifecycle" / RUN_ID
OUT.mkdir(parents=True, exist_ok=True)

ENGINE = "http://127.0.0.1:15000"
NAMESPACE = "ricxapp"
TARGET = "security-observer"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def now_ms():
    return int(time.time() * 1000)


def save_json(name, obj):
    p = OUT / name
    with open(p, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
    return str(p)


def run_cmd(args, timeout=30):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return {
        "cmd": args,
        "returncode": p.returncode,
        "stdout": p.stdout,
        "stderr": p.stderr,
    }


def kubectl_json(args, timeout=30):
    cmd = ["kubectl"] + args
    r = run_cmd(cmd, timeout=timeout)
    if r["returncode"] != 0:
        raise RuntimeError(f"kubectl failed: {' '.join(cmd)}\n{r['stderr']}")
    return json.loads(r["stdout"])


def http_json(method, path, payload=None, timeout=30):
    url = ENGINE + path
    data = None
    headers = {"Accept": "application/json"}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {
                "ok": 200 <= resp.status < 300,
                "status": resp.status,
                "url": url,
                "body": json.loads(body) if body else {},
                "raw": body,
            }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"raw": body}
        return {
            "ok": False,
            "status": e.code,
            "url": url,
            "body": parsed,
            "raw": body,
        }


def recursive_find(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            found = recursive_find(v, key)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = recursive_find(v, key)
            if found is not None:
                return found
    return None


def recursive_find_any(obj, keys):
    for k in keys:
        found = recursive_find(obj, k)
        if found is not None:
            return found
    return None


def service_selector(xapp):
    svc = kubectl_json(["get", "svc", "-n", NAMESPACE, xapp, "-o", "json"])
    return svc.get("spec", {}).get("selector", {}) or {}


def endpoint_count(xapp):
    ep = kubectl_json(["get", "endpoints", "-n", NAMESPACE, xapp, "-o", "json"])
    count = 0
    for subset in ep.get("subsets", []) or []:
        count += len(subset.get("addresses", []) or [])
    return count


def wait_endpoint_count(xapp, wanted, timeout_s=20):
    start = now_ms()
    observations = []
    deadline = time.time() + timeout_s

    while time.time() < deadline:
        try:
            ep = endpoint_count(xapp)
            sel = service_selector(xapp)
        except Exception as e:
            ep = None
            sel = {"error": str(e)}

        observations.append({
            "time": utc_now(),
            "endpoint_count": ep,
            "selector": sel,
        })

        if ep == wanted:
            return {
                "matched": True,
                "wanted": wanted,
                "latency_ms": now_ms() - start,
                "endpoint_count": ep,
                "selector": sel,
                "observations": observations,
            }

        time.sleep(0.5)

    return {
        "matched": False,
        "wanted": wanted,
        "latency_ms": now_ms() - start,
        "endpoint_count": observations[-1]["endpoint_count"] if observations else None,
        "selector": observations[-1]["selector"] if observations else {},
        "observations": observations,
    }


def main():
    print("ZT-XGuard Phase 2B Live Lifecycle Audit")
    print(f"OUT={OUT}")
    print(f"TARGET={TARGET}")
    print()

    summary = {
        "run_id": RUN_ID,
        "target": TARGET,
        "start_time": utc_now(),
        "checks": {},
        "latency_ms": {},
        "evidence_dir": str(OUT),
    }

    # 1. Health
    health = http_json("GET", "/health")
    save_json("01-health.json", health)
    health_body = health.get("body", {})
    health_pass = (
        health.get("ok") is True
        and health_body.get("status") == "ok"
        and health_body.get("state_engine_version") == "5.3-state-machine"
        and health_body.get("state_engine_import_error") is None
    )
    summary["checks"]["health_pass"] = health_pass

    print(f"[{'OK' if health_pass else 'FAIL'}] health state_engine_version={health_body.get('state_engine_version')}")

    # 2. Restore target to known baseline
    restore_start = now_ms()
    restore = http_json("POST", "/csm/containment/restore", {"xapp": TARGET})
    save_json("02-restore-before.json", restore)
    wait_ep1_before = wait_endpoint_count(TARGET, 1, timeout_s=20)
    save_json("03-baseline-endpoint-wait.json", wait_ep1_before)

    baseline_ep = wait_ep1_before.get("endpoint_count")
    baseline_selector = wait_ep1_before.get("selector", {})
    baseline_pass = (
        wait_ep1_before.get("matched") is True
        and baseline_ep == 1
        and baseline_selector.get("app") == TARGET
        and "zt-xguard.io/service-isolated" not in baseline_selector
    )
    summary["checks"]["baseline_pass"] = baseline_pass
    summary["latency_ms"]["baseline_restore_to_endpoint_one"] = now_ms() - restore_start

    print(f"[{'OK' if baseline_pass else 'FAIL'}] baseline endpoint_count={baseline_ep} selector={baseline_selector}")

    # 3. Ingest controlled A8 compromise signal
    payload = {
        "run_id": RUN_ID,
        "xapp": TARGET,
        "signal": "external_egress",
        "signal_type": "external_egress",
        "source": "phase2b_live_lifecycle_audit",
        "severity": "critical",
        "previous_state": "TRUSTED",
        "profile": {
            "role": "security_observer",
            "expected_external_egress": False,
            "allowed_peers": [],
        },
        "evidence": {
            "destination": "8.8.8.8",
            "method": "controlled_api_signal",
            "threat_scenario": "A8_external_egress",
        },
        "snapshot": {
            "activity": {
                "heartbeat_ok": True
            }
        }
    }

    decision_start = now_ms()
    ingest = http_json("POST", "/csm/intent/ingest", payload, timeout=60)
    decision_latency = now_ms() - decision_start
    save_json("04-a8-ingest-response.json", ingest)

    ingest_body = ingest.get("body", {})
    actual_state = recursive_find_any(ingest_body, ["actual_state", "detection_state", "decision_state", "state"])
    containment_required = recursive_find_any(ingest_body, ["containment_required", "actual_containment"])
    rule_ids = recursive_find_any(ingest_body, ["rule_ids"])

    decision_pass = (
        ingest.get("ok") is True
        and actual_state in ["COMPROMISED", "QUARANTINED"]
        and bool(containment_required) is True
    )

    summary["checks"]["decision_pass"] = decision_pass
    summary["decision"] = {
        "actual_state": actual_state,
        "containment_required": containment_required,
        "rule_ids": rule_ids,
    }
    summary["latency_ms"]["ingest_to_decision_response"] = decision_latency

    print(f"[{'OK' if decision_pass else 'FAIL'}] decision state={actual_state} containment_required={containment_required} rule_ids={rule_ids} decision_response_ms={decision_latency}")

    # 4. Wait for endpoint_count=0 after containment
    wait_ep0 = wait_endpoint_count(TARGET, 0, timeout_s=20)
    save_json("05-quarantine-endpoint-zero-wait.json", wait_ep0)

    quarantine_selector = wait_ep0.get("selector", {})
    quarantine_pass = (
        wait_ep0.get("matched") is True
        and wait_ep0.get("endpoint_count") == 0
        and quarantine_selector.get("zt-xguard.io/service-isolated") is not None
    )

    summary["checks"]["quarantine_endpoint_zero_pass"] = quarantine_pass
    summary["latency_ms"]["decision_response_to_endpoint_zero"] = wait_ep0.get("latency_ms")

    print(f"[{'OK' if quarantine_pass else 'FAIL'}] quarantine endpoint_count={wait_ep0.get('endpoint_count')} selector={quarantine_selector} endpoint_zero_wait_ms={wait_ep0.get('latency_ms')}")

    # 5. Query verify API if available
    verify = http_json("GET", f"/csm/containment/verify?xapp={urllib.parse.quote(TARGET)}")
    save_json("06-verify-after-quarantine.json", verify)

    # 6. Restore
    restore2_start = now_ms()
    restore2 = http_json("POST", "/csm/containment/restore", {"xapp": TARGET})
    save_json("07-restore-after-quarantine.json", restore2)

    wait_ep1_after = wait_endpoint_count(TARGET, 1, timeout_s=20)
    save_json("08-restore-endpoint-one-wait.json", wait_ep1_after)

    restored_selector = wait_ep1_after.get("selector", {})
    restore_pass = (
        wait_ep1_after.get("matched") is True
        and wait_ep1_after.get("endpoint_count") == 1
        and restored_selector.get("app") == TARGET
        and "zt-xguard.io/service-isolated" not in restored_selector
    )

    summary["checks"]["restore_pass"] = restore_pass
    summary["latency_ms"]["restore_to_endpoint_one"] = now_ms() - restore2_start

    print(f"[{'OK' if restore_pass else 'FAIL'}] restore endpoint_count={wait_ep1_after.get('endpoint_count')} selector={restored_selector}")

    summary["end_time"] = utc_now()
    summary["overall_pass"] = all(summary["checks"].values())

    save_json("summary.json", summary)

    print()
    print(json.dumps(summary, indent=2, sort_keys=True))

    if not summary["overall_pass"]:
        print()
        print("PHASE2B_LIVE_LIFECYCLE_AUDIT_FAIL")
        sys.exit(1)

    print()
    print("PHASE2B_LIVE_LIFECYCLE_AUDIT_PASS")


if __name__ == "__main__":
    main()
