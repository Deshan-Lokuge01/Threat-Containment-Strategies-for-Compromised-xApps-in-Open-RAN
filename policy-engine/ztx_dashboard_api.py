#!/usr/bin/env python3
"""ZT-XGuard SOC dashboard backend.

Two capabilities the new primary dashboard needs, kept out of the heavily
patched app.py:

1. Per-xApp runtime metrics (CPU / memory / network RX-TX) for the live
   graphs. Source is the kubelet Summary API (https://<node>:10250/stats/
   summary) read with the policy-engine ServiceAccount token. This is the
   only in-cluster source that gives per-pod counters WITHOUT exec'ing into
   the xApp - exec would itself trip Falco's unexpected_shell rule and
   auto-contain the pod we are trying to measure. Requires the
   zt-xguard-kubelet-stats ClusterRole (nodes/stats, nodes get/list).

2. A real attack launcher for the dashboard console. Runs a whitelisted
   attack command inside the target xApp via the k8s exec API (genuinely
   triggering Falco -> the real containment pipeline). Requires the
   zt-xguard-ricxapp-attacker Role (pods/exec in ricxapp).

Both are registered onto the existing Flask APP via register_dashboard_api().
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import ssl
import threading
import time
import traceback
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Response, jsonify, request, send_file
from kubernetes.client import ApiException
from kubernetes.client import V1Container, V1ObjectMeta, V1Pod, V1PodSpec
from kubernetes.stream import stream

from k8s_clients import CORE, EXEC_CORE

# --------------------------------------------------------------------------
# Forensic evidence vault (DFIR / SOC-standard, tamper-evident).
# The containment path already captures per-incident artifacts (pod spec,
# k8s events, log tail, the decision record) to the /evidence PVC. A
# background sealer mirrors each incident into a durable, on-disk vault
# inside the project (hostPath /forensic-vault ->
# zt-xguard/forensic-vault), computing a SHA-256 over every artifact and
# writing a chain-of-custody manifest. This matches standard evidence
# handling: write-once artifacts, integrity hashes, and a custody log.
# --------------------------------------------------------------------------
FORENSIC_VAULT = Path(os.environ.get("FORENSIC_VAULT", "/forensic-vault"))
EVIDENCE_INCIDENTS = Path(os.environ.get("EVIDENCE_DIR", "/evidence")) / "incidents"
_VAULT_STARTED = False


def _vutc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _incident_summary_from_meta(meta: Dict[str, Any]) -> Dict[str, Any]:
    dr = meta.get("decision_result") or {}
    re_ = meta.get("raw_event") or {}
    return {
        "captured_utc": meta.get("time"),
        "xapp": meta.get("xapp"),
        "pod": meta.get("pod_name"),
        "namespace": meta.get("namespace"),
        "source": dr.get("source") or re_.get("source"),
        "signal": dr.get("normalized_signal") or dr.get("signal"),
        "falco_rule": re_.get("rule"),
        "priority": re_.get("priority"),
        "rule_ids": dr.get("rule_ids"),
        "state": dr.get("final_state") or dr.get("state"),
        "detection_state": dr.get("detection_state"),
        "severity": dr.get("severity"),
        "isolation_timing": dr.get("isolation_timing"),
        "containment_required": dr.get("containment_required"),
        "containment_action": dr.get("containment_action"),
        "score": dr.get("score"),
        "confidence": dr.get("confidence"),
        "alert": (re_.get("output") or "")[:800],
    }


def _seal_incident(src_dir: Path, inc_id: str) -> None:
    dst = FORENSIC_VAULT / inc_id
    if (dst / "manifest.json").exists():
        return  # already sealed - write-once
    dst.mkdir(parents=True, exist_ok=True)
    meta: Dict[str, Any] = {}
    try:
        meta = json.loads((src_dir / "incident.json").read_text(encoding="utf-8"))
    except Exception:
        pass
    artifacts = []
    for f in sorted(src_dir.glob("*")):
        if not f.is_file():
            continue
        try:
            shutil.copy2(f, dst / f.name)
            artifacts.append({"name": f.name, "bytes": (dst / f.name).stat().st_size, "sha256": _sha256(dst / f.name)})
        except Exception:
            pass
    summary = _incident_summary_from_meta(meta)
    manifest = {
        "schema": "ztx-forensic-vault-v1",
        "incident_id": inc_id,
        "captured_utc": summary.get("captured_utc"),
        "sealed_utc": _vutc(),
        "captured_by": "ZT-XGuard policy-engine (automated containment)",
        "asset": {"xapp": summary.get("xapp"), "pod": summary.get("pod"), "namespace": summary.get("namespace")},
        "trigger": {
            "source": summary.get("source"), "signal": summary.get("signal"),
            "falco_rule": summary.get("falco_rule"), "priority": summary.get("priority"),
            "rule_ids": summary.get("rule_ids"), "alert": summary.get("alert"),
        },
        "decision": {
            "state": summary.get("state"), "detection_state": summary.get("detection_state"),
            "containment_required": summary.get("containment_required"),
            "containment_action": summary.get("containment_action"),
            "isolation_timing": summary.get("isolation_timing"),
            "severity": summary.get("severity"), "score": summary.get("score"),
            "confidence": summary.get("confidence"),
        },
        "integrity": "sha256",
        "artifacts": artifacts,
        "chain_of_custody": [
            {"actor": "policy-engine.forensic-capture", "action": "captured", "utc": summary.get("captured_utc")},
            {"actor": "policy-engine.vault-sealer", "action": "sealed+hashed", "utc": _vutc()},
        ],
    }
    tmp = dst / ".manifest.json.tmp"
    tmp.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    tmp.replace(dst / "manifest.json")


def _vault_sync_once() -> None:
    if not EVIDENCE_INCIDENTS.exists():
        return
    try:
        FORENSIC_VAULT.mkdir(parents=True, exist_ok=True)
    except Exception:
        return
    for d in sorted(EVIDENCE_INCIDENTS.iterdir()):
        if d.is_dir():
            try:
                _seal_incident(d, d.name)
            except Exception:
                pass


def _vault_sync_loop() -> None:
    while True:
        try:
            _vault_sync_once()
        except Exception:
            pass
        time.sleep(20)


def start_vault_sync() -> None:
    global _VAULT_STARTED
    if _VAULT_STARTED:
        return
    _VAULT_STARTED = True
    threading.Thread(target=_vault_sync_loop, daemon=True, name="ztx-vault-sync").start()


def _incident_base() -> Path:
    return FORENSIC_VAULT if FORENSIC_VAULT.exists() else EVIDENCE_INCIDENTS


def _read_incident_meta(d: Path) -> Dict[str, Any]:
    # prefer the sealed manifest; fall back to raw incident.json
    mf = d / "manifest.json"
    if mf.exists():
        try:
            m = json.loads(mf.read_text(encoding="utf-8"))
            return {
                "id": m.get("incident_id", d.name), "captured_utc": m.get("captured_utc"),
                "sealed_utc": m.get("sealed_utc"),
                "xapp": (m.get("asset") or {}).get("xapp"), "pod": (m.get("asset") or {}).get("pod"),
                "source": (m.get("trigger") or {}).get("source"), "signal": (m.get("trigger") or {}).get("signal"),
                "falco_rule": (m.get("trigger") or {}).get("falco_rule"), "priority": (m.get("trigger") or {}).get("priority"),
                "rule_ids": (m.get("trigger") or {}).get("rule_ids"),
                "state": (m.get("decision") or {}).get("state"), "severity": (m.get("decision") or {}).get("severity"),
                "sealed": True, "artifacts": len(m.get("artifacts") or []),
            }
        except Exception:
            pass
    try:
        meta = json.loads((d / "incident.json").read_text(encoding="utf-8"))
        s = _incident_summary_from_meta(meta)
        return {"id": d.name, "captured_utc": s.get("captured_utc"), "sealed_utc": None,
                "xapp": s.get("xapp"), "pod": s.get("pod"), "source": s.get("source"),
                "signal": s.get("signal"), "falco_rule": s.get("falco_rule"), "priority": s.get("priority"),
                "rule_ids": s.get("rule_ids"), "state": s.get("state"), "severity": s.get("severity"),
                "sealed": False, "artifacts": len([f for f in d.glob("*") if f.is_file()])}
    except Exception:
        return {"id": d.name, "sealed": False}


def list_incidents(limit: int = 300) -> List[Dict[str, Any]]:
    base = _incident_base()
    if not base.exists():
        return []
    dirs = sorted([p for p in base.iterdir() if p.is_dir()], key=lambda p: p.name, reverse=True)[:limit]
    return [_read_incident_meta(d) for d in dirs]


def incident_detail(inc_id: str) -> Dict[str, Any]:
    if "/" in inc_id or ".." in inc_id:
        return {"ok": False, "error": "bad_id"}
    d = _incident_base() / inc_id
    if not d.exists():
        d = EVIDENCE_INCIDENTS / inc_id
    if not d.exists():
        return {"ok": False, "error": "not_found", "id": inc_id}
    manifest = None
    mf = d / "manifest.json"
    if mf.exists():
        try:
            manifest = json.loads(mf.read_text(encoding="utf-8"))
        except Exception:
            manifest = None
    files = []
    for f in sorted(d.glob("*")):
        if f.is_file():
            files.append({"name": f.name, "bytes": f.stat().st_size,
                          "kind": ("json" if f.suffix == ".json" else "text")})
    return {"ok": True, "id": inc_id, "manifest": manifest,
            "summary": _read_incident_meta(d), "files": files,
            "vault_path": str(FORENSIC_VAULT / inc_id)}


def incident_file(inc_id: str, name: str) -> Optional[Path]:
    if "/" in inc_id or ".." in inc_id or "/" in name or ".." in name:
        return None
    for base in (_incident_base(), EVIDENCE_INCIDENTS):
        p = base / inc_id / name
        if p.exists() and p.is_file():
            return p
    return None

XAPP_NS = "ricxapp"
# canonical xApp id (== app label) -> pod-name prefix
XAPPS = ["ricxapp-kpimon-go", "ricxapp-trafficxapp", "ricxapp-hw-go", "ricxapp-hw-python"]
_KUBELET_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
T2_XAPP = "ricxapp-kpimon-go"  # only xApp the T2 resource detector monitors
T2_STATE_FILE = Path(os.environ.get("T2_STATE_FILE", "/var/lib/ztx-t2-state/latest.json"))
PROM_URL = os.environ.get(
    "PROM_URL",
    "http://r4-infrastructure-prometheus-server.ricplt.svc.cluster.local",
)
_SELF_URL = f"http://127.0.0.1:{os.environ.get('PORT', '5000')}"
# a real, already-locally-cached image (no pull needed) with wget+nc+python3
# for the throwaway network-verification probe pod - see verify_isolation().
_PROBE_IMAGE = os.environ.get("ZTX_PROBE_IMAGE", "127.0.0.1:80/hw-python:latest")

# --------------------------------------------------------------------------
# metrics collector
# --------------------------------------------------------------------------
_METRICS: Dict[str, Dict[str, Any]] = {}
_PREV_NET: Dict[str, Dict[str, float]] = {}
_METRICS_LOCK = threading.Lock()
_NODE_IP: Optional[str] = None
_COLLECTOR_STARTED = False
METRICS_INTERVAL_SECONDS = float(os.environ.get("DASH_METRICS_INTERVAL", "2.0"))


def _resolve_node_ip() -> Optional[str]:
    global _NODE_IP
    if _NODE_IP:
        return _NODE_IP
    # 1) downward-API env (set on the deployment), else 2) k8s API
    ip = os.environ.get("HOST_IP") or os.environ.get("NODE_IP")
    if not ip:
        try:
            nodes = CORE.list_node().items
            for n in nodes:
                for a in (n.status.addresses or []):
                    if a.type == "InternalIP":
                        ip = a.address
                        break
                if ip:
                    break
        except Exception:
            ip = None
    _NODE_IP = ip
    return ip


def _kubelet_summary() -> Optional[Dict[str, Any]]:
    ip = _resolve_node_ip()
    if not ip:
        return None
    try:
        with open(_KUBELET_TOKEN_PATH) as fh:
            token = fh.read().strip()
    except Exception:
        token = ""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        f"https://{ip}:10250/stats/summary",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _canonical(pod_name: str) -> Optional[str]:
    for x in XAPPS:
        if pod_name.startswith(x):
            return x
    return None


def _collect_once() -> None:
    summary = _kubelet_summary()
    if not summary:
        return
    now = time.time()
    for pod in summary.get("pods", []):
        ref = pod.get("podRef", {})
        if ref.get("namespace") != XAPP_NS:
            continue
        xid = _canonical(ref.get("name", ""))
        if not xid:
            continue
        cpu = (pod.get("cpu") or {}).get("usageNanoCores") or 0
        mem = (pod.get("memory") or {}).get("workingSetBytes") or 0
        net = pod.get("network") or {}
        rx_b = net.get("rxBytes") or 0
        tx_b = net.get("txBytes") or 0

        rx_rate = tx_rate = 0.0
        prev = _PREV_NET.get(xid)
        if prev:
            dt = max(0.5, now - prev["ts"])
            rx_rate = max(0.0, (rx_b - prev["rx"]) / dt / 1024.0)   # KB/s
            tx_rate = max(0.0, (tx_b - prev["tx"]) / dt / 1024.0)
        _PREV_NET[xid] = {"rx": rx_b, "tx": tx_b, "ts": now}

        with _METRICS_LOCK:
            _METRICS[xid] = {
                "xapp": xid,
                "pod": ref.get("name"),
                "cpu_millicores": round(cpu / 1_000_000.0, 2),
                "mem_mb": round(mem / 1_000_000.0, 2),
                "rx_kbps": round(rx_rate, 2),
                "tx_kbps": round(tx_rate, 2),
                "ts": now,
            }


def _collector_loop() -> None:
    while True:
        try:
            _collect_once()
        except Exception:
            traceback.print_exc()
        time.sleep(METRICS_INTERVAL_SECONDS)


def start_metrics_collector() -> None:
    global _COLLECTOR_STARTED
    if _COLLECTOR_STARTED:
        return
    _COLLECTOR_STARTED = True
    t = threading.Thread(target=_collector_loop, name="ztx-dash-metrics", daemon=True)
    t.start()
    print("ZTX_DASHBOARD_METRICS_COLLECTOR_STARTED node=%s" % _resolve_node_ip())


# --------------------------------------------------------------------------
# attack launcher (whitelisted commands, real exec -> real Falco pipeline)
# --------------------------------------------------------------------------
# id -> {cmd, label, rule, scope}  scope: 'all' works on any xApp; 'kpimon' only
ATTACK_CATALOG = {
    "ZTX-A1":  {"cmd": ["sh", "-c", "sleep 0.5"],                          "label": "Unexpected Shell",          "rule": "R-CRIT-01", "tech": "T1059", "scope": "all"},
    "ZTX-A2":  {"cmd": ["cat", "/etc/passwd"],                             "label": "Sensitive File Access",     "rule": "R-CRIT-02", "tech": "T1552", "scope": "all"},
    "ZTX-A3":  {"cmd": ["cat", "/var/run/secrets/kubernetes.io/serviceaccount/token"], "label": "SA Token Access", "rule": "ZTX-LM-01", "tech": "T1552.007", "scope": "all"},
    # External egress made universal: bash /dev/tcp fires a real connect(2) to an
    # external host on every xApp (all four ship bash). Bounded to ~1s so the exec
    # never hangs on a blocked-egress SYN. bash (not a "tool") keeps the primary
    # signal external_egress rather than malicious_tool_execution.
    "ZTX-A8":  {"cmd": ["bash", "-c", "(exec 3<>/dev/tcp/8.8.8.8/53) & p=$!; sleep 1; kill $p 2>/dev/null; true"], "label": "External Egress", "rule": "R-CRIT-04", "tech": "T1048", "scope": "all"},
    # Malicious tool execution: execve of a known attack/probing tool. perl ships in
    # all four containers and is in the ZTX-A6 tool list -> maps to ZTX-LM-02 (critical).
    "ZTX-A6":  {"cmd": ["perl", "-e", "0"], "label": "Malicious Tool Execution", "rule": "ZTX-LM-02", "tech": "T1105", "scope": "all"},
    "ZTX-A11": {"cmd": ["sh", "-c", "cat /etc/svid/svid.0.pem 2>/dev/null || cat /run/spire/sockets/* 2>/dev/null || cat /spiffe-workload-api/* 2>/dev/null"], "label": "SVID Material Access", "rule": "ZTX-A11", "tech": "T1552", "scope": "all"},
    "ZTX-A12": {"cmd": ["sh", "-c", "chmod 777 /opt/ric/config/config-file.json 2>/dev/null || chmod 777 /etc/hostname"], "label": "Config Tamper", "rule": "ZTX-A12", "tech": "T1565", "scope": "all"},
    # Container escape: openat on a container-runtime socket path. Fires ZTX-LM-03
    # even when the socket is absent (ENOENT openat still carries the path) -
    # verified live 2026-08-25. sh ships everywhere.
    "ZTX-LM-03": {"cmd": ["sh", "-c", "head -c1 /run/containerd/containerd.sock 2>/dev/null; head -c1 /var/run/docker.sock 2>/dev/null; head -c1 /var/run/crio/crio.sock 2>/dev/null; true"], "label": "Container Escape Attempt", "rule": "ZTX-LM-03", "tech": "T1611", "scope": "all"},

    # ---- T2 resource-anomaly attacks (kpimon-go only; detected by the node
    # ztx_t2_collector via the pod cgroup, NOT Falco). CRITICAL: launched with
    # `setsid stress-ng ...` - a bare binary exec, NOT a shell. A shell wrapper
    # (sh -c / nohup ...) would trip Falco's ZTX-A1 unexpected_shell rule and
    # isolate kpimon via the FALCO path before the T2 detector ever confirms,
    # defeating the whole point of a resource-detection demo (verified live
    # 2026-08-25). setsid also detaches the process so it survives the exec
    # stream close and runs its full --timeout window. Only single-invocation
    # scenarios are offered - multi-step shapes (staircase/burst) need a shell
    # loop and would re-introduce the Falco confound. Memory-exhaustion scenario
    # deliberately omitted. Flow: resource_anomaly_t2_elevated (SUSPICIOUS) ->
    # 6-of-8 + CPU gate (~25s) -> resource_anomaly_t2 (COMPROMISED, DWELL_30S)
    # -> auto-isolate (T2_AUTO_CONTAIN).
    # A1/A2 are single-invocation stress-ng runs. A3/A4 are multi-step shapes
    # driven by a "steps" list: the backend runs each step as its OWN bare
    # `setsid stress-ng` exec (NO shell), sleeping between steps in a background
    # thread - so a shape scenario never needs an in-container shell loop and
    # never trips Falco. Each step: {load, dur, [vm], cooldown}. stress-ng's own
    # --timeout stops each step; the thread sleeps dur(+cooldown) before the next.
    "T2-A1": {"kind": "resource", "scope": "kpimon", "rule": "R-T2-01", "tech": "T1499",
              "label": "A1 · CPU Exhaustion",
              "desc": "Sustained CPU flood - stress-ng --cpu-load 20% for 220s. T2 flags an anomaly in ~10s, confirms after the ~60s 6-of-8 corroboration window (COMPROMISED), then a 30s dwell -> auto-isolation (~2 min end-to-end). The long window ensures the full detect->dwell->isolate cycle completes on the live, CPU-capped kpimon.",
              "cmd": ["setsid", "stress-ng", "--cpu", "1", "--cpu-load", "20", "--timeout", "220s", "--metrics-brief"]},
    "T2-A2": {"kind": "resource", "scope": "kpimon", "rule": "R-T2-01", "tech": "T1499",
              "label": "A2 · CPU + Memory Combined Stealth",
              "desc": "Combined CPU(20%)+memory(vm 24M)+disk(16M) pressure for 220s - a fuller-spectrum resource attack that still confirms and isolates after the corroboration window + 30s dwell.",
              "cmd": ["setsid", "stress-ng", "--cpu", "1", "--cpu-load", "20", "--vm", "1", "--vm-bytes", "24M", "--hdd", "1", "--hdd-bytes", "16M", "--timeout", "220s", "--metrics-brief"]},
    "T2-A3": {"kind": "resource", "scope": "kpimon", "rule": "R-T2-02", "tech": "T1499",
              "label": "A3 · Low & Slow Stealth",
              "desc": "Step-wise CPU escalation (loads 20->28->36->40%, 45s each) - a low-and-slow climb probing the confirmation window. Detected by the MEWMA drift, not a fixed threshold.",
              "steps": [{"load": 20, "dur": 45}, {"load": 28, "dur": 45}, {"load": 36, "dur": 45}, {"load": 40, "dur": 45}]},
    "T2-A4": {"kind": "resource", "scope": "kpimon", "rule": "R-T2-02", "tech": "T1499",
              "label": "A4 · Burst Pulse Train",
              "desc": "Repeated CPU bursts (5/10/20/40/60s at 100%, 20s cooldown between) testing the 6-of-8 confirmation gate against transient spikes.",
              "steps": [{"load": 100, "dur": 5, "cooldown": 20}, {"load": 100, "dur": 10, "cooldown": 20}, {"load": 100, "dur": 20, "cooldown": 20}, {"load": 100, "dur": 40, "cooldown": 20}, {"load": 100, "dur": 60, "cooldown": 20}]},
    "T2-STOP": {"kind": "control", "scope": "kpimon", "rule": "cleanup", "tech": "-",
                "label": "Stop Resource Load",
                "desc": "Kill any running stress-ng in kpimon-go (cleanup between demo runs; does not clear an already-applied containment - use restore for that).",
                "cmd": ["pkill", "-KILL", "-f", "stress-ng"]},
}


def _main_container(pod) -> Optional[str]:
    try:
        for c in pod.spec.containers:
            if c.name != "renew-svid" and "svid" not in c.name:
                return c.name
    except Exception:
        pass
    return None


def _running_pod(xapp: str):
    try:
        pods = CORE.list_namespaced_pod(XAPP_NS, label_selector=f"app={xapp}").items
    except Exception:
        return None
    running = [p for p in pods if (p.status.phase or "") == "Running" and not p.metadata.deletion_timestamp]
    return (running or pods or [None])[0]


def _exec_in_pod(pod_name: str, container: str, cmd: List[str], timeout: float = 8.0) -> str:
    """One bare exec into an xApp container (no shell). Returns stdout/err text.
    A stream timeout is not an error for detached (setsid) commands."""
    resp = stream(
        EXEC_CORE.connect_get_namespaced_pod_exec,
        name=pod_name, namespace=XAPP_NS, container=container, command=cmd,
        stderr=True, stdin=False, stdout=True, tty=False, _request_timeout=timeout,
    )
    return resp or ""


def _stressng_step_cmd(load, dur, vm=None):
    cmd = ["setsid", "stress-ng", "--cpu", "1", "--cpu-load", str(load)]
    if vm:
        cmd += ["--vm", "1", "--vm-bytes", str(vm)]
    cmd += ["--timeout", "%ds" % int(dur), "--metrics-brief"]
    return cmd


def _run_resource_sequence(pod_name: str, container: str, steps: List[Dict[str, Any]]) -> None:
    """Drive a multi-step resource shape from the backend: each step is its own
    detached `setsid stress-ng` exec (no in-container shell -> no Falco), with the
    inter-step spacing done here. Runs in a daemon thread."""
    for st in steps:
        dur = int(st.get("dur", 45))
        try:
            _exec_in_pod(pod_name, container, _stressng_step_cmd(st.get("load", 20), dur, st.get("vm")), timeout=4.0)
        except Exception:
            pass  # setsid detaches; a stream timeout/close is expected
        time.sleep(dur + int(st.get("cooldown", 0)))


def _attack_cmd_str(v: Dict[str, Any]) -> str:
    """Human-readable rendering of the REAL command an attack runs."""
    if v.get("steps"):
        return "setsid stress-ng  (%d-step CPU load shape)" % len(v["steps"])
    return " ".join(v.get("cmd", []) or [])


def launch_attack(xapp: str, attack_id: str) -> Dict[str, Any]:
    spec = ATTACK_CATALOG.get(attack_id)
    if not spec:
        return {"launched": False, "error": "unknown_attack", "attack": attack_id}
    if xapp not in XAPPS:
        return {"launched": False, "error": "unknown_xapp", "xapp": xapp}
    pod = _running_pod(xapp)
    if not pod:
        return {"launched": False, "error": "no_running_pod", "xapp": xapp}
    container = _main_container(pod)
    if not container:
        return {"launched": False, "error": "no_container", "xapp": xapp}

    # Multi-step resource shapes (A3/A4): sequence bare setsid execs in a thread.
    if spec.get("steps"):
        threading.Thread(
            target=_run_resource_sequence,
            args=(pod.metadata.name, container, spec["steps"]),
            daemon=True,
        ).start()
        return {
            "launched": True, "attack": attack_id, "label": spec["label"], "rule": spec["rule"], "tech": spec["tech"],
            "xapp": xapp, "pod": pod.metadata.name, "container": container,
            "command": _attack_cmd_str(spec), "exec_api": "kubernetes pods/exec",
            "sequence": True, "steps": len(spec["steps"]),
            "output": "sequence started (%d steps)" % len(spec["steps"]),
            "time": time.strftime("%H:%M:%S", time.gmtime()),
        }

    try:
        out = _exec_in_pod(pod.metadata.name, container, spec["cmd"], timeout=10.0)
        return {
            "launched": True, "attack": attack_id, "label": spec["label"], "rule": spec["rule"], "tech": spec["tech"],
            "xapp": xapp, "pod": pod.metadata.name, "container": container,
            "command": _attack_cmd_str(spec), "exec_api": "kubernetes pods/exec",
            "output": (out or "")[:400],
            "time": time.strftime("%H:%M:%S", time.gmtime()),
        }
    except Exception as exc:
        return {"launched": False, "error": str(exc), "xapp": xapp, "attack": attack_id}


# --------------------------------------------------------------------------
# RAN / E2 status (open5GS + gNB + UE run outside k8s; the concrete signal
# is the gNB's E2 connection, read from e2mgr's nodeb list).
# --------------------------------------------------------------------------
_E2MGR_URL = os.environ.get(
    "E2MGR_URL",
    "http://service-ricplt-e2mgr-http.ricplt.svc.cluster.local:3800",
)
_RAN_CACHE: Dict[str, Any] = {"ts": 0.0, "data": None}
_RAN_CACHE_TTL = 3.0


def _ran_status() -> Dict[str, Any]:
    now = time.time()
    if _RAN_CACHE["data"] is not None and (now - _RAN_CACHE["ts"]) < _RAN_CACHE_TTL:
        return _RAN_CACHE["data"]
    nodebs: List[Dict[str, Any]] = []
    try:
        req = urllib.request.Request(_E2MGR_URL + "/v1/nodeb/states")
        with urllib.request.urlopen(req, timeout=3) as resp:
            raw = json.loads(resp.read().decode("utf-8")) or []
        for n in raw:
            nodebs.append({
                "name": n.get("inventoryName"),
                "status": n.get("connectionStatus"),
                "plmn": (n.get("globalNbId") or {}).get("plmnId"),
            })
    except Exception as exc:
        nodebs = []
        _RAN_CACHE["err"] = str(exc)
    present = len(nodebs) > 0
    connected = any((nb.get("status") == "CONNECTED") for nb in nodebs)
    status = (nodebs[0].get("status") if nodebs else "ABSENT")
    # Staged, from the one real signal (e2mgr). open5GS/UE run outside k8s and
    # are not directly observable, so: core+gNB "up" once the gNB registers
    # (present), E2 link + UE "up" once the gNB is CONNECTED.
    data = {
        "ok": True,
        "connected": connected,
        "core": present,          # open5GS (inferred: a gNB only registers after the core is up)
        "gnb": present,           # gNB process registered with e2mgr
        "e2": connected,          # E2 link established to the RIC
        "ue": connected,          # UE attached (inferred from a live E2/KPM session)
        "status": status,
        "nodebs": nodebs,
        "gnb_name": (nodebs[0]["name"] if nodebs else None),
        "plmn": (nodebs[0].get("plmn") if nodebs else None),
        "time": now,
    }
    _RAN_CACHE["ts"] = now
    _RAN_CACHE["data"] = data
    return data


# --------------------------------------------------------------------------
# per-xApp detail page - T2 resource state, Falco/T2 events, containment
# timing, container logs, long-range Prometheus metrics, and a real
# bidirectional network-isolation verification.
# --------------------------------------------------------------------------

def _read_t2_state() -> Optional[Dict[str, Any]]:
    """Read the T2 collector's live state file (hostPath-mounted). Only
    meaningful for kpimon-go - that is the only pod the collector watches."""
    try:
        raw = T2_STATE_FILE.read_text(encoding="utf-8")
        return json.loads(raw)
    except Exception:
        return None


def _t2_resource_label(t2: Optional[Dict[str, Any]]) -> str:
    """Which resource dimension is actually elevated, read off the frozen
    model's own per-feature normalized excess (directional_excess) -
    M1=cpu, M4=memory growth, M5/M6=network. CPU is the only live decision
    gate (per v5_frozen_gate_manifest.json), so this label is informational,
    not a second decision path.

    M4 (memory growth) is DELIBERATELY excluded here even though its excess
    is exposed in the raw panel: the frozen gate manifest itself documents
    M4 as an "unreliable feature, not tuned around" that "spikes to values
    physically inconsistent with the concurrent M3 trajectory on BOTH benign
    and attack data" - confirmed live 2026-08-25 (M4 excess sat around 100
    on a completely idle baseline while M1/M5/M6 stayed near 0). Labeling
    off M4 would call a normal baseline "Memory pressure"."""
    if not t2 or not t2.get("directional_excess"):
        return "—"
    exc = t2["directional_excess"]
    cpu = float(exc.get("M1_log1p", 0) or 0)
    net = max(float(exc.get("M5_log1p", 0) or 0), float(exc.get("M6_log1p", 0) or 0))
    parts = []
    if cpu > 0.15:
        parts.append("CPU")
    if net > 0.15:
        parts.append("Network")
    if not parts:
        return "Baseline (no dimension elevated)"
    return " + ".join(parts) + " pressure"


def _trust_state_snapshot() -> Dict[str, Any]:
    """Loopback read of /trust-state - the SAME state the frontend polls -
    so this module never needs to import app.py (which would re-execute it
    as a second module, a fresh CSM_STATE, since app.py runs as __main__)."""
    try:
        req = urllib.request.Request(_SELF_URL + "/trust-state")
        with urllib.request.urlopen(req, timeout=4) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {}


def _containment_timing_for(xapp: str) -> Optional[Dict[str, Any]]:
    try:
        import containment_orchestrator as _co
        return dict((getattr(_co, "_ZTX_LAST_CONTAINMENT", {}) or {}).get(xapp, {}))
    except Exception:
        return None


def xapp_detail(xid: str) -> Dict[str, Any]:
    if xid not in XAPPS:
        return {"ok": False, "error": "unknown_xapp", "xapp": xid}

    snap = _trust_state_snapshot()
    entry = next((x for x in (snap.get("xapps") or []) if x.get("xapp") == xid), {})
    events = [e for e in (snap.get("recent_events") or []) if e.get("xapp") == xid][:30]

    t2 = _read_t2_state() if xid == T2_XAPP else None
    t2_gauges = None
    if t2:
        t2_gauges = {
            "score": {
                "value": t2.get("t2_pressure_score"),
                "warning_limit": t2.get("warning_limit"),
                "upper_limit": t2.get("upper_limit"),
            },
            "cpu_rate_gate": {
                "hits": t2.get("cpu_exceed_hits"),
                "window": t2.get("cpu_exceed_window") or t2.get("cpu_gate_window_l"),
                "floor_millicores": t2.get("cpu_gate_floor_millicores"),
                "rate_threshold": t2.get("cpu_gate_rate_r"),
                "hit": bool(t2.get("cpu_gate_hit")),
                "current_millicores": t2.get("m1_cpu_millicores"),
            },
            "confirmation": {
                "hits": t2.get("upper_hits"),
                "window": t2.get("upper_window") or t2.get("confirmation_l"),
                "required": t2.get("confirmation_k"),
                "confirmed": bool(t2.get("confirmed_upper_6of8")),
            },
            "resource_label": _t2_resource_label(t2),
            "throttle": {
                "active": bool(t2.get("throttle_active") or t2.get("throttled")),
                "quota_millicores": t2.get("quota_millicores"),
            },
            "sample_quality": t2.get("sample_quality"),
            "eligible": t2.get("eligible"),
            "raw": {
                "m1_cpu_millicores": t2.get("m1_cpu_millicores"),
                "m4_memory_growth_bytes_per_s": t2.get("m4_memory_growth_bytes_per_s"),
                "m5_network_rx_bytes_per_s": t2.get("m5_network_rx_bytes_per_s"),
                "m6_network_tx_bytes_per_s": t2.get("m6_network_tx_bytes_per_s"),
            },
        }

    return {
        "ok": True,
        "xapp": xid,
        "state": entry.get("state", "NORMAL"),
        "last_signal": entry.get("last_signal"),
        "last_source": entry.get("last_source"),
        "last_update": entry.get("last_update"),
        "rule_ids": entry.get("rule_ids") or [],
        "isolation_dwell_seconds_remaining": entry.get("isolation_dwell_seconds_remaining"),
        "events": events,
        "t2": t2_gauges,
        "containment": _containment_timing_for(xid),
        "time": time.time(),
    }


# --------------------------------------------------------------------------
# container logs
# --------------------------------------------------------------------------
def xapp_container_logs(xid: str, container: str, tail: int) -> Dict[str, Any]:
    if xid not in XAPPS:
        return {"ok": False, "error": "unknown_xapp"}
    pod = _running_pod(xid)
    if not pod:
        return {"ok": False, "error": "no_running_pod", "xapp": xid}
    if container == "renew-svid":
        real_container = "renew-svid"
    else:
        real_container = _main_container(pod) or ""
    try:
        text = CORE.read_namespaced_pod_log(
            name=pod.metadata.name, namespace=XAPP_NS, container=real_container,
            tail_lines=max(1, min(tail, 2000)), timestamps=True,
        )
        lines = (text or "").splitlines()
        return {"ok": True, "xapp": xid, "pod": pod.metadata.name, "container": real_container, "lines": lines}
    except ApiException as exc:
        return {"ok": False, "error": f"k8s_api_{exc.status}", "detail": str(exc.reason), "xapp": xid, "container": real_container}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "xapp": xid, "container": real_container}


# --------------------------------------------------------------------------
# long-range metrics via the cluster's own Prometheus (cAdvisor container_*
# series, 15d retention) - the correct tool for real historical graphs,
# instead of re-deriving a short in-process buffer.
# --------------------------------------------------------------------------
# Live-tested against this cluster's actual Prometheus (2026-08-25): rate()
# returned empty results at 1m/2m/3m lookback windows and only started
# working at [5m] - this cAdvisor scrape target's real cadence is sparser
# than the usual 15-30s default, so a short rate() window frequently has
# fewer than 2 samples. [5m] is the smallest window confirmed to reliably
# return data; smoothing is the honest cost of this cluster's real scrape
# interval, not a query bug.
_RATE_WINDOW = "5m"
_PROM_QUERIES = {
    "cpu": ('sum(rate(container_cpu_usage_seconds_total{{namespace="ricxapp",pod=~"{pod}-.*",'
            'container!="",container!="POD"}}[' + _RATE_WINDOW + '])) * 1000', "mC"),
    "mem": ('sum(container_memory_working_set_bytes{{namespace="ricxapp",pod=~"{pod}-.*",'
            'container!="",container!="POD"}}) / 1048576', "MB"),
    "rx": ('sum(rate(container_network_receive_bytes_total{{namespace="ricxapp",pod=~"{pod}-.*"}}[' + _RATE_WINDOW + '])) / 1024', "KB/s"),
    "tx": ('sum(rate(container_network_transmit_bytes_total{{namespace="ricxapp",pod=~"{pod}-.*"}}[' + _RATE_WINDOW + '])) / 1024', "KB/s"),
}


def xapp_metrics_range(xid: str, metric: str, range_s: int, step_s: int) -> Dict[str, Any]:
    if xid not in XAPPS:
        return {"ok": False, "error": "unknown_xapp"}
    if metric not in _PROM_QUERIES:
        return {"ok": False, "error": "unknown_metric", "known": list(_PROM_QUERIES)}
    tmpl, unit = _PROM_QUERIES[metric]
    promql = tmpl.format(pod=xid)
    now = time.time()
    start = now - max(60, min(range_s, 6 * 3600))
    step = max(5, min(step_s, 120))
    qs = urllib.parse.urlencode({"query": promql, "start": start, "end": now, "step": step})
    url = f"{PROM_URL}/api/v1/query_range?{qs}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=6) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        result = (body.get("data") or {}).get("result") or []
        points = []
        if result:
            for t, v in result[0].get("values", []):
                try:
                    points.append({"t": t, "v": float(v)})
                except (TypeError, ValueError):
                    pass
        return {"ok": True, "xapp": xid, "metric": metric, "unit": unit, "points": points,
                "range_s": range_s, "step_s": step, "query": promql}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "xapp": xid, "metric": metric, "query": promql}


# --------------------------------------------------------------------------
# network isolation verification - real, multi-method, not simulated.
#
# Method 1 (control-plane evidence): the pod's live quarantine label +
# the SAME iptables -C check apply_quarantine's own verification path uses
# (containment_orchestrator.verify_direct_network_isolation) - checks the
# actual ZTX-DIRECT-QUARANTINE DROP rules for this pod's IP, both directions.
#
# Method 2 (active behavioral evidence): a throwaway, unlabeled probe pod
# (image reused from an already-locally-cached xApp image - no pull, starts
# in ~1-2s) attempts a real TCP connect to the target pod's IP:port with
# `nc -z`. The probe pod's name deliberately does NOT match any of Falco's
# ztx_controlled_xapp_pod name prefixes, so it is invisible to the xApp
# security rules regardless of what it does.
#
# Method 3 (reverse active evidence, target -> outside): only attempted when
# the target is ALREADY COMPROMISED/ISOLATED (an extra Falco signal on an
# already-contained pod is inert - the sticky-COMPROMISED rule keeps state),
# and only if that xApp's own image actually has a network tool (kpimon-go/
# hw-python have wget; hw-go/trafficxapp do not - reported honestly, not
# faked).
# --------------------------------------------------------------------------
def _target_port_for(pod) -> int:
    try:
        for c in pod.spec.containers:
            if c.name == "renew-svid":
                continue
            for p in (c.ports or []):
                if p.name == "http":
                    return int(p.container_port)
        for c in pod.spec.containers:
            if c.name != "renew-svid" and c.ports:
                return int(c.ports[0].container_port)
    except Exception:
        pass
    return 8080


def _create_probe_pod() -> str:
    name = "ztx-probe-" + uuid.uuid4().hex[:10]
    body = V1Pod(
        metadata=V1ObjectMeta(name=name, namespace=XAPP_NS, labels={"zt-xguard.io/probe": "true"}),
        spec=V1PodSpec(
            containers=[V1Container(name="probe", image=_PROBE_IMAGE, image_pull_policy="IfNotPresent", command=["sleep", "120"])],
            restart_policy="Never",
            automount_service_account_token=False,
            active_deadline_seconds=110,
        ),
    )
    CORE.create_namespaced_pod(namespace=XAPP_NS, body=body)
    deadline = time.time() + 15
    while time.time() < deadline:
        p = CORE.read_namespaced_pod(name=name, namespace=XAPP_NS)
        if (p.status.phase or "") == "Running":
            return name
        time.sleep(0.5)
    return name  # best-effort even if not yet confirmed Running


def _delete_probe_pod(name: str) -> None:
    try:
        CORE.delete_namespaced_pod(name=name, namespace=XAPP_NS, grace_period_seconds=0)
    except Exception:
        pass


def _exec_argv(pod_name: str, container: str, argv: List[str], timeout: float = 6.0) -> Dict[str, Any]:
    """Exec argv (no shell) and return the REMOTE COMMAND's real exit code,
    not just whether the exec channel opened. The simple stream() wrapper
    used elsewhere in this file for one-way attack commands never surfaces
    the remote exit status (a failing `nc`/`wget` inside the container is
    NOT a Python exception - stream() would happily return "ok" even though
    the command itself failed). Confirmed live 2026-08-25: this bug made
    verify_isolation() report every connectivity probe as "reachable"
    regardless of the real result, because it only checked "did exec open".
    Uses the WSClient form (_preload_content=False), the same pattern
    containment_orchestrator.py's own _ztx_exec_iptables relies on for a
    trustworthy exit code."""
    t0 = time.time()
    try:
        resp = stream(
            EXEC_CORE.connect_get_namespaced_pod_exec,
            name=pod_name, namespace=XAPP_NS, container=container, command=argv,
            stderr=True, stdin=False, stdout=True, tty=False, _preload_content=False,
        )
        resp.run_forever(timeout=timeout)
        exit_code = resp.returncode
        output = resp.read_all()
        resp.close()
        return {"ok": exit_code == 0, "exit_code": exit_code, "output": (output or "").strip()[:300],
                "ms": round((time.time() - t0) * 1000, 1)}
    except Exception as exc:
        return {"ok": False, "exit_code": None, "output": str(exc)[:300], "ms": round((time.time() - t0) * 1000, 1)}


def verify_isolation(xid: str) -> Dict[str, Any]:
    if xid not in XAPPS:
        return {"ok": False, "error": "unknown_xapp"}
    pod = _running_pod(xid)
    if not pod:
        return {"ok": False, "error": "no_running_pod", "xapp": xid}
    pod_ip = getattr(getattr(pod, "status", None), "pod_ip", None)
    if not pod_ip:
        return {"ok": False, "error": "no_pod_ip", "xapp": xid}
    port = _target_port_for(pod)
    labels = dict(pod.metadata.labels or {})
    transcript: List[Dict[str, str]] = []

    # Method 1: control-plane evidence.
    transcript.append({"cmd": f"kubectl get pod {pod.metadata.name} -n ricxapp -o labels", "out": json.dumps(labels)})
    control_plane = None
    try:
        import containment_orchestrator as _co
        control_plane = _co.verify_direct_network_isolation(pod_ip)
    except Exception as exc:
        control_plane = {"checked": False, "error": str(exc)}
    transcript.append({
        "cmd": f"iptables -t raw -C ZTX-DIRECT-QUARANTINE -s/-d {pod_ip} -j DROP  (egress + ingress)",
        "out": json.dumps(control_plane),
    })

    # Method 2: active ingress probe from a throwaway, unlabeled pod.
    probe_name = _create_probe_pod()
    ingress_cmd = ["nc", "-z", "-w", "3", pod_ip, str(port)]
    ingress = _exec_argv(probe_name, "probe", ingress_cmd, timeout=6.0)
    transcript.append({
        "cmd": f"[probe pod] nc -z -w3 {pod_ip} {port}",
        "out": (ingress.get("output") or "(no output)") + ("  -> CONNECTED" if ingress["ok"] else "  -> FAILED/TIMED OUT"),
    })
    ingress_reachable = bool(ingress.get("ok"))
    _delete_probe_pod(probe_name)

    # Method 3: reverse active probe from INSIDE the xApp toward an in-cluster RIC
    # platform peer it is legitimately supposed to reach. A healthy xApp reaches
    # it; an isolated one (deny-all egress + iptables DROP) cannot. Using an
    # in-cluster target (not 8.8.8.8) keeps the probe OFFLINE-SAFE and avoids
    # emitting the external-egress attack signature. Only run when already
    # contained, and only if the image has a tool for it.
    # Default: the xApp's real E2 peer (e2term RMR) - a legitimate RIC platform
    # endpoint every xApp talks to. Override with env ZTX_EGRESS_PROBE=host:port.
    _eg = os.environ.get("ZTX_EGRESS_PROBE", "service-ricplt-e2term-rmr-alpha.ricplt.svc.cluster.local:4561")
    eg_host, _, eg_port = _eg.partition(":"); eg_port = eg_port or "4561"
    egress = {"attempted": False, "target": _eg, "reason": "target not COMPROMISED/ISOLATED - skipped to avoid probing a healthy pod"}
    snap = _trust_state_snapshot()
    cur_state = next((x.get("state") for x in (snap.get("xapps") or []) if x.get("xapp") == xid), "NORMAL")
    if cur_state in ("COMPROMISED", "ISOLATED"):
        container = _main_container(pod) or ""
        # cheap presence check without a shell: try nc, else wget
        nc_check = _exec_argv(pod.metadata.name, container, ["nc", "-h"], timeout=2.0)
        if nc_check.get("ok") or "usage" in (nc_check.get("output") or "").lower():
            r = _exec_argv(pod.metadata.name, container, ["nc", "-z", "-w", "3", eg_host, eg_port], timeout=5.0)
            egress = {"attempted": True, "tool": "nc", "target": _eg, "reachable": bool(r.get("ok")), "ms": r.get("ms")}
            transcript.append({"cmd": f"[{xid}] nc -z -w3 {eg_host} {eg_port}", "out": (r.get("output") or "") + ("  -> CONNECTED" if r.get("ok") else "  -> FAILED/TIMED OUT")})
        else:
            wget_check = _exec_argv(pod.metadata.name, container, ["wget", "--help"], timeout=2.0)
            if wget_check.get("ok") or "usage" in (wget_check.get("output") or "").lower():
                r = _exec_argv(pod.metadata.name, container, ["wget", "-T", "3", "-O", "/dev/null", f"http://{eg_host}:{eg_port}/"], timeout=6.0)
                egress = {"attempted": True, "tool": "wget", "target": _eg, "reachable": bool(r.get("ok")), "ms": r.get("ms")}
                transcript.append({"cmd": f"[{xid}] wget -T3 -O /dev/null http://{eg_host}:{eg_port}/", "out": (r.get("output") or "") + ("  -> CONNECTED" if r.get("ok") else "  -> FAILED/TIMED OUT")})
            else:
                egress = {"attempted": False, "reason": f"{xid}'s image has no nc/wget - not testable from inside this container"}
                transcript.append({"cmd": f"[{xid}] probe for nc/wget", "out": "neither tool present in this xApp's image"})

    overall_isolated = bool(control_plane.get("blocked")) and not ingress_reachable

    return {
        "ok": True,
        "xapp": xid,
        "pod": pod.metadata.name,
        "pod_ip": pod_ip,
        "port": port,
        "checked_state": cur_state,
        "control_plane": control_plane,
        "active_ingress": {"reachable": ingress_reachable, "tool": "nc", "target": f"{pod_ip}:{port}", "ms": ingress.get("ms")},
        "active_egress": egress,
        "overall_isolated": overall_isolated,
        "transcript": transcript,
        "time": time.time(),
    }


# --------------------------------------------------------------------------
# route registration
# --------------------------------------------------------------------------
def register_dashboard_api(APP) -> None:
    # Cache-busting token for static assets (soc.css / soc.js). Changes on every
    # process start (i.e. every image rollout), so the browser always fetches the
    # freshly deployed CSS/JS instead of a stale cached copy.
    try:
        APP.jinja_env.globals["ASSET_VER"] = str(int(time.time()))
    except Exception:
        pass

    @APP.route("/csm/xapps/metrics", methods=["GET"])
    def ztx_xapps_metrics():
        with _METRICS_LOCK:
            data = {k: dict(v) for k, v in _METRICS.items()}
        return jsonify({
            "ok": True,
            "metrics": data,
            "xapps": XAPPS,
            "interval_s": METRICS_INTERVAL_SECONDS,
            "node": _NODE_IP,
            "time": time.time(),
        })

    @APP.route("/csm/attack/catalog", methods=["GET"])
    def ztx_attack_catalog():
        return jsonify({
            "ok": True,
            "xapps": XAPPS,
            "attacks": [
                {"id": k, "label": v["label"], "rule": v["rule"], "tech": v["tech"], "scope": v["scope"],
                 "kind": v.get("kind", "falco"), "desc": v.get("desc", ""), "command": _attack_cmd_str(v)}
                for k, v in ATTACK_CATALOG.items()
            ],
        })

    @APP.route("/csm/attack/launch", methods=["POST"])
    def ztx_attack_launch():
        payload = request.get_json(force=True, silent=True) or {}
        xapp = payload.get("xapp")
        attack_id = payload.get("attack") or payload.get("attack_id")
        result = launch_attack(xapp, attack_id)
        return jsonify(result), (200 if result.get("launched") else 400)

    @APP.route("/csm/ran/status", methods=["GET"])
    def ztx_ran_status():
        return jsonify(_ran_status())

    @APP.route("/csm/incident/timing", methods=["GET"])
    def ztx_incident_timing():
        # per-mechanism real latencies recorded by apply_quarantine (live
        # containment_orchestrator, populated on the last containment per xApp)
        try:
            import containment_orchestrator as _co
            data = {k: dict(v) for k, v in (getattr(_co, "_ZTX_LAST_CONTAINMENT", {}) or {}).items()}
        except Exception as exc:
            data = {}
        return jsonify({"ok": True, "timing": data, "time": time.time()})

    # ---- per-xApp detail page ----
    @APP.route("/csm/xapp/<xid>/detail", methods=["GET"])
    def ztx_xapp_detail(xid):
        return jsonify(xapp_detail(xid))

    @APP.route("/csm/xapp/<xid>/logs", methods=["GET"])
    def ztx_xapp_logs(xid):
        container = request.args.get("container", "main")
        try:
            tail = int(request.args.get("tail", "200"))
        except ValueError:
            tail = 200
        return jsonify(xapp_container_logs(xid, container, tail))

    @APP.route("/csm/xapp/<xid>/metrics_range", methods=["GET"])
    def ztx_xapp_metrics_range(xid):
        metric = request.args.get("metric", "cpu")
        try:
            range_s = int(request.args.get("range_s", "1800"))
            step_s = int(request.args.get("step_s", "15"))
        except ValueError:
            range_s, step_s = 1800, 15
        return jsonify(xapp_metrics_range(xid, metric, range_s, step_s))

    @APP.route("/csm/xapp/<xid>/verify-isolation", methods=["POST"])
    def ztx_xapp_verify_isolation(xid):
        result = verify_isolation(xid)
        return jsonify(result), (200 if result.get("ok") else 400)

    start_vault_sync()

    @APP.route("/csm/policy/posture", methods=["GET"])
    def ztx_policy_posture():
        def _b(v):
            return str(os.environ.get(v, "")).lower() in ("1", "true", "yes", "on")
        enforcement = {
            "auto_quarantine": _b("AUTO_QUARANTINE"),
            "t2_auto_contain": _b("T2_AUTO_CONTAIN"),
            "revoke_spire": _b("REVOKE_SPIRE"),
            "allow_destructive": _b("ALLOW_DESTRUCTIVE_ACTIONS"),
            "containment_mode": os.environ.get("CONTAINMENT_MODE", "service"),
        }
        # per-xApp identity (svid-enabled label) - common zero-trust posture
        identity = {}
        for x in XAPPS:
            pod = _running_pod(x)
            lbl = {}
            if pod:
                lbl = dict((pod.metadata.labels or {}))
            identity[x] = {
                "svid_enabled": lbl.get("zt-xguard.io/svid-enabled") == "true",
                "quarantined": lbl.get("zt-xguard.io/quarantine") == "true",
                "identity_managed": lbl.get("zt-xguard.io/identity-managed") == "true",
            }
        n_incidents = 0
        n_incidents_24h = 0
        try:
            base = _incident_base()
            if base.exists():
                import re as _re
                cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
                for p in base.iterdir():
                    if not p.is_dir():
                        continue
                    n_incidents += 1
                    m = _re.match(r"^(\d{8}T\d{6})Z", p.name)   # incident dirs are named <UTC>Z-...
                    if m:
                        try:
                            dt = datetime.strptime(m.group(1), "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc)
                            if dt >= cutoff:
                                n_incidents_24h += 1
                        except Exception:
                            pass
        except Exception:
            pass
        return jsonify({"ok": True, "enforcement": enforcement, "identity": identity,
                        "incidents_total": n_incidents, "incidents_24h": n_incidents_24h, "time": time.time()})

    @APP.route("/csm/incidents", methods=["GET"])
    def ztx_incidents():
        try:
            lim = int(request.args.get("limit", "300"))
        except ValueError:
            lim = 300
        items = list_incidents(lim)
        return jsonify({"ok": True, "incidents": items, "count": len(items),
                        "vault": str(FORENSIC_VAULT)})

    @APP.route("/csm/incidents/<inc_id>", methods=["GET"])
    def ztx_incident_detail(inc_id):
        return jsonify(incident_detail(inc_id))

    @APP.route("/csm/incidents/<inc_id>/file/<name>", methods=["GET"])
    def ztx_incident_file(inc_id, name):
        p = incident_file(inc_id, name)
        if not p:
            return jsonify({"ok": False, "error": "not_found"}), 404
        if request.args.get("download"):
            return send_file(str(p), as_attachment=True, download_name=name)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500
        return Response(text, mimetype="text/plain; charset=utf-8")

    @APP.route("/csm/live/pulses", methods=["GET"])
    def ztx_live_pulses():
        """Real event signals for the homepage's live animation - so the
        overview visualizes ACTUAL system activity, not a timer-driven
        simulation:
          - svid[xapp]: timestamp of the most recent 'Writing SVID' line in
            that xApp's renew-svid sidecar log = a real per-xApp SVID renewal.
          - kpm: kpimon-go's real work-unit / heartbeat counters from the T2
            collector (increments when it actually processes KPM indications
            and writes to InfluxDB)."""
        out = {"svid": {}, "kpm": None, "time": time.time()}
        for x in XAPPS:
            pod = _running_pod(x)
            if not pod:
                continue
            try:
                txt = CORE.read_namespaced_pod_log(
                    name=pod.metadata.name, namespace=XAPP_NS,
                    container="renew-svid", tail_lines=30, timestamps=True,
                )
                last_ts = None
                for line in (txt or "").splitlines():
                    if "Writing SVID" in line or "IDENTITY RENEWAL REPORT" in line:
                        last_ts = line.split(" ", 1)[0]
                if last_ts:
                    out["svid"][x] = last_ts
            except Exception:
                pass
        t2 = _read_t2_state()
        if t2 and t2.get("activity"):
            a = t2["activity"] or {}
            out["kpm"] = {
                "work_units": a.get("work_units_processed"),
                "heartbeat": a.get("heartbeat_total"),
                "uptime": a.get("uptime_seconds"),
                "eligible": t2.get("eligible"),
            }
        return jsonify(out)
