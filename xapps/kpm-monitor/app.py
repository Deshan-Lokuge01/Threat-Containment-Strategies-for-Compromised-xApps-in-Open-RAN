#!/usr/bin/env python3
import json
import os
import signal
import threading
import time
import traceback
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests
from ricxappframe.rmr import rmr

from lib.asn1.e2sm_kpm_packer import e2sm_kpm_packer


XAPP_NAME = os.getenv("XAPP_NAME", "kpm-monitor")
XAPP_ROLE = os.getenv("XAPP_ROLE", "real-oran-kpm-monitor")

HTTP_PORT = int(os.getenv("HTTP_PORT", "8092"))
RMR_PORT = int(os.getenv("RMR_PORT", "4562"))

POD_IP = os.getenv("POD_IP", "127.0.0.1")
SERVICE_HTTP_HOST = os.getenv("SERVICE_HTTP_HOST", "kpm-monitor.ricxapp.svc.cluster.local")
SERVICE_HTTP_PORT = int(os.getenv("SERVICE_HTTP_PORT", str(HTTP_PORT)))

SUBMGR_URI = os.getenv(
    "SUBMGR_URI",
    "http://ztx-submgr-http.ricplt.svc.cluster.local:8088/ric/v1"
).rstrip("/")

E2MGR_NODEB_STATES_URL = os.getenv(
    "E2MGR_NODEB_STATES_URL",
    "http://service-ricplt-e2mgr-http.ricplt.svc.cluster.local:3800/v1/nodeb/states"
)

E2_NODE_ID = os.getenv("E2_NODE_ID", "gnbd_001_001_00019b_0")
RAN_FUNCTION_ID = int(os.getenv("RAN_FUNCTION_ID", "2"))
KPM_REPORT_STYLE = int(os.getenv("KPM_REPORT_STYLE", "1"))
KPM_REPORT_PERIOD_MS = int(os.getenv("KPM_REPORT_PERIOD_MS", "1000"))
KPM_GRANULARITY_MS = int(os.getenv("KPM_GRANULARITY_MS", "1000"))
KPM_METRICS = [x.strip() for x in os.getenv("KPM_METRICS", "DRB.UEThpUl,DRB.UEThpDl").split(",") if x.strip()]

RMR_MESSAGE_TYPES = {
    12010: "RIC_SUB_REQ",
    12011: "RIC_SUB_RESP",
    12012: "RIC_SUB_FAILURE",
    12020: "RIC_SUB_DEL_REQ",
    12021: "RIC_SUB_DEL_RESP",
    12022: "RIC_SUB_DEL_FAILURE",
    12040: "RIC_CONTROL_REQ",
    12041: "RIC_CONTROL_ACK",
    12042: "RIC_CONTROL_FAILURE",
    12050: "RIC_INDICATION",
}


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.last_heartbeat = time.time()
        self.running = True

        self.e2_node_total = 0
        self.e2_node_connected = 0
        self.e2_node_disconnected = 0
        self.target_e2_connected = False
        self.last_e2_state = "UNKNOWN"
        self.last_e2_check_time = "never"
        self.last_e2_error = "none"

        self.subscription_attempts = 0
        self.subscription_success = 0
        self.subscription_failures = 0
        self.subscription_id = None
        self.subscription_response = None
        self.subscription_callback_events = 0
        self.last_subscription_status = "not_started"
        self.last_subscription_time = "never"
        self.last_subscription_error = "none"

        self.rmr_ready = False
        self.rmr_messages_total = 0
        self.rmr_indications_total = 0
        self.rmr_sub_resp_total = 0
        self.rmr_sub_failure_total = 0
        self.rmr_control_ack_total = 0
        self.rmr_control_failure_total = 0
        self.rmr_other_total = 0
        self.last_rmr_type = "none"
        self.last_rmr_name = "none"
        self.last_rmr_meid = "none"
        self.last_rmr_sub_id = "none"
        self.last_rmr_state = "none"
        self.last_rmr_payload_len = 0
        self.last_rmr_time = "never"
        self.last_rmr_error = "none"

        self.event_trigger_len = 0
        self.action_def_len = 0

    def snapshot(self):
        with self.lock:
            uptime = round(time.time() - self.start_time, 2)
            heartbeat_age = round(time.time() - self.last_heartbeat, 2)
            return {
                "xapp": XAPP_NAME,
                "role": XAPP_ROLE,
                "state": "real-oran-kpm-monitoring",
                "uptime_sec": uptime,
                "heartbeat_age_sec": heartbeat_age,
                "heartbeat_ok": heartbeat_age <= 15,

                "http_port": HTTP_PORT,
                "rmr_port": RMR_PORT,
                "pod_ip": POD_IP,
                "service_http_host": SERVICE_HTTP_HOST,
                "service_http_port": SERVICE_HTTP_PORT,

                "submgr_uri": SUBMGR_URI,
                "e2mgr_nodeb_states_url": E2MGR_NODEB_STATES_URL,
                "target_e2_node": E2_NODE_ID,
                "target_e2_connected": self.target_e2_connected,
                "last_e2_state": self.last_e2_state,
                "e2_node_total": self.e2_node_total,
                "e2_node_connected": self.e2_node_connected,
                "e2_node_disconnected": self.e2_node_disconnected,
                "last_e2_check_time": self.last_e2_check_time,
                "last_e2_error": self.last_e2_error,

                "ran_function_id": RAN_FUNCTION_ID,
                "kpm_report_style": KPM_REPORT_STYLE,
                "kpm_report_period_ms": KPM_REPORT_PERIOD_MS,
                "kpm_granularity_ms": KPM_GRANULARITY_MS,
                "kpm_metrics": KPM_METRICS,
                "event_trigger_len": self.event_trigger_len,
                "action_def_len": self.action_def_len,

                "subscription_attempts": self.subscription_attempts,
                "subscription_success": self.subscription_success,
                "subscription_failures": self.subscription_failures,
                "subscription_id": self.subscription_id,
                "subscription_response": self.subscription_response,
                "subscription_callback_events": self.subscription_callback_events,
                "last_subscription_status": self.last_subscription_status,
                "last_subscription_time": self.last_subscription_time,
                "last_subscription_error": self.last_subscription_error,

                "rmr_ready": self.rmr_ready,
                "rmr_messages_total": self.rmr_messages_total,
                "rmr_indications_total": self.rmr_indications_total,
                "rmr_sub_resp_total": self.rmr_sub_resp_total,
                "rmr_sub_failure_total": self.rmr_sub_failure_total,
                "rmr_control_ack_total": self.rmr_control_ack_total,
                "rmr_control_failure_total": self.rmr_control_failure_total,
                "rmr_other_total": self.rmr_other_total,
                "last_rmr_type": self.last_rmr_type,
                "last_rmr_name": self.last_rmr_name,
                "last_rmr_meid": self.last_rmr_meid,
                "last_rmr_sub_id": self.last_rmr_sub_id,
                "last_rmr_state": self.last_rmr_state,
                "last_rmr_payload_len": self.last_rmr_payload_len,
                "last_rmr_time": self.last_rmr_time,
                "last_rmr_error": self.last_rmr_error,

                "time": now(),
            }


STATE = State()


def now():
    return datetime.now(timezone.utc).isoformat()


def log(msg):
    print(f"[{now()}] {msg}", flush=True)


def bytes_to_int_list(b):
    return [b[i] for i in range(len(b))]


def build_kpm_defs():
    packer = e2sm_kpm_packer()
    event_trigger = packer.pack_event_trigger_def(KPM_REPORT_PERIOD_MS)

    if KPM_REPORT_STYLE != 1:
        raise ValueError("Stage-1 kpm-monitor currently supports KPM Report Style 1 only")

    action_def = packer.pack_action_def_format1(KPM_METRICS, KPM_GRANULARITY_MS)

    with STATE.lock:
        STATE.event_trigger_len = len(event_trigger)
        STATE.action_def_len = len(action_def)

    return event_trigger, action_def


def check_e2_node_state():
    try:
        r = requests.get(E2MGR_NODEB_STATES_URL, timeout=5)
        r.raise_for_status()
        nodes = r.json()

        total = len(nodes)
        connected = sum(1 for n in nodes if n.get("connectionStatus") == "CONNECTED")
        disconnected = sum(1 for n in nodes if n.get("connectionStatus") == "DISCONNECTED")
        target = next((n for n in nodes if n.get("inventoryName") == E2_NODE_ID), None)

        if target:
            target_status = target.get("connectionStatus", "UNKNOWN")
        else:
            target_status = "NOT_FOUND"

        with STATE.lock:
            STATE.e2_node_total = total
            STATE.e2_node_connected = connected
            STATE.e2_node_disconnected = disconnected
            STATE.target_e2_connected = target_status == "CONNECTED"
            STATE.last_e2_state = target_status
            STATE.last_e2_check_time = now()
            STATE.last_e2_error = "none"

        return target_status == "CONNECTED", nodes

    except Exception as e:
        with STATE.lock:
            STATE.target_e2_connected = False
            STATE.last_e2_state = "CHECK_FAILED"
            STATE.last_e2_check_time = now()
            STATE.last_e2_error = repr(e)
        return False, []


def subscription_payload():
    event_trigger, action_def = build_kpm_defs()

    # PascalCase payload format expected by this OSC/NIST SubMgr build.
    return {
        "Meid": E2_NODE_ID,
        "RANFunctionID": RAN_FUNCTION_ID,
        "ClientEndpoint": {
            "Host": SERVICE_HTTP_HOST,
            "HTTPPort": SERVICE_HTTP_PORT,
            "RMRPort": RMR_PORT
        },
        "SubscriptionDetails": [
            {
                "XappEventInstanceId": 1234,
                "EventTriggers": bytes_to_int_list(event_trigger),
                "ActionToBeSetupList": [
                    {
                        "ActionID": 1,
                        "ActionType": "report",
                        "ActionDefinition": bytes_to_int_list(action_def),
                        "SubsequentAction": {
                            "SubsequentActionType": "continue",
                            "TimeToWait": "w10ms"
                        }
                    }
                ]
            }
        ]
    }


def create_subscription():
    with STATE.lock:
        STATE.subscription_attempts += 1
        STATE.last_subscription_time = now()
        STATE.last_subscription_status = "checking_e2_node"

    connected, nodes = check_e2_node_state()
    if not connected:
        msg = f"Target E2 node {E2_NODE_ID} is not CONNECTED. Current state={STATE.last_e2_state}"
        with STATE.lock:
            STATE.subscription_failures += 1
            STATE.last_subscription_status = "blocked_e2_not_connected"
            STATE.last_subscription_error = msg
        log(msg)
        return False

    payload = subscription_payload()
    url = f"{SUBMGR_URI}/subscriptions"

    log(f"Sending KPM subscription request to {url}")
    log(f"Target E2 node={E2_NODE_ID}, RANFunctionID={RAN_FUNCTION_ID}, metrics={KPM_METRICS}")

    try:
        r = requests.post(url, json=payload, timeout=8)
        body = r.text

        with STATE.lock:
            STATE.subscription_response = body[:2000]
            STATE.last_subscription_time = now()

        if r.status_code in (200, 201, 202):
            sub_id = None
            try:
                parsed = r.json()
                sub_id = parsed.get("SubscriptionId") or parsed.get("subscriptionId")
            except Exception:
                pass

            with STATE.lock:
                STATE.subscription_success += 1
                STATE.subscription_id = sub_id
                STATE.last_subscription_status = f"accepted_http_{r.status_code}"
                STATE.last_subscription_error = "none"

            log(f"Subscription accepted. HTTP={r.status_code}, SubscriptionId={sub_id}, body={body[:500]}")
            return True

        with STATE.lock:
            STATE.subscription_failures += 1
            STATE.last_subscription_status = f"rejected_http_{r.status_code}"
            STATE.last_subscription_error = body[:1000]

        log(f"Subscription rejected. HTTP={r.status_code}, body={body[:1000]}")
        return False

    except Exception as e:
        with STATE.lock:
            STATE.subscription_failures += 1
            STATE.last_subscription_status = "request_failed"
            STATE.last_subscription_error = repr(e)
        log(f"Subscription request failed: {repr(e)}")
        return False


def rmr_loop():
    try:
        log(f"Starting RMR listener on port {RMR_PORT}")
        ctx = rmr.rmr_init(str(RMR_PORT).encode("utf-8"), rmr.RMR_MAX_RCV_BYTES, 0x00)

        while rmr.rmr_ready(ctx) == 0 and STATE.running:
            time.sleep(1)

        rmr.rmr_set_stimeout(ctx, 1)

        with STATE.lock:
            STATE.rmr_ready = True

        log("RMR listener is ready")

        while STATE.running:
            sbuf = None
            try:
                sbuf = rmr.rmr_torcv_msg(ctx, None, 100)
                summary = rmr.message_summary(sbuf)
                msg_state = summary.get(rmr.RMR_MS_MSG_STATE)
                mtype = summary.get("message type")
                meid = summary.get("meid")
                sub_id = summary.get("subscription id")
                payload = rmr.get_payload(sbuf)

                if isinstance(meid, bytes):
                    meid = meid.decode(errors="ignore")

                mname = RMR_MESSAGE_TYPES.get(mtype, "UNKNOWN")

                with STATE.lock:
                    STATE.rmr_messages_total += 1
                    STATE.last_rmr_type = str(mtype)
                    STATE.last_rmr_name = mname
                    STATE.last_rmr_meid = str(meid)
                    STATE.last_rmr_sub_id = str(sub_id)
                    STATE.last_rmr_state = str(msg_state)
                    STATE.last_rmr_payload_len = len(payload) if payload is not None else 0
                    STATE.last_rmr_time = now()
                    STATE.last_rmr_error = "none"

                    if mtype == 12050:
                        STATE.rmr_indications_total += 1
                    elif mtype == 12011:
                        STATE.rmr_sub_resp_total += 1
                    elif mtype == 12012:
                        STATE.rmr_sub_failure_total += 1
                    elif mtype == 12041:
                        STATE.rmr_control_ack_total += 1
                    elif mtype == 12042:
                        STATE.rmr_control_failure_total += 1
                    else:
                        STATE.rmr_other_total += 1

                log(f"RMR message received: type={mtype} name={mname} meid={meid} sub_id={sub_id} payload_len={len(payload) if payload else 0}")

            except Exception as e:
                with STATE.lock:
                    STATE.last_rmr_error = repr(e)
                time.sleep(0.2)

            finally:
                try:
                    if sbuf is not None:
                        rmr.rmr_free_msg(sbuf)
                except Exception:
                    pass

        try:
            rmr.rmr_close(ctx)
        except Exception:
            pass

    except Exception as e:
        with STATE.lock:
            STATE.rmr_ready = False
            STATE.last_rmr_error = repr(e)
        log("RMR loop crashed:")
        traceback.print_exc()


def heartbeat_loop():
    while STATE.running:
        with STATE.lock:
            STATE.last_heartbeat = time.time()
        check_e2_node_state()
        time.sleep(5)


def subscription_loop():
    time.sleep(10)
    while STATE.running:
        snap = STATE.snapshot()
        if snap["subscription_success"] == 0:
            create_subscription()
        time.sleep(30)


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        data = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            snap = STATE.snapshot()
            healthy = snap["heartbeat_ok"] and snap["rmr_ready"]
            self._json(200 if healthy else 503, {
                "status": "ok" if healthy else "degraded",
                "xapp": XAPP_NAME,
                "rmr_ready": snap["rmr_ready"],
                "target_e2_connected": snap["target_e2_connected"],
                "time": now(),
            })
        elif self.path == "/profile":
            self._json(200, {
                "xapp": XAPP_NAME,
                "role": XAPP_ROLE,
                "expected_cpu_class": "medium",
                "expected_memory_class": "medium",
                "expected_ric_activity": True,
                "expected_control_activity": False,
                "expected_external_egress": False,
                "expected_cross_xapp_comm": False,
                "expected_shell": False,
                "expected_sensitive_file_access": False,
                "allowed_ric_services": ["e2mgr", "submgr", "prometheus"],
                "allowed_e2_nodes": [E2_NODE_ID],
                "ran_function_id": RAN_FUNCTION_ID,
                "kpm_report_style": KPM_REPORT_STYLE,
                "rmr_port": RMR_PORT,
                "http_port": HTTP_PORT,
                "max_api_rate_per_min": 120,
            })
        elif self.path == "/activity":
            self._json(200, STATE.snapshot())
        elif self.path == "/ric-check":
            connected, nodes = check_e2_node_state()
            self._json(200, {
                "xapp": XAPP_NAME,
                "target_e2_node": E2_NODE_ID,
                "target_e2_connected": connected,
                "nodes": nodes,
                "submgr_uri": SUBMGR_URI,
                "subscription_status": STATE.snapshot()["last_subscription_status"],
                "time": now(),
            })
        elif self.path == "/metrics":
            snap = STATE.snapshot()
            lines = []
            labels = f'xapp="{XAPP_NAME}",role="{XAPP_ROLE}"'
            for metric in [
                "e2_node_total",
                "e2_node_connected",
                "e2_node_disconnected",
                "subscription_attempts",
                "subscription_success",
                "subscription_failures",
                "subscription_callback_events",
                "rmr_messages_total",
                "rmr_indications_total",
                "rmr_sub_resp_total",
                "rmr_sub_failure_total",
                "rmr_control_ack_total",
                "rmr_control_failure_total",
                "rmr_other_total",
            ]:
                lines.append(f'ztx_kpm_monitor_{metric}{{{labels}}} {snap[metric]}')
            lines.append(f'ztx_kpm_monitor_target_e2_connected{{{labels}}} {1 if snap["target_e2_connected"] else 0}')
            lines.append(f'ztx_kpm_monitor_rmr_ready{{{labels}}} {1 if snap["rmr_ready"] else 0}')
            data = "\n".join(lines) + "\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data.encode())))
            self.end_headers()
            self.wfile.write(data.encode())
        else:
            self._json(404, {"error": "not_found", "path": self.path})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode(errors="ignore") if length > 0 else ""

        with STATE.lock:
            STATE.subscription_callback_events += 1
            STATE.last_subscription_time = now()
            STATE.last_subscription_status = f"callback_{self.path}"
            STATE.subscription_response = body[:2000]

        log(f"HTTP callback received path={self.path} body={body[:1000]}")
        self._json(200, {"status": "ok", "xapp": XAPP_NAME, "time": now()})

    def log_message(self, fmt, *args):
        return


def http_loop():
    server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    log(f"HTTP server listening on 0.0.0.0:{HTTP_PORT}")
    server.serve_forever()


def shutdown_handler(sig, frame):
    log(f"Shutdown signal received: {sig}")
    STATE.running = False


def main():
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    log("Starting kpm-monitor real O-RAN xApp")
    log(f"POD_IP={POD_IP}, SERVICE_HTTP_HOST={SERVICE_HTTP_HOST}, SUBMGR_URI={SUBMGR_URI}")
    log(f"E2_NODE_ID={E2_NODE_ID}, RAN_FUNCTION_ID={RAN_FUNCTION_ID}, KPM_METRICS={KPM_METRICS}")

    threads = [
        threading.Thread(target=heartbeat_loop, daemon=True),
        threading.Thread(target=rmr_loop, daemon=True),
        threading.Thread(target=subscription_loop, daemon=True),
        threading.Thread(target=http_loop, daemon=True),
    ]

    for t in threads:
        t.start()

    while STATE.running:
        time.sleep(1)

    log("kpm-monitor stopped")


if __name__ == "__main__":
    main()
