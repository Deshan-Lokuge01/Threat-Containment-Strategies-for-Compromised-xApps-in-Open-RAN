#!/usr/bin/env python3
import json
import os
import time
import threading
import socket
import math
import random
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timezone

PROFILE_PATH = os.environ.get("XAPP_PROFILE_PATH", "/etc/xapp-profile/profile.json")
PORT = int(os.environ.get("XAPP_PORT", "8080"))

# Real RIC services discovered from your NIST O-RAN SC RIC service list.
# The xApp will only contact services listed in its profile's allowed_ric_services.
RIC_SERVICE_CANDIDATES = {
    "appmgr": [
        "http://service-ricplt-appmgr-http.ricplt.svc.cluster.local:8080",
        "http://service-ricplt-appmgr-http.ricplt.svc.cluster.local:8080/ric/v1/health/ready",
        "http://service-ricplt-appmgr-http.ricplt.svc.cluster.local:8080/ric/v1/xapps"
    ],
    "e2mgr": [
        "http://service-ricplt-e2mgr-http.ricplt.svc.cluster.local:3800",
        "http://service-ricplt-e2mgr-http.ricplt.svc.cluster.local:3800/v1/nodeb/states",
        "http://service-ricplt-e2mgr-http.ricplt.svc.cluster.local:3800/v1/nodeb/ids"
    ],
    "submgr": [
        "http://service-ricplt-submgr-http.ricplt.svc.cluster.local:3800",
        "http://service-ricplt-submgr-http.ricplt.svc.cluster.local:3800/ric/v1/subscriptions",
        "http://service-ricplt-submgr-http.ricplt.svc.cluster.local:3800/ric/v1/health/ready"
    ],
    "rtmgr": [
        "http://service-ricplt-rtmgr-http.ricplt.svc.cluster.local:3800",
        "http://service-ricplt-rtmgr-http.ricplt.svc.cluster.local:3800/ric/v1/getdebuginfo"
    ],
    "a1mediator": [
        "http://service-ricplt-a1mediator-http.ricplt.svc.cluster.local:10000",
        "http://service-ricplt-a1mediator-http.ricplt.svc.cluster.local:10000/a1-p/healthcheck"
    ],
    "alarmmanager": [
        "http://service-ricplt-alarmmanager-http.ricplt.svc.cluster.local:8080"
    ],
    "prometheus": [
        "http://r4-infrastructure-prometheus-server.ricplt.svc.cluster.local:80/-/ready",
        "http://r4-infrastructure-prometheus-server.ricplt.svc.cluster.local:80/api/v1/query?query=up"
    ],
    "influxdb": [
        "http://r4-influxdb-influxdb2.ricplt.svc.cluster.local:80"
    ]
}

state = {
    "start_time": time.time(),
    "last_heartbeat": time.time(),
    "work_units_processed": 0,
    "ric_activity_counter": 0,
    "control_action_counter": 0,
    "telemetry_samples": 0,
    "qos_decisions": 0,
    "traffic_reports": 0,
    "resource_recommendations": 0,
    "security_checks": 0,
    "errors": 0,
    "mode": "starting",
    "last_decision": "none",

    # RIC-aware activity state
    "ric_service_attempts": 0,
    "ric_service_success": 0,
    "ric_service_failures": 0,
    "last_ric_service": "none",
    "last_ric_url": "none",
    "last_ric_status": "not_checked",
    "last_ric_time": "never",
    "ric_results": []
}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def load_profile():
    default = {
        "xapp": os.environ.get("XAPP_NAME", "unknown-xapp"),
        "role": "generic",
        "expected_cpu_class": "low",
        "expected_memory_class": "low",
        "expected_external_egress": False,
        "expected_cross_xapp_comm": False,
        "expected_ric_activity": False,
        "expected_control_activity": False,
        "expected_shell": False,
        "expected_sensitive_file_access": False,
        "heartbeat_period_sec": 5,
        "workload_intensity": "low",
        "allowed_ric_services": [],
        "max_api_rate_per_min": 60
    }

    try:
        with open(PROFILE_PATH, "r") as f:
            loaded = json.load(f)
            default.update(loaded)
    except Exception as e:
        state["errors"] += 1
        default["profile_load_error"] = str(e)

    return default


profile = load_profile()


def cpu_work(duration_sec: float, complexity: int):
    """
    Legitimate CPU work simulation.
    This models real xApps performing analytics, optimization,
    scoring, and feature processing.
    """
    end = time.time() + duration_sec
    result = 0.0

    while time.time() < end:
        for i in range(complexity):
            result += math.sin(i) * math.cos(i % 17)

    return result


def record_ric_result(service, url, status, success):
    result = {
        "time": now_iso(),
        "service": service,
        "url": url,
        "status": status,
        "success": success
    }

    state["last_ric_service"] = service
    state["last_ric_url"] = url
    state["last_ric_status"] = status
    state["last_ric_time"] = result["time"]

    state["ric_results"].append(result)
    state["ric_results"] = state["ric_results"][-20:]


def probe_url(service, url):
    """
    Probe a RIC HTTP service.

    Important:
    HTTP 200/204/301/302/401/403/404 are all treated as successful reachability,
    because the goal here is to prove the xApp reached the real RIC service.
    A 404 still proves the service is reachable even if that specific endpoint path
    does not exist in this RIC release.
    """
    state["ric_service_attempts"] += 1

    try:
        req = urllib.request.Request(
            url,
            method="GET",
            headers={
                "User-Agent": f"zt-xguard-{profile.get('xapp')}",
                "Accept": "application/json,text/plain,*/*"
            }
        )

        with urllib.request.urlopen(req, timeout=1.5) as response:
            code = response.getcode()
            state["ric_service_success"] += 1
            record_ric_result(service, url, f"HTTP_{code}", True)
            return True

    except urllib.error.HTTPError as e:
        # HTTP error still means the RIC service was reached.
        state["ric_service_success"] += 1
        record_ric_result(service, url, f"HTTP_{e.code}", True)
        return True

    except Exception as e:
        state["ric_service_failures"] += 1
        record_ric_result(service, url, f"FAILED_{type(e).__name__}", False)
        return False


def check_ric_services():
    """
    Best-effort RIC service interaction.

    This is not full E2SM-KPM decoding.
    It is RIC-aware behavior: the xApp contacts only RIC services allowed
    by its declared profile and records the outcome.
    """
    allowed = profile.get("allowed_ric_services", [])

    if not allowed:
        record_ric_result("none", "none", "SKIPPED_NO_ALLOWED_RIC_SERVICES", True)
        return

    for service in allowed:
        candidates = RIC_SERVICE_CANDIDATES.get(service, [])

        if not candidates:
            state["ric_service_failures"] += 1
            record_ric_result(service, "none", "NO_CANDIDATE_URLS", False)
            continue

        for url in candidates:
            if probe_url(service, url):
                state["ric_activity_counter"] += 1
                return


def telemetry_monitor_behavior():
    """
    Telemetry/KPI monitoring xApp.
    Expected:
    - low CPU
    - regular telemetry sample collection
    - allowed to query monitoring/RIC state services
    - no control actions
    """
    state["mode"] = "telemetry-monitoring"

    check_ric_services()

    samples = random.randint(5, 20)
    state["telemetry_samples"] += samples
    state["work_units_processed"] += samples

    state["last_decision"] = f"collected_{samples}_telemetry_samples"


def qos_optimizer_behavior():
    """
    QoS optimizer xApp.
    Expected:
    - medium CPU
    - queries RIC state
    - produces QoS recommendations/control-like decisions
    """
    state["mode"] = "qos-optimization"

    cpu_work(0.4, 400)
    check_ric_services()

    qos_score = random.uniform(0.70, 0.99)

    state["qos_decisions"] += 1
    state["work_units_processed"] += 120

    if profile.get("expected_control_activity", False):
        state["control_action_counter"] += 1

    state["last_decision"] = f"qos_score={qos_score:.3f}"


def traffic_analyzer_behavior():
    """
    Legitimate high-load traffic analytics xApp.
    This is the key benign high-CPU workload.
    Expected:
    - high CPU
    - RIC-aware activity through allowed services
    - activity counter continuously increases
    - no shell
    - no sensitive file access
    - no unexpected external egress
    """
    state["mode"] = "traffic-analytics"

    cpu_work(1.5, 1200)
    check_ric_services()

    processed_flows = random.randint(500, 1500)
    state["traffic_reports"] += 1
    state["work_units_processed"] += processed_flows

    state["last_decision"] = f"processed_{processed_flows}_traffic_flows"


def resource_optimizer_behavior():
    """
    Resource optimizer xApp.
    Expected:
    - medium CPU
    - queries RIC/platform state
    - produces bounded resource recommendations
    """
    state["mode"] = "resource-optimization"

    cpu_work(0.5, 500)
    check_ric_services()

    recommendation = random.choice(["hold", "rebalance", "reduce_load", "increase_capacity"])

    state["resource_recommendations"] += 1
    state["work_units_processed"] += 160

    if profile.get("expected_control_activity", False):
        state["control_action_counter"] += 1

    state["last_decision"] = f"resource_action={recommendation}"


def security_observer_behavior():
    """
    Security observer xApp.
    Expected:
    - low CPU
    - normally no RIC control/service probing
    - no external egress
    - no cross-xApp communication
    """
    state["mode"] = "security-observation"

    # It intentionally does NOT call check_ric_services unless its profile allows services.
    # This gives us a clean baseline for detecting unexpected service probing.
    if profile.get("allowed_ric_services", []):
        check_ric_services()

    state["security_checks"] += 1
    state["work_units_processed"] += 10
    state["last_decision"] = "security_heartbeat_ok"


def generic_behavior():
    state["mode"] = "generic"
    check_ric_services()
    state["work_units_processed"] += 5
    state["last_decision"] = "generic_heartbeat"


def run_role_behavior():
    role = profile.get("role", "generic")

    if role == "telemetry-monitoring":
        telemetry_monitor_behavior()
    elif role == "qos-optimization":
        qos_optimizer_behavior()
    elif role == "traffic-analytics":
        traffic_analyzer_behavior()
    elif role == "resource-optimization":
        resource_optimizer_behavior()
    elif role == "security-observation":
        security_observer_behavior()
    else:
        generic_behavior()


def workload_loop():
    heartbeat_period = int(profile.get("heartbeat_period_sec", 5))

    while True:
        try:
            state["last_heartbeat"] = time.time()
            run_role_behavior()
        except Exception as e:
            state["errors"] += 1
            state["last_decision"] = f"error={type(e).__name__}: {str(e)}"

        time.sleep(heartbeat_period)


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, code, text):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"{now_iso()} {self.client_address[0]} {fmt % args}", flush=True)

    def do_GET(self):
        uptime = time.time() - state["start_time"]
        heartbeat_age = time.time() - state["last_heartbeat"]

        if self.path == "/health":
            self._send_json(200, {
                "status": "ok",
                "xapp": profile.get("xapp"),
                "role": profile.get("role"),
                "hostname": socket.gethostname(),
                "time": now_iso()
            })

        elif self.path == "/profile":
            self._send_json(200, profile)

        elif self.path == "/activity":
            self._send_json(200, {
                "xapp": profile.get("xapp"),
                "role": profile.get("role"),
                "state": state["mode"],
                "uptime_sec": round(uptime, 2),
                "heartbeat_age_sec": round(heartbeat_age, 2),
                "heartbeat_ok": heartbeat_age <= int(profile.get("heartbeat_period_sec", 5)) * 3,

                "work_units_processed": state["work_units_processed"],
                "ric_activity_counter": state["ric_activity_counter"],
                "control_action_counter": state["control_action_counter"],

                "telemetry_samples": state["telemetry_samples"],
                "qos_decisions": state["qos_decisions"],
                "traffic_reports": state["traffic_reports"],
                "resource_recommendations": state["resource_recommendations"],
                "security_checks": state["security_checks"],

                "ric_service_attempts": state["ric_service_attempts"],
                "ric_service_success": state["ric_service_success"],
                "ric_service_failures": state["ric_service_failures"],
                "last_ric_service": state["last_ric_service"],
                "last_ric_url": state["last_ric_url"],
                "last_ric_status": state["last_ric_status"],
                "last_ric_time": state["last_ric_time"],

                "last_decision": state["last_decision"],
                "errors": state["errors"],
                "time": now_iso()
            })

        elif self.path == "/ric-check":
            check_ric_services()
            self._send_json(200, {
                "xapp": profile.get("xapp"),
                "allowed_ric_services": profile.get("allowed_ric_services", []),
                "ric_service_attempts": state["ric_service_attempts"],
                "ric_service_success": state["ric_service_success"],
                "ric_service_failures": state["ric_service_failures"],
                "last_ric_service": state["last_ric_service"],
                "last_ric_url": state["last_ric_url"],
                "last_ric_status": state["last_ric_status"],
                "last_ric_time": state["last_ric_time"],
                "recent_results": state["ric_results"],
                "time": now_iso()
            })

        elif self.path == "/metrics":
            text = f"""# HELP xapp_work_units_processed Total legitimate work units processed
# TYPE xapp_work_units_processed counter
xapp_work_units_processed{{xapp="{profile.get('xapp')}",role="{profile.get('role')}"}} {state["work_units_processed"]}

# HELP xapp_ric_activity_counter Logical RIC-aware activity counter
# TYPE xapp_ric_activity_counter counter
xapp_ric_activity_counter{{xapp="{profile.get('xapp')}",role="{profile.get('role')}"}} {state["ric_activity_counter"]}

# HELP xapp_control_action_counter Simulated control action counter
# TYPE xapp_control_action_counter counter
xapp_control_action_counter{{xapp="{profile.get('xapp')}",role="{profile.get('role')}"}} {state["control_action_counter"]}

# HELP xapp_ric_service_attempts_total RIC service probe attempts
# TYPE xapp_ric_service_attempts_total counter
xapp_ric_service_attempts_total{{xapp="{profile.get('xapp')}",role="{profile.get('role')}"}} {state["ric_service_attempts"]}

# HELP xapp_ric_service_success_total Successful RIC service reachability checks
# TYPE xapp_ric_service_success_total counter
xapp_ric_service_success_total{{xapp="{profile.get('xapp')}",role="{profile.get('role')}"}} {state["ric_service_success"]}

# HELP xapp_ric_service_failures_total Failed RIC service reachability checks
# TYPE xapp_ric_service_failures_total counter
xapp_ric_service_failures_total{{xapp="{profile.get('xapp')}",role="{profile.get('role')}"}} {state["ric_service_failures"]}

# HELP xapp_heartbeat_age_seconds Seconds since last heartbeat
# TYPE xapp_heartbeat_age_seconds gauge
xapp_heartbeat_age_seconds{{xapp="{profile.get('xapp')}",role="{profile.get('role')}"}} {round(heartbeat_age, 2)}

# HELP xapp_errors_total Total internal xApp errors
# TYPE xapp_errors_total counter
xapp_errors_total{{xapp="{profile.get('xapp')}",role="{profile.get('role')}"}} {state["errors"]}
"""
            self._send_text(200, text)

        else:
            self._send_json(404, {"error": "not found", "path": self.path})


def main():
    print(f"[ZT-XGuard xApp] Starting {profile.get('xapp')} role={profile.get('role')} on port {PORT}", flush=True)
    print(f"[ZT-XGuard xApp] Profile: {json.dumps(profile)}", flush=True)
    print(f"[ZT-XGuard xApp] Allowed RIC services: {profile.get('allowed_ric_services', [])}", flush=True)

    t = threading.Thread(target=workload_loop, daemon=True)
    t.start()

    server = HTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
