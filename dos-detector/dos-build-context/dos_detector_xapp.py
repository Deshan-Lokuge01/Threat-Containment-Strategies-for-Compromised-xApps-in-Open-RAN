#!/usr/bin/env python3

import argparse
import signal
import os
import json
import time
import requests
from urllib.parse import urlparse
from lib.xAppBase import xAppBase

# --- FIX START: PASCAL CASE MAPPER ---
try:
    from ricxappframe.subsclient.api_client import ApiClient

    class FakeResponse:
        def __init__(self, status, data):
            self.status = status
            self.data = data
            self.reason = "OK" if status < 300 else "Error"
        def getheaders(self): return {}

    def _patched_request(self, method, url, query_params=None, headers=None, body=None, post_params=None, _preload_content=True, _request_timeout=None):

        if ":8088" not in url or method != "POST":
            return FakeResponse(404, "Not Found")

        if body is None: body = {}

        my_host = os.environ.get("SERVICE_HTTP_HOST", "my-secure-dos-xapp")
        my_port = int(os.environ.get("SERVICE_HTTP_PORT", "8092"))
        rmr_port = int(os.environ.get("RMR_PORT", "4562"))

        new_payload = {
            "Meid": body.get("meid"),
            "RANFunctionID": body.get("ran_function_id"),
            "ClientEndpoint": {
                "Host": my_host,
                "HTTPPort": my_port,
                "RMRPort": rmr_port
            },
            "SubscriptionDetails": []
        }

        if "subscription_details" in body:
            for detail in body["subscription_details"]:
                new_detail = {
                    "XappEventInstanceId": detail.get("xapp_event_instance_id"),
                    "EventTriggers": detail.get("event_triggers"),
                    "ActionToBeSetupList": []
                }

                if "action_to_be_setup_list" in detail:
                    for action in detail["action_to_be_setup_list"]:
                        new_action = {
                            "ActionID": action.get("action_id"),
                            "ActionType": action.get("action_type"),
                            "ActionDefinition": action.get("action_definition"),
                            "SubsequentAction": action.get("subsequent_action")
                        }
                        new_detail["ActionToBeSetupList"].append(new_action)

                new_payload["SubscriptionDetails"].append(new_detail)

        target_url = "http://service-ricplt-submgr-http.ricplt.svc.cluster.local:8080/ric/v1/subscriptions"
        custom_headers = {"Content-Type": "application/json"}

        print("-" * 40)
        print(f"[FIX] PASCAL CASE MAPPER ACTIVE.")
        print(f"[FIX] Sending Transformed Payload: {json.dumps(new_payload)}")

        try:
            r = requests.post(target_url, json=new_payload, headers=custom_headers, timeout=5)

            print(f"[FIX] Server Response Code: {r.status_code}")
            print(f"[FIX] Server Response Body: {r.text}")

            if r.status_code in [200, 201]:
                print("[FIX] SUCCESS! Subscription accepted.")
                return FakeResponse(201, r.text)
            else:
                print("[FIX] Server rejected the request.")
                raise Exception(f"Server Error {r.status_code}: {r.text}")

        except Exception as e:
            print(f"[FIX] Connection Failed: {e}")
            raise e

    ApiClient.request = _patched_request
    print("[INFO] PascalCase Mapper Active.")

except ImportError:
    print("[WARNING] Could not patch ApiClient.")
# --- FIX END ---

# --- CONFIGURATION ---
SECURITY_THRESHOLD_UL = 200.0

class MyXapp(xAppBase):
    def __init__(self, config, http_server_port, rmr_port):
        super(MyXapp, self).__init__(config, http_server_port, rmr_port)

    def my_subscription_callback(self, e2_agent_id, subscription_id, indication_hdr, indication_msg, kpm_report_style, ue_id):
        meas_data = self.e2sm_kpm.extract_meas_data(indication_msg)

        if kpm_report_style == 5:
            if "ueMeasData" in meas_data:
                for ue_id_str, ue_data in meas_data["ueMeasData"].items():
                    if "measData" in ue_data:
                        for metric_name, value in ue_data["measData"].items():
                            self.check_security(ue_id_str, metric_name, value)
            else:
                print("[WARNING] Received Style 5 report but no 'ueMeasData' found.")

        elif kpm_report_style == 1:
            if "measData" in meas_data:
                for metric_name, value in meas_data["measData"].items():
                    self.check_security("GLOBAL", metric_name, value)

    def check_security(self, ue_id, metric_name, value):
        if metric_name == "DRB.UEThpUl":
            try:
                current_speed = float(value[0]) if isinstance(value, list) else float(value)
            except (IndexError, ValueError, TypeError):
                current_speed = 0.0

            print(f"[MONITOR] UE {ue_id} Upload Speed: {current_speed} kbps")

            if current_speed > SECURITY_THRESHOLD_UL:
                print("\n" + "!" * 50)
                print(f" [ALERT] SECURITY VIOLATION DETECTED!")
                print(f" [TYPE]  Potential DoS / Data Exfiltration")
                print(f" [UE ID] {ue_id}")
                print(f" [VAL]   Current Speed: {current_speed} kbps > Limit: {SECURITY_THRESHOLD_UL}")
                print(" [ACTION] BLOCK UE IMMEDIATELY")
                print("!" * 50 + "\n")
            else:
                print(f" [STATUS] Traffic Normal (UE {ue_id})")

    @xAppBase.start_function
    def start(self, e2_node_id, kpm_report_style, ue_ids, metric_names):
        print("=" * 60)
        print("[INFO] Bypassing E2 Subscription call (No E2 Node connected).")
        print("[INFO] MySecureDoS xApp is now running in Standalone Listening Mode.")
        print("[INFO] Health probes (/ric/v1/health/alive & /ready) are ACTIVE.")
        print("=" * 60)

        # Non-blocking keep-alive loop so Kubernetes keeps container status 1/1 Running
        while self.running:
            time.sleep(5)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DoS Detector Custom xApp')
    parser.add_argument("--config", type=str, default='', help="config")
    parser.add_argument("--http_server_port", type=int, default=8092, help="port")
    parser.add_argument("--rmr_port", type=int, default=4562, help="rmr port")
    parser.add_argument("--e2_node_id", type=str, default='gnbd_001_001_00019b_0', help="E2 Node ID")
    parser.add_argument("--ran_func_id", type=int, default=2, help="RAN func ID")
    parser.add_argument("--kpm_report_style", type=int, default=5, help="Style")
    parser.add_argument("--ue_ids", type=str, default='0', help="UE ID")
    parser.add_argument("--metrics", type=str, default='DRB.UEThpUl,DRB.UEThpDl', help="metrics")

    args = parser.parse_args()
    myXapp = MyXapp(args.config, args.http_server_port, args.rmr_port)
    if myXapp.e2sm_kpm:
        myXapp.e2sm_kpm.set_ran_func_id(args.ran_func_id)
    signal.signal(signal.SIGQUIT, myXapp.signal_handler)
    signal.signal(signal.SIGINT, myXapp.signal_handler)

    ue_ids = list(map(int, args.ue_ids.split(",")))
    metrics = args.metrics.split(",")
    myXapp.start(args.e2_node_id, args.kpm_report_style, ue_ids, metrics)
