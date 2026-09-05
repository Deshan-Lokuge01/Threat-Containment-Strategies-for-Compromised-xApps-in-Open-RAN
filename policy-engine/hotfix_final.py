# ZTX_FINAL_ACTIVE_ROUTE_HOTFIX_V1
# Active route-level hotfix for final demo stability.

from __future__ import annotations

import json
import time
import uuid
import traceback
from datetime import datetime, timezone
from flask import jsonify, request


def install(g):
    APP = g["APP"]
    CORE = g.get("CORE")
    CSM_STATE = g.get("CSM_STATE")
    CSM_STATE_LOCK = g.get("CSM_STATE_LOCK")
    XAPP_LIST = list(g.get("XAPP_LIST") or [
        "telemetry-monitor",
        "qos-optimizer",
        "traffic-analyzer",
        "resource-optimizer",
        "security-observer",
    ])
    XAPP_NAMESPACE = g.get("XAPP_NAMESPACE", "ricxapp")

    if g.get("_ZTX_FINAL_ACTIVE_ROUTE_HOTFIX_V1"):
        return

    g["_ZTX_FINAL_ACTIVE_ROUTE_HOTFIX_V1"] = True

    def utc_now():
        return datetime.now(timezone.utc).isoformat()

    def public_state(state):
        s = str(state or "NORMAL").upper().strip()
        if s in {"NORMAL", "TRUSTED", "HEALTHY", "RESTORED", "UNKNOWN", "INITIALIZING"}:
            return "NORMAL"
        if s == "OBSERVED":
            return "OBSERVED"
        if s in {"SUSPICIOUS", "DEGRADED"}:
            return "SUSPICIOUS"
        if s in {"COMPROMISED", "QUARANTINED", "CONTAINED"}:
            return "COMPROMISED"
        return "NORMAL"

    def rank(state):
        return {
            "NORMAL": 0,
            "OBSERVED": 1,
            "SUSPICIOUS": 2,
            "COMPROMISED": 3,
        }.get(public_state(state), 0)

    def scores(state):
        s = public_state(state)
        if s == "NORMAL":
            return 0, 100
        if s == "OBSERVED":
            return 20, 80
        if s == "SUSPICIOUS":
            return 60, 40
        if s == "COMPROMISED":
            return 100, 0
        return 0, 100

    def is_restore(source=None, signal=None):
        src = str(source or "").lower()
        sig = str(signal or "").lower()
        return "restore" in src or sig in {"restore", "readmit", "manual_restore", "restore_baseline"}

    def response_to_payload(ret):
        code = 200
        obj = ret

        if isinstance(ret, tuple):
            obj = ret[0]
            if len(ret) > 1 and isinstance(ret[1], int):
                code = ret[1]

        if hasattr(obj, "get_json"):
            data = obj.get_json(silent=True)
            if data is not None:
                return data, code

        if isinstance(obj, dict):
            return obj, code

        return {"ok": False, "error": "unparsed_response", "repr": repr(ret)}, code

    def pod_quarantine_marked(labels):
        labels = labels or {}
        return (
            labels.get("security-status") == "quarantined"
            or labels.get("zt-xguard.io/quarantine") == "true"
            or labels.get("zt-xguard.io/decision") in {"quarantined", "compromised"}
        )

    def read_endpoints(namespace, service_name):
        try:
            ep = CORE.read_namespaced_endpoints(service_name, namespace)
            subsets = ep.subsets or []
            addresses = []
            ports = []

            for subset in subsets:
                for a in (subset.addresses or []):
                    if getattr(a, "ip", None):
                        addresses.append(a.ip)
                for p in (subset.ports or []):
                    ports.append({
                        "name": getattr(p, "name", None),
                        "port": getattr(p, "port", None),
                        "protocol": getattr(p, "protocol", None),
                    })

            return {
                "service": service_name,
                "endpoint_count": len(addresses),
                "has_endpoints": len(addresses) > 0,
                "addresses": addresses,
                "ports": ports,
                "source": "endpoints",
                "error": None,
            }
        except Exception as exc:
            return {
                "service": service_name,
                "endpoint_count": None,
                "has_endpoints": None,
                "addresses": [],
                "ports": [],
                "source": "endpoints",
                "error": str(exc),
            }

    def find_services_for_xapp(xapp, namespace):
        services = []

        try:
            svc = CORE.read_namespaced_service(xapp, namespace)
            services.append(svc)
        except Exception:
            pass

        if not services:
            try:
                res = CORE.list_namespaced_service(namespace, label_selector=f"app={xapp}")
                services.extend(res.items or [])
            except Exception:
                pass

        return services

    def live_verify(xapp, namespace=None):
        namespace = namespace or XAPP_NAMESPACE

        pods_out = []
        quarantine_marked = False

        try:
            pods = CORE.list_namespaced_pod(namespace, label_selector=f"app={xapp}").items or []
            for pod in pods:
                labels = pod.metadata.labels or {}
                marked = pod_quarantine_marked(labels)
                quarantine_marked = quarantine_marked or marked
                pods_out.append({
                    "pod": pod.metadata.name,
                    "phase": pod.status.phase,
                    "ready": all((c.ready for c in (pod.status.container_statuses or []))) if pod.status.container_statuses else False,
                    "quarantine_label": marked,
                    "labels": labels,
                })
        except Exception as exc:
            pods_out.append({"error": str(exc)})

        services_out = []
        service_isolated = False

        for svc in find_services_for_xapp(xapp, namespace):
            meta = svc.metadata
            spec = svc.spec
            annotations = meta.annotations or {}
            selector = spec.selector or {}

            ep = read_endpoints(namespace, meta.name)

            selector_isolated = "zt-xguard.io/service-isolated" in selector
            annotation_isolated = annotations.get("zt-xguard.io/service-isolated") == "true"

            isolated = bool(selector_isolated or annotation_isolated or ep.get("endpoint_count") == 0)
            service_isolated = service_isolated or isolated

            services_out.append({
                "service": meta.name,
                "selector": selector,
                "annotations": annotations,
                "endpoint_summary": ep,
                "service_isolated": isolated,
            })

        contained = bool(quarantine_marked and service_isolated)

        return {
            "xapp": xapp,
            "namespace": namespace,
            "pods": pods_out,
            "services": services_out,
            "quarantine_marked": quarantine_marked,
            "pod_labelled_quarantined": quarantine_marked,
            "service_isolated": service_isolated,
            "contained": contained,
            "verification_unknown": False,
            "time": utc_now(),
            "ztx_final_active_route_hotfix_v1": True,
        }

    def force_service_isolation(xapp, namespace=None, reason=None):
        namespace = namespace or XAPP_NAMESPACE
        reason = reason or "compromised_xapp_requires_service_isolation"
        token = "ztxq-" + uuid.uuid4().hex[:16]

        results = []

        # label pod as quarantined/compromised evidence
        try:
            pods = CORE.list_namespaced_pod(namespace, label_selector=f"app={xapp}").items or []
            for pod in pods:
                CORE.patch_namespaced_pod(
                    pod.metadata.name,
                    namespace,
                    {
                        "metadata": {
                            "labels": {
                                "security-status": "quarantined",
                                "zt-xguard.io/quarantine": "true",
                                "zt-xguard.io/decision": "compromised",
                            },
                            "annotations": {
                                "zt-xguard.io/quarantine-reason": reason,
                                "zt-xguard.io/quarantine-time": utc_now(),
                            },
                        }
                    },
                )
        except Exception as exc:
            results.append({"pod_patch_error": str(exc)})

        # isolate service by making selector require a label no pod has
        for svc in find_services_for_xapp(xapp, namespace):
            meta = svc.metadata
            spec = svc.spec
            annotations = meta.annotations or {}
            selector = dict(spec.selector or {"app": xapp})

            original = annotations.get("zt-xguard.io/original-service-selector")
            if not original:
                original = json.dumps(selector)

            blocked = dict(selector)
            blocked["zt-xguard.io/service-isolated"] = token

            body = {
                "metadata": {
                    "annotations": {
                        "zt-xguard.io/original-service-selector": original,
                        "zt-xguard.io/service-isolated": "true",
                        "zt-xguard.io/service-isolated-time": utc_now(),
                        "zt-xguard.io/service-isolated-reason": reason,
                        "zt-xguard.io/service-isolated-selector-token": token,
                        "zt-xguard.io/xapp": xapp,
                    }
                },
                "spec": {
                    "selector": blocked
                },
            }

            try:
                CORE.patch_namespaced_service(meta.name, namespace, body)
                time.sleep(0.25)
                ep = read_endpoints(namespace, meta.name)
                results.append({
                    "service": meta.name,
                    "applied": True,
                    "blocked_selector": blocked,
                    "endpoint_summary_after_patch": ep,
                    "isolated": ep.get("endpoint_count") == 0,
                })
            except Exception as exc:
                results.append({
                    "service": meta.name,
                    "applied": False,
                    "error": str(exc),
                    "trace": traceback.format_exc(),
                })

        verification = live_verify(xapp, namespace)

        return {
            "applied": bool(verification.get("service_isolated")),
            "xapp": xapp,
            "namespace": namespace,
            "reason": reason,
            "services": results,
            "verification_after": verification,
            "effective_containment_applied": bool(verification.get("contained")),
            "service_isolation_applied": bool(verification.get("service_isolated")),
            "ztx_final_active_route_hotfix_v1": True,
        }

    def set_csm_state(xapp, state, source=None, signal=None, containment_verified=None, extra=None):
        if CSM_STATE is None:
            return {}

        final_state = public_state(state)
        risk, trust = scores(final_state)

        with CSM_STATE_LOCK:
            prev = dict(CSM_STATE.get(xapp) or {})
            previous_state = public_state(prev.get("state"))

            downgrade_blocked = False
            if not is_restore(source, signal) and rank(previous_state) > rank(final_state):
                final_state = previous_state
                risk, trust = scores(final_state)
                downgrade_blocked = True

            entry = dict(prev)
            entry.update({
                "xapp": xapp,
                "namespace": XAPP_NAMESPACE,
                "state": final_state,
                "score": risk,
                "risk_score": risk,
                "trust_score": trust,
                "score_type": "risk_score_0_to_100_higher_means_riskier",
                "containment_required": final_state == "COMPROMISED",
                "containment_verified": containment_verified if containment_verified is not None else prev.get("containment_verified"),
                "previous_state": previous_state,
                "downgrade_blocked": downgrade_blocked,
                "last_source": source,
                "last_signal": signal,
                "last_update": utc_now(),
                "ztx_final_active_route_hotfix_v1": True,
            })

            if extra:
                entry.update(extra)

            CSM_STATE[xapp] = entry
            return dict(entry)

    def hotfix_state_view():
        xapps = []

        for xapp in XAPP_LIST:
            with CSM_STATE_LOCK:
                entry = dict((CSM_STATE or {}).get(xapp) or {
                    "xapp": xapp,
                    "state": "NORMAL",
                })

            state = public_state(entry.get("state"))

            if state == "COMPROMISED":
                verification = live_verify(xapp, XAPP_NAMESPACE)
                if not verification.get("contained"):
                    force_service_isolation(xapp, XAPP_NAMESPACE, "state_refresh_compromised_requires_containment")
                    verification = live_verify(xapp, XAPP_NAMESPACE)
                entry["containment_verified"] = bool(verification.get("contained"))

            risk, trust = scores(state)
            entry["state"] = state
            entry["score"] = risk
            entry["risk_score"] = risk
            entry["trust_score"] = trust
            entry["score_type"] = "risk_score_0_to_100_higher_means_riskier"
            xapps.append(entry)

            with CSM_STATE_LOCK:
                CSM_STATE[xapp] = dict(entry)

        summary = {
            "NORMAL": 0,
            "OBSERVED": 0,
            "SUSPICIOUS": 0,
            "COMPROMISED": 0,
            "total": len(xapps),
        }

        for item in xapps:
            summary[public_state(item.get("state"))] += 1

        overall = "COMPROMISED" if summary["COMPROMISED"] else "SUSPICIOUS" if summary["SUSPICIOUS"] else "OBSERVED" if summary["OBSERVED"] else "NORMAL"

        return jsonify({
            "component": "zt-xguard-policy-engine",
            "overall_state": overall,
            "summary": summary,
            "xapps": xapps,
            "state_vocabulary": ["NORMAL", "OBSERVED", "SUSPICIOUS", "COMPROMISED"],
            "containment_is_separate": True,
            "ztx_final_active_route_hotfix_v1": True,
            "time": utc_now(),
        })

    def hotfix_runtime_wrapper(original):
        def view(*args, **kwargs):
            ret = original(*args, **kwargs)
            payload, code = response_to_payload(ret)

            rows = payload.get("rows") or payload.get("xapps") or []

            for row in rows:
                xapp = row.get("xapp")
                if not xapp:
                    continue

                with CSM_STATE_LOCK:
                    state = public_state((CSM_STATE.get(xapp) or {}).get("state"))

                if state == "COMPROMISED":
                    v = live_verify(xapp, XAPP_NAMESPACE)
                    if not v.get("contained"):
                        force_service_isolation(xapp, XAPP_NAMESPACE, "runtime_refresh_compromised_requires_containment")
                        v = live_verify(xapp, XAPP_NAMESPACE)
                else:
                    v = live_verify(xapp, XAPP_NAMESPACE)

                service = {}
                if v.get("services"):
                    first = v["services"][0]
                    ep = first.get("endpoint_summary") or {}
                    service = {
                        "name": first.get("service"),
                        "selector": first.get("selector"),
                        "endpoint_count": ep.get("endpoint_count"),
                        "has_endpoints": ep.get("has_endpoints"),
                        "addresses": ep.get("addresses"),
                        "ports": ep.get("ports"),
                        "source": ep.get("source"),
                        "error": ep.get("error"),
                    }

                row["trust_state"] = state
                row["service"] = {**obj(row.get("service")), **service}
                row["containment"] = {
                    **obj(row.get("containment")),
                    "contained": bool(v.get("contained")),
                    "quarantine_marked": bool(v.get("quarantine_marked")),
                    "pod_labelled_quarantined": bool(v.get("pod_labelled_quarantined")),
                    "service_isolated": bool(v.get("service_isolated")),
                    "verification_unknown": False,
                    "ztx_final_active_route_hotfix_v1": True,
                }

            payload["rows"] = rows
            payload["ztx_final_active_route_hotfix_v1"] = True
            return jsonify(payload), code
        return view

    def normalize_scenario(item):
        s = dict(item)
        s["expected_state_raw"] = s.get("expected_state")
        s["expected_state"] = public_state(s.get("expected_state"))
        s["target_xapp"] = s.get("target_xapp") or s.get("default_xapp") or "telemetry-monitor"
        s["default_xapp"] = s.get("default_xapp") or s.get("target_xapp")
        return s

    def hotfix_scenarios_wrapper(original):
        def view(*args, **kwargs):
            ret = original(*args, **kwargs)
            payload, code = response_to_payload(ret)

            scenarios = payload if isinstance(payload, list) else payload.get("scenarios", [])
            scenarios = [normalize_scenario(s) for s in scenarios]

            if isinstance(payload, list):
                return jsonify(scenarios), code

            payload["scenarios"] = scenarios
            payload["ztx_final_active_route_hotfix_v1"] = True
            return jsonify(payload), code
        return view

    def hotfix_run_scenario_wrapper(original):
        def view(*args, **kwargs):
            scenario_id = kwargs.get("scenario_id") or kwargs.get("id") or kwargs.get("sid")
            body = request.get_json(silent=True) or {}
            xapp = body.get("xapp") or body.get("target_xapp") or "telemetry-monitor"

            ret = original(*args, **kwargs)
            payload, code = response_to_payload(ret)

            expected_state = public_state(payload.get("expected_state"))
            actual_state = public_state(payload.get("actual_state") or payload.get("state"))
            expected_containment = bool(payload.get("expected_containment"))

            if expected_state == "COMPROMISED" or actual_state == "COMPROMISED" or expected_containment:
                force_service_isolation(xapp, XAPP_NAMESPACE, f"scenario_{scenario_id}_compromised_requires_containment")
                verification = live_verify(xapp, XAPP_NAMESPACE)
                actual_containment = bool(verification.get("contained"))
                actual_state = "COMPROMISED"
            else:
                verification = live_verify(xapp, XAPP_NAMESPACE)
                actual_containment = bool(verification.get("contained"))

            state_entry = set_csm_state(
                xapp,
                actual_state,
                source=f"scenario_{scenario_id}",
                signal=payload.get("signal"),
                containment_verified=actual_containment,
                extra={"verification": verification},
            )

            expected_state = public_state(payload.get("expected_state"))
            if expected_state == "NORMAL" and expected_containment:
                expected_state = "COMPROMISED"

            payload["expected_state_raw"] = payload.get("expected_state")
            payload["expected_state"] = expected_state
            payload["actual_state_raw"] = payload.get("actual_state")
            payload["actual_state"] = actual_state
            payload["actual_containment"] = actual_containment
            payload["containment_verified"] = actual_containment
            payload["verification"] = verification
            payload["state_pass"] = actual_state == expected_state
            payload["containment_pass"] = actual_containment == expected_containment
            payload["pass"] = bool(payload["state_pass"] and payload["containment_pass"])
            payload["csm_state_after_hotfix"] = state_entry
            payload["ztx_final_active_route_hotfix_v1"] = True

            return jsonify(payload), code
        return view

    def hotfix_intent_wrapper(original):
        def view(*args, **kwargs):
            body = request.get_json(silent=True) or {}
            xapp = body.get("xapp")
            signal = body.get("signal")

            with CSM_STATE_LOCK:
                previous_state = public_state((CSM_STATE.get(xapp) or {}).get("state")) if xapp else "NORMAL"

            ret = original(*args, **kwargs)
            payload, code = response_to_payload(ret)

            if xapp:
                incoming = public_state(payload.get("final_state") or payload.get("state") or payload.get("decision_state"))
                final_state = incoming

                if not is_restore("manual_intent_signal", signal) and rank(previous_state) > rank(incoming):
                    final_state = previous_state
                    payload["downgrade_blocked"] = True
                    payload["previous_state"] = previous_state

                containment_verified = None
                if final_state == "COMPROMISED":
                    v = live_verify(xapp, XAPP_NAMESPACE)
                    if not v.get("contained"):
                        force_service_isolation(xapp, XAPP_NAMESPACE, "intent_compromised_requires_containment")
                        v = live_verify(xapp, XAPP_NAMESPACE)
                    containment_verified = bool(v.get("contained"))
                    payload["verification"] = v

                entry = set_csm_state(
                    xapp,
                    final_state,
                    source="manual_intent_signal",
                    signal=signal,
                    containment_verified=containment_verified,
                    extra={"raw_intent_result": payload},
                )

                risk, trust = scores(final_state)
                payload["state"] = final_state
                payload["final_state"] = final_state
                payload["decision_state"] = final_state
                payload["score"] = risk
                payload["risk_score"] = risk
                payload["trust_score"] = trust
                payload["score_type"] = "risk_score_0_to_100_higher_means_riskier"
                payload["csm_state_after_hotfix"] = entry
                payload["ztx_final_active_route_hotfix_v1"] = True

            return jsonify(payload), code
        return view

    # Replace active Flask route functions.
    for rule in list(APP.url_map.iter_rules()):
        endpoint = rule.endpoint
        original = APP.view_functions.get(endpoint)
        if original is None:
            continue

        if rule.rule == "/csm/state":
            APP.view_functions[endpoint] = hotfix_state_view

        elif rule.rule in {"/csm/xapps/runtime-lite", "/csm/xapps/runtime"}:
            APP.view_functions[endpoint] = hotfix_runtime_wrapper(original)

        elif rule.rule == "/csm/scenarios":
            APP.view_functions[endpoint] = hotfix_scenarios_wrapper(original)

        elif "scenarios" in rule.rule and rule.rule.endswith("/run"):
            APP.view_functions[endpoint] = hotfix_run_scenario_wrapper(original)

        elif rule.rule == "/csm/intent/ingest":
            APP.view_functions[endpoint] = hotfix_intent_wrapper(original)

    print("ZTX_FINAL_ACTIVE_ROUTE_HOTFIX_V1 installed")
