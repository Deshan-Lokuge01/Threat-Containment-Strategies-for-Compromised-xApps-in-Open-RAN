#!/usr/bin/env python3
import curses
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

ENGINE = "http://127.0.0.1:15000"
XAPPS = [
    "telemetry-monitor",
    "qos-optimizer",
    "traffic-analyzer",
    "resource-optimizer",
    "security-observer",
]

def get_json(path, timeout=3):
    try:
        with urllib.request.urlopen(ENGINE + path, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"ok": False, "error": str(e)}

def find_xapp(obj, xapp):
    if isinstance(obj, dict):
        if obj.get("xapp") == xapp:
            return obj
        for v in obj.values():
            found = find_xapp(v, xapp)
            if found:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = find_xapp(v, xapp)
            if found:
                return found
    return None

def state_rank(state):
    return {
        "UNKNOWN": 0,
        "TRUSTED": 1,
        "RESTORED": 1,
        "OBSERVED": 2,
        "SUSPICIOUS": 3,
        "COMPROMISED": 4,
        "QUARANTINED": 5,
    }.get(str(state or "UNKNOWN").upper(), 0)

def color_for_state(state):
    s = str(state or "UNKNOWN").upper()
    if s in ("TRUSTED", "RESTORED"):
        return 1
    if s == "OBSERVED":
        return 2
    if s == "SUSPICIOUS":
        return 3
    if s in ("COMPROMISED", "QUARANTINED"):
        return 4
    return 5

def safe_get(d, *path, default=""):
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return default if cur is None else cur

def draw(stdscr):
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()

    curses.init_pair(1, curses.COLOR_GREEN, -1)
    curses.init_pair(2, curses.COLOR_CYAN, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_RED, -1)
    curses.init_pair(5, curses.COLOR_WHITE, -1)
    curses.init_pair(6, curses.COLOR_MAGENTA, -1)

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        health = get_json("/health")
        state = get_json("/csm/state")
        runtime = get_json("/csm/xapps/runtime")
        incidents = get_json("/incidents")

        title = "ZT-XGuard Terminal Console | q=quit | r=refresh | read-only"
        stdscr.addstr(0, 0, title[:w-1], curses.A_BOLD)

        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        health_line = (
            f"UTC={ts}  "
            f"health={health.get('status')}  "
            f"engine={health.get('state_engine_version')}  "
            f"import_error={health.get('state_engine_import_error')}"
        )
        stdscr.addstr(1, 0, health_line[:w-1])

        header = (
            f"{'xApp':22} {'State':14} {'Det.State':14} "
            f"{'Trust':7} {'Risk':7} {'EP':4} {'Isolated':9} {'Contained':9} {'Source':18}"
        )
        stdscr.addstr(3, 0, header[:w-1], curses.A_UNDERLINE)

        row = 4
        for xapp in XAPPS:
            s_item = find_xapp(state, xapp) or {}
            r_item = find_xapp(runtime, xapp) or {}

            st = (
                s_item.get("state")
                or s_item.get("decision_state")
                or safe_get(s_item, "decision", "state")
                or "UNKNOWN"
            )
            det = (
                s_item.get("detection_state")
                or s_item.get("decision_state")
                or st
            )

            trust = s_item.get("trust_score", "")
            risk = s_item.get("risk_score", "")
            score = s_item.get("score", "")

            if risk == "" and score != "":
                risk = score

            ep = safe_get(r_item, "service", "endpoint_count", default="")
            isolated = safe_get(r_item, "containment", "service_isolated", default="")
            contained = safe_get(r_item, "containment", "contained", default="")
            src = s_item.get("last_source", "")

            line = (
                f"{xapp:22} {str(st):14} {str(det):14} "
                f"{str(trust):7} {str(risk):7} {str(ep):4} "
                f"{str(isolated):9} {str(contained):9} {str(src):18}"
            )

            attr = curses.color_pair(color_for_state(st))
            if str(st).upper() in ("COMPROMISED", "QUARANTINED"):
                attr |= curses.A_BOLD

            if row < h - 8:
                stdscr.addstr(row, 0, line[:w-1], attr)
            row += 1

        row += 1
        stdscr.addstr(row, 0, "Recent incidents:", curses.A_BOLD)
        row += 1

        inc_list = incidents.get("incidents", []) if isinstance(incidents, dict) else []
        for inc in inc_list[:5]:
            xapp = inc.get("xapp", "?")
            sig = inc.get("signal", inc.get("rule", "?"))
            t = inc.get("time", inc.get("timestamp", "?"))
            p = inc.get("path", inc.get("evidence_path", ""))
            line = f"- {t} | {xapp} | {sig} | {p}"
            if row < h - 2:
                stdscr.addstr(row, 0, line[:w-1], curses.color_pair(6))
            row += 1

        stdscr.addstr(h-1, 0, "Containment proof = endpoint_count=0 + service_isolated=true + contained=true. Pod may still be Running.", curses.A_DIM)

        stdscr.timeout(2000)
        ch = stdscr.getch()
        if ch in (ord("q"), ord("Q")):
            break

def main():
    curses.wrapper(draw)

if __name__ == "__main__":
    main()
