# RTMgr Route Registration Debug

Problem:
kpm-monitor successfully sends a subscription request, but SubMgr fails to create routeinfo with RTMgr.

Observed:
RTMgr route table contains stale xApps hw-go and kpimon-go, but does not contain kpm-monitor.

Goal:
Find where RTMgr/AppMgr stores or reads xApp routing metadata, then register kpm-monitor correctly.
