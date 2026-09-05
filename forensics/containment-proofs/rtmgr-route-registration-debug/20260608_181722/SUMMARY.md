# Summary

Collected evidence to identify why RTMgr does not include kpm-monitor in the RMR route table.

Known failure:
SubMgr cannot create routeinfo for kpm-monitor. RTMgr currently contains stale xApp route entries for hw-go and kpimon-go.
