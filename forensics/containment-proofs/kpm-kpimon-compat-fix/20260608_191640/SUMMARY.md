# KPM kpimon-go Compatibility Fix

Problem:
RTMgr does not know service-ricxapp-kpm-monitor-rmr.ricxapp:4560 as an xApp instance.

Fix:
Created service-ricxapp-kpimon-go-rmr.ricxapp as a compatibility alias pointing to kpm-monitor.
Changed kpm-monitor ClientEndpoint.Host to service-ricxapp-kpimon-go-rmr.ricxapp.

Reason:
RTMgr already has kpimon-go in its xApp instance table, so using the known endpoint avoids the AppMgr registration gap.

Evidence:
evidence/kpm-kpimon-compat-fix/20260608_191640
