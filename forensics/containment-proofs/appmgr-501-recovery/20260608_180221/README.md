# AppMgr 501 Recovery

Finding:
AppMgr POST /ric/v1/xapps returned 501 Not Implemented:
"operation XappDeployXapp has not yet been implemented"

Conclusion:
The deployed AppMgr image exposes the route in the REST API specification, but the deployXapp handler is not implemented in this build. Therefore AppMgr REST deployment cannot be used as the reliable xApp deployment path in this testbed.

Decision:
Use the ZT-XGuard secure onboarding pipeline + ChartMuseum + Helm deployment path as the reliable lifecycle mechanism. Continue with RIC/KPM indication debugging after restoring kpm-monitor.
