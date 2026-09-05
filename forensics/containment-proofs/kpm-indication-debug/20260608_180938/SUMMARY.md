# Summary

Collected evidence for KPM indication failure.

Known before debug:
- kpm-monitor has RMR ready.
- kpm-monitor successfully sends subscription request.
- Subscription accepted with HTTP 201.
- kpm-monitor metrics show RMR messages total = 0.

Files to inspect:
- kpm-logs-tail500.txt
- kpm-metrics.txt
- e2mgr-api-probe.txt
- submgr-api-probe.txt
- deployment-ricplt-submgr-filtered.txt
- deployment-ricplt-rtmgr-filtered.txt
- deployment-ricplt-e2term-alpha-filtered.txt
- deployment-ricplt-e2mgr-filtered.txt
- ran-related-pods.txt
