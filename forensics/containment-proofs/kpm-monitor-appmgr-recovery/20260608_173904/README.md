# ZT-XGuard KPM Monitor + AppMgr Recovery Snapshot

Date: 2026-06-08T17:39:04+05:30

## Current Understanding

- NIST O-RAN single-VM testbed is running.
- RIC platform services are running in ricplt.
- kpm-monitor is running in ricxapp.
- AppMgr health endpoint returns 200 OK.
- AppMgr xApps list currently returns [].
- service-ricplt-xapp-onboarder-http currently points to 192.168.112.129:8090.
- That endpoint returns ChartMuseum welcome page.
- Therefore, the current xapp-onboarder service is acting as ChartMuseum/chart repo endpoint, not a normal onboarder API pod.
