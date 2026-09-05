# Summary

## Status
- AppMgr is running and health endpoint is OK.
- AppMgr currently reports no deployed xApps through /ric/v1/xapps.
- kpm-monitor is running as a Helm release in ricxapp.
- service-ricplt-xapp-onboarder-http points to host endpoint 192.168.112.129:8090.
- The endpoint returns ChartMuseum HTML, so this is currently ChartMuseum/chart repo access.

## Main Issue
Official AppMgr/onboarder recognition path is not confirmed yet. kpm-monitor is deployed, but AppMgr does not list it.

## Next Debug Focus
1. Check ChartMuseum contains kpm-monitor chart.
2. Check AppMgr config for chart repo URL.
3. Check whether kpm-monitor was deployed manually or through AppMgr.
4. Check whether official xapp_onboarder Python API is actually running.

## Update: ChartMuseum / AppMgr Diagnosis

The service named service-ricplt-xapp-onboarder-http is currently acting as a ChartMuseum alias, not as a normal xApp onboarder API pod.

Evidence:
- service-ricplt-xapp-onboarder-http has no selector.
- It manually points to endpoint 192.168.112.129:8090.
- curl to the service returns the ChartMuseum welcome page.
- Host port 8090 is handled by docker-proxy.
- ChartMuseum /api/charts lists hw-go, hw-python, kpimon-go, rc, and trafficxapp.
- ChartMuseum does not list kpm-monitor.
- AppMgr /ric/v1/xapps returns [].
- Therefore, the current kpm-monitor was deployed manually with Helm and is not currently managed by AppMgr.

Next required step:
Package the kpm-monitor Helm chart and upload it to ChartMuseum, then test whether AppMgr can deploy/list it.

## Recovery Update: Official AppMgr/onboarder work

The current work is focused on getting the official O-RAN SC xApp lifecycle path working for kpm-monitor.

Goal:
- kpm-monitor should not only run as a manual Helm release.
- It should be onboarded/discovered through the AppMgr/ChartMuseum/onboarder path.
- After AppMgr lifecycle works, the next issue is RIC/KPM indication delivery.

Current evidence:
- kpm-monitor verified Helm chart exists under roles/smo/charts/verified/kpm-monitor.
- kpm-monitor packaged chart exists under roles/smo/charts/verified/packages/kpm-monitor-1.0.0.tgz.
- ChartMuseum is reachable on host port 8090.
- ChartMuseum currently lists hw-go, hw-python, kpimon-go, rc, and trafficxapp.
- ChartMuseum does not currently list kpm-monitor.
- AppMgr /ric/v1/xapps returns [].
- Therefore, kpm-monitor is deployed manually/through ZT-XGuard Helm registration, not yet through AppMgr.

Next action:
Upload kpm-monitor-1.0.0.tgz to ChartMuseum and verify it appears in /api/charts. Then test AppMgr discovery/deployment.

## Update: kpm-monitor uploaded to ChartMuseum

Result:
- Upload of roles/smo/charts/verified/packages/kpm-monitor-1.0.0.tgz to ChartMuseum succeeded.
- ChartMuseum returned HTTP 201 Created and {"saved":true}.
- /api/charts/kpm-monitor now returns kpm-monitor version 1.0.0.
- AppMgr /ric/v1/xapps still returns [].

Interpretation:
- Chart repository stage is now working.
- AppMgr still does not manage kpm-monitor because the existing kpm-monitor release was installed directly using Helm/ZT-XGuard registration.
- Next step is to inspect AppMgr deploy API and deploy through AppMgr after safely removing the manual Helm release.

## Update: AppMgr API and config inspection

Findings:
- AppMgr exposes deployXapp through POST /ric/v1/xapps.
- AppMgr exposes getAllXapps through GET /ric/v1/xapps.
- AppMgr exposes undeployXapp through DELETE /ric/v1/xapps/{xAppName}.
- /ric/v1/xapps/list exists in API but returns 501 Not Implemented in this build.
- The API schema includes deploy fields such as helmVersion, releaseName, and namespace.
- Source config/appmgr.yaml contains old static helm repo values: http://192.168.0.6/charts.
- Need to inspect the running AppMgr pod config before using AppMgr deploy.

Next step:
Confirm the runtime AppMgr configuration and exact deploy request schema.
