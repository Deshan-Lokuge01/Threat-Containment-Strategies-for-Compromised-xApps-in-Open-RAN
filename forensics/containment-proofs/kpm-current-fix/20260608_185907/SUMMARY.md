# KPM Current Fix Summary

Main issue before fix:
kpm-monitor was running and RMR-ready, but subscription_success stayed 0.
Pod logs showed E2 state CHECK_FAILED, meaning the xApp could not reliably read E2Mgr node state.

Fix attempted:
- Probe E2Mgr from host and inside kpm-monitor pod.
- Force kpm-monitor to use E2Mgr ClusterIP URL:
  http://10.108.243.89:3800/v1/nodeb/states
- Repost RTMgr accepted xApp registration body.
- Restart kpm-monitor for a clean subscription attempt.

Evidence:
evidence/kpm-current-fix/20260608_185907
