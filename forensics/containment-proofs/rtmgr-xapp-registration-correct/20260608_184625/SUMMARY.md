# RTMgr xApp Registration Fix Summary

Problem:
RTMgr did not know kpm-monitor. SubMgr failed with:
XApp instance not found: service-ricxapp-kpm-monitor-rmr.ricxapp:4560

Root cause:
A raw xApp array was posted to RTMgr, but this RTMgr build expects an AppMgr-style XappCallbackData object.

Fix:
Register kpm-monitor with RTMgr using the accepted callback body stored at:
evidence/rtmgr-xapp-registration-correct/20260608_184625/ACCEPTED-rtmgr-xapp-callback-body.json

Permanent pipeline rule:
After every verified Helm deployment, ZT-XGuard must register the xApp RMR endpoint with RTMgr before starting subscriptions.
