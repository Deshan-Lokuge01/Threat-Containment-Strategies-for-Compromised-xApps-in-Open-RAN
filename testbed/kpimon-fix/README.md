# Fixing kpimon-go ↔ OSC Near-RT RIC connectivity (upstream issue #13)

**Upstream issue:** [usnistgov/O-RAN-Testbed-Automation#13](https://github.com/usnistgov/O-RAN-Testbed-Automation/issues/13)

## The problem

On the OSC Near-RT RIC brought up by the testbed automation, the **kpimon-go** xApp could not
complete its side of the E2 flow. It would deploy and run, but it never got to a working KPM
subscription against the connected gNB — so no `RIC_INDICATION` (KPM measurement) messages ever came
back, and there was no live telemetry to build the security monitoring on top of. Without kpimon-go
actually receiving indications, the whole detection pipeline had nothing to watch.

## The fix

We worked through the E2 path — the RMR routing between `service-ricxapp-kpimon-go-rmr.ricxapp` and
`service-ricplt-e2term-rmr-alpha.ricplt`, app registration with the RIC, and the subscription request
to the gNB — and corrected the configuration so kpimon-go registers, subscribes, and receives KPM
indications end to end.

## Evidence (in `success-evidence/`)

After the fix, the kpimon-go log shows the complete, working sequence:

```
Connection to database established!
List for connected gNBs: [gnbd_001_001_00019b_0]
App registration is done, ready to send subscription request.
Sending subscription request for MEID: gnbd_001_001_00019b_0
Successfully subscription done (gnbd_001_001_00019b_0), subscription id: 3EuYbZ8Uzx34idQIgrm8Nx3rNg6
Message received: name=RIC_INDICATION meid=gnbd_001_001_00019b_0 ...
RIC Indication message from {gnbd_001_001_00019b_0} received
```

- `kpimon_success.log` — the full log showing registration → subscription → RIC_INDICATION.
- `kpimon_deployment.yaml` — the working kpimon-go deployment.
- `ricxapp_pods.txt` — the xApp pods running (kpimon-go healthy).
- `submgr_after_success.log` — the subscription manager side after the subscription succeeded.

## Actuator xApp

`actuator-xapp-source/` and `actuator-xapp-image/` contain the kpimon-based actuator xApp we built on
top of the working KPM pipeline — the same xApp the T² resource detector later monitors.

> This connectivity fix is what made the rest of the project possible: once kpimon-go received live
> KPM indications, we had real per-xApp resource telemetry to detect DoS attacks against.
