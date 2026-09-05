# xApps and security profiles

The third-party microservices ZT-XGuard guards, and the declarative profiles that define what each
one is allowed to do.

## Guarded xApps

The Near-RT RIC runs four xApps that the framework watches: `kpimon-go` (KPM monitoring — the one the
T² DoS detector observes), `trafficxapp`, `hw-go`, and `hw-python`. Additional profiled xApp roles
(traffic-analyzer, telemetry-monitor, qos-optimizer, resource-optimizer, security-observer) are used
in the behavioural evaluation.

## Security profiles

`security-profiles/` holds a declarative profile per xApp. A profile states what is normal for that
workload — which services it may contact, which files it may touch, whether it may spawn processes —
so the Falco rule set can be strict where it should be and permissive where a behaviour is legitimate.
The trust evaluation is driven from these profiles rather than hard-coded per xApp.
