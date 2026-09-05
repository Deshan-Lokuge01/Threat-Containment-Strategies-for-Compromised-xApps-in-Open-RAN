# O-RAN testbed

The RAN side of this project runs on the NIST
[O-RAN-Testbed-Automation](https://github.com/usnistgov/O-RAN-Testbed-Automation), which builds a
full stack:

```
OpenAirInterface 5G Core  ──►  gNB (CU/DU)  ──►  UE (emulated over ZMQ)
                                   │
                                   └── E2 ──►  OSC Near-RT RIC (ricplt + xApps)
```

That upstream repository is several gigabytes of downloaded source and build artifacts, so it is
**not** vendored here. This folder holds only our own additions on top of it:

- `scripts/` — the run scripts we use to bring the stack up in a single-UE configuration
  (`start-1ue.sh`, `switch-to-1ue-temporary.sh`) and to launch the Grafana web UI
  (`start_grafana_webui.sh`).
- `kpimon-fix/` — the kpimon-go ↔ OSC Near-RT RIC connectivity bug we found and fixed, reported
  upstream as issue #13. See its own README.

## Bringing the RAN up

```bash
# from a clone of usnistgov/O-RAN-Testbed-Automation, with our scripts copied in:
./start-1ue.sh          # starts 5G core, gNB, and one UE
```

The Near-RT RIC is deployed as a Kubernetes cluster (ricplt + ricxapp namespaces). ZT-XGuard then
runs on top of that cluster and guards the xApps.

## Monitoring

A Grafana + Prometheus stack visualises RAN KPIs. Bring the Grafana UI up with
`scripts/start_grafana_webui.sh` (defaults to `http://localhost:3300`, admin/admin). The ZT-XGuard
xApp/CSM Grafana dashboard definition is under [`../monitoring/grafana/`](../monitoring/grafana/).
