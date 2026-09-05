# dos-detector — runtime onboarding demo xApp

A custom xApp named **dos-detector**, built to demonstrate secure runtime onboarding into the guarded
RIC. It shows a peer operator adding a new xApp to a running cluster and that xApp being attested and
issued a SPIFFE/SVID identity through the same zero-trust flow that protects every other xApp.

- It is deployed into the `ricxapp` namespace with a real SPIRE workload attestation (SVID issued and
  renewed by a sidecar).
- It starts scaled to zero and is revealed by a scale-up command, so the onboarding can be shown live.
- It uses the standard `zt-xguard.io/svid-enabled=true` identity label, so the moment it starts it is
  attested and, if it ever misbehaves, subject to the same four-lock containment as the rest.

This folder holds the manifests and the demo helper material for that onboarding walkthrough.
