"""
ZT-XGuard Policy Engine - shared Kubernetes API client singletons.

Extracted from app.py during step_xguard_02 Step B1 (2026-07-15) so that
containment_orchestrator.py and app.py use the same client construction
without app.py needing to be imported back into containment_orchestrator.py.
"""
from __future__ import annotations

from kubernetes import client, config

try:
    config.load_incluster_config()
except Exception:
    config.load_kube_config()

CORE = client.CoreV1Api()
APPS = client.AppsV1Api()
NET = client.NetworkingV1Api()

# 2026-07-24: dedicated CoreV1Api instance (own ApiClient, own connection
# pool) for exec/attach calls specifically (kubernetes.stream.stream(),
# used for direct-iptables enforcement and SPIRE entry revocation).
# Sharing the CORE singleton between websocket-upgrade exec calls and
# regular REST calls caused CORE's pooled connections to intermittently
# get corrupted under concurrent load - observed live as /ready failing
# with a bogus "Handshake status 200 OK" error on a plain
# list_namespaced_pod call (a regular REST call reusing a connection last
# used for a websocket upgrade). Confirmed live: a freshly constructed
# CoreV1Api() in the same broken pod worked fine while CORE kept failing -
# isolating the corruption to CORE's own connection pool, not the API
# server. Giving exec calls their own client removes the shared pool
# entirely.
EXEC_CORE = client.CoreV1Api()
# Calico's native NetworkPolicy (crd.projectcalico.org/v1) isn't a built-in
# API type, so it goes through CustomObjectsApi rather than NET - added for
# Phase 3's tiered SUSPICIOUS-tier policy (2026-07-17).
CUSTOM = client.CustomObjectsApi()
