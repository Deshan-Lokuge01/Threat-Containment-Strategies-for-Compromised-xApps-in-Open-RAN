#!/usr/bin/env python3
"""Generates the per-xApp rule-violation trigger scripts under this folder.

Not itself an attack script - a one-time generator, kept here for
traceability/regeneration if the rule set or xApp list ever changes. Reads
nothing live from the cluster; the applicability table and per-xApp allowed
targets below are transcribed directly from
zt-xguard/ztx-control-plane/policy-engine/falco/ztx-xapp-rules.yaml as of
2026-07-14 (18 rules, all 9 xApps covered - see that file for the source of
truth if rules change later).
"""
import os
import stat

BASE = os.path.dirname(os.path.abspath(__file__))

# 12 universal rules - identical trigger command regardless of which xApp,
# apply to all 9 xApps via ztx_controlled_xapp (no profile needed).
UNIVERSAL_RULES = [
    dict(id="ZTX-A1", key="unexpected_shell", title="Unexpected Shell", severity="CRITICAL",
         desc="Spawns a shell (sh) inside the main container - one of the 6 exact programs the rule watches (sh, bash, dash, zsh, ksh, ash).",
         cmd=["sh", "-c", "true"]),
    dict(id="ZTX-A2", key="sensitive_file_access", title="Sensitive File Access", severity="CRITICAL",
         desc="Opens /etc/passwd - one of the 3 named sensitive files the rule watches (/etc/shadow, /etc/sudoers, /etc/passwd), chosen because it's world-readable everywhere so the demo doesn't depend on container UID/permissions.",
         cmd=["cat", "/etc/passwd"]),
    dict(id="ZTX-A3", key="serviceaccount_token_access", title="ServiceAccount Token Access", severity="CRITICAL",
         desc="Opens the Kubernetes-mounted ServiceAccount token file - the exact path prefix the rule watches (/var/run/secrets/kubernetes.io/serviceaccount).",
         cmd=["cat", "/var/run/secrets/kubernetes.io/serviceaccount/token"]),
    dict(id="ZTX-A6", key="malicious_tool_execution", title="Suspicious Tool Execution", severity="WARNING",
         desc="Executes python3 - one of the 12 exact programs the rule watches (curl, wget, nc, ncat, netcat, socat, ssh, scp, python, python3, perl, ruby). This is also the family of invocation Peirates itself uses.",
         cmd=["python3", "--version"]),
    dict(id="ZTX-A8", key="external_egress", title="External Egress Attempt", severity="CRITICAL",
         desc="Connects to a public internet address (8.8.8.8) - fails every destination check in ztx_known_internal_dest (not a RIC-platform service, not a peer xApp, not the Kubernetes API, not CoreDNS), so it is genuinely outside every destination this xApp is ever expected to reach. curl is not installed in these images, so the trigger uses python3's urllib the same way this project's own verification steps have throughout.",
         cmd=["python3", "-c", "import urllib.request; urllib.request.urlopen('http://8.8.8.8', timeout=3)"]),
    dict(id="ZTX-A11", key="svid_material_access", title="SVID Or SPIFFE Material Access", severity="CRITICAL",
         desc="Reads SVID certificate material directly from the MAIN container (not the renew-svid sidecar, which is the only place this is expected) - one of the 16 listed read tools (cat) on a path under /etc/svid.",
         cmd=["cat", "/etc/svid/svid.0.pem"]),
    dict(id="ZTX-A12", key="xapp_profile_or_config_tamper", title="Profile Or Config Tamper", severity="CRITICAL",
         desc="Changes permissions on the mounted xApp profile file - chmod is one of the write/metadata-tamper operations the rule watches, on a path under /etc/xapp-profile.",
         cmd=["chmod", "644", "/etc/xapp-profile/profile.json"]),
    dict(id="ZTX-A13", key="package_manager_execution", title="Package Manager Execution", severity="WARNING",
         desc="Executes pip3 - one of the 9 exact package-manager programs the rule watches (apt, apt-get, apk, yum, dnf, rpm, dpkg, pip, pip3).",
         cmd=["pip3", "--version"]),
    dict(id="ZTX-A14", key="binary_drop", title="Binary Drop In Writable Path", severity="WARNING",
         desc="Writes a file ending in .sh into /tmp/ - matches both conditions the rule requires (one of the 3 writable locations, one of the 8 watched extensions).",
         cmd=["sh", "-c", "echo demo > /tmp/ztx_demo_drop.sh"]),
    dict(id="ZTX-A15", key="permission_tamper", title="Permission Tamper", severity="WARNING",
         desc="Executes chmod - one of the 3 exact programs the rule watches (chmod, chown, setcap). Creates a throwaway file first so the chmod itself succeeds cleanly.",
         cmd=["sh", "-c", "touch /tmp/ztx_demo_perm_test && chmod 644 /tmp/ztx_demo_perm_test"]),
    dict(id="ZTX-A16", key="k8s_api_contact", title="Kubernetes API Contact", severity="WARNING",
         desc="Connects to the Kubernetes API server on port 443 via its in-cluster DNS name - matches the rule's hostname check. No ServiceAccount token is presented, so the API call itself will likely be rejected (401/403) - that's fine, the rule fires on the network connection attempt, not on successful authentication.",
         cmd=["python3", "-c",
              "import ssl,urllib.request; ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE; urllib.request.urlopen('https://kubernetes.default.svc.cluster.local', timeout=3, context=ctx)"]),
    dict(id="ZTX-LM-03", key="privileged_container_escape_attempt", title="Privileged Container Escape Attempt", severity="CRITICAL",
         desc="Attempts to open two of the 6 watched container-runtime socket paths (Docker and containerd variants) - a real container-escape probing technique (MITRE ATT&CK T1611), and the same kind of candidate-path probing Peirates itself performs. Expected to fail (socket not present/not permitted) - the rule fires on the open attempt itself, not on success.",
         cmd=["sh", "-c", "cat /var/run/docker.sock 2>/dev/null; cat /run/containerd/containerd.sock 2>/dev/null; true"]),
]

# The 4 non-profiled real xApps: universal rules only (rules 6/7 structurally
# do not apply - see ztx_profiled_xapp in the rules file, which deliberately
# excludes these 4 because they have no declared allow-list to check against).
NON_PROFILED_XAPPS = {
    "kpimon-go": dict(pod_pattern="ricxapp-kpimon-go", container="kpimon-go"),
    "hw-go": dict(pod_pattern="ricxapp-hw-go", container="hw-go"),
    "hw-python": dict(pod_pattern="ricxapp-hw-python", container="hw-python"),
    "trafficxapp": dict(pod_pattern="ricxapp-trafficxapp", container="trafficxapp"),
}

# The 5 profiled xApps get the 12 universal rules PLUS rules 6/7, each with a
# per-xApp target chosen to be genuinely disallowed under that specific
# xApp's own profile (k8s/profiles/*.json), not a generic guess. Every port
# used below (e2mgr:3800, appmgr:8080, peer-xApp services:8080) is taken
# directly from this session's own live Falco log observations, not assumed
# - prometheus's port is never needed here since no xApp's chosen "unexpected"
# rule-7 target below happens to be prometheus.
PROFILED_XAPPS = {
    "telemetry-monitor": dict(
        pod_pattern="telemetry-monitor", container="telemetry-monitor",
        # allowed_ric_services=[e2mgr], allowed_peers=[]
        rule6_target=("traffic-analyzer.ricxapp.svc.cluster.local", 8080, "any peer is unexpected - allowed_peers is empty"),
        rule7_target=("service-ricplt-appmgr-http.ricplt.svc.cluster.local", 8080, "only e2mgr is allowed, appmgr is not"),
    ),
    "traffic-analyzer": dict(
        pod_pattern="traffic-analyzer", container="traffic-analyzer",
        # allowed_ric_services=[], allowed_peers=[telemetry-monitor]
        rule6_target=("qos-optimizer.ricxapp.svc.cluster.local", 8080, "only telemetry-monitor is allowed, qos-optimizer is not"),
        rule7_target=("service-ricplt-e2mgr-http.ricplt.svc.cluster.local", 3800, "any RIC service is unexpected - allowed_ric_services is empty"),
    ),
    "qos-optimizer": dict(
        pod_pattern="qos-optimizer", container="qos-optimizer",
        # allowed_ric_services=[], allowed_peers=[traffic-analyzer]
        rule6_target=("telemetry-monitor.ricxapp.svc.cluster.local", 8080, "only traffic-analyzer is allowed, telemetry-monitor is not"),
        rule7_target=("service-ricplt-e2mgr-http.ricplt.svc.cluster.local", 3800, "any RIC service is unexpected - allowed_ric_services is empty"),
    ),
    "resource-optimizer": dict(
        pod_pattern="resource-optimizer", container="resource-optimizer",
        # allowed_ric_services=[prometheus], allowed_peers=[]
        rule6_target=("telemetry-monitor.ricxapp.svc.cluster.local", 8080, "any peer is unexpected - allowed_peers is empty"),
        rule7_target=("service-ricplt-e2mgr-http.ricplt.svc.cluster.local", 3800, "only prometheus is allowed, e2mgr is not"),
    ),
    "security-observer": dict(
        pod_pattern="security-observer", container="security-observer",
        # allowed_ric_services=[], allowed_peers=[all 4 others] - rule 6 is
        # STRUCTURALLY IMPOSSIBLE for this xApp: its own allow-list already
        # covers every peer the rule could ever flag as unexpected, so no
        # trigger script is generated for rule 6 here - generating one that
        # can never fire would be dishonest filler, not a real scenario.
        rule6_target=None,
        rule7_target=("service-ricplt-e2mgr-http.ricplt.svc.cluster.local", 3800, "any RIC service is unexpected - allowed_ric_services is empty"),
    ),
}

HEADER = """#!/usr/bin/env bash
# {title} ({rule_id}, {severity})
# xApp: {xapp}
#
# {desc}
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
source "$SCRIPT_DIR/../_common.sh"

POD=$(ztx_resolve_pod "{pod_pattern}")
"""


def write_script(xapp_dir, filename, title, rule_id, severity, desc, pod_pattern, container, cmd):
    path = os.path.join(xapp_dir, filename)
    body = HEADER.format(title=title, rule_id=rule_id, severity=severity, xapp=os.path.basename(xapp_dir),
                          desc=desc, pod_pattern=pod_pattern)
    cmd_str = " ".join(_shquote(c) for c in cmd)
    body += f'ztx_trigger "$POD" "{container}" {cmd_str}\n'
    with open(path, "w", newline="\n") as f:
        f.write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _shquote(s):
    if all(c.isalnum() or c in "-_./:" for c in s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def main():
    created = []

    for xapp, info in {**NON_PROFILED_XAPPS, **{k: {**v, "profiled": True} for k, v in PROFILED_XAPPS.items()}}.items():
        xapp_dir = os.path.join(BASE, xapp)
        os.makedirs(xapp_dir, exist_ok=True)

        for rule in UNIVERSAL_RULES:
            filename = f"{rule['id']}_{rule['key']}.sh"
            write_script(xapp_dir, filename, rule["title"], rule["id"], rule["severity"], rule["desc"],
                         info["pod_pattern"], info["container"], rule["cmd"])
            created.append(os.path.join(xapp, filename))

        if info.get("profiled"):
            if info["rule6_target"] is not None:
                target, port, why = info["rule6_target"]
                filename = "ZTX-A7_unexpected_peer_contact.sh"
                desc = (f"Connects to {target}:{port}, a peer xApp NOT on {xapp}'s own declared allow-list ({why}). "
                        f"Matches the rule's per-xApp profile check exactly, not a generic probe.")
                cmd = ["python3", "-c",
                       f"import urllib.request; urllib.request.urlopen('http://{target}:{port}/', timeout=3)"]
                write_script(xapp_dir, filename, "Unexpected Peer xApp Contact", "ZTX-A7", "WARNING", desc,
                             info["pod_pattern"], info["container"], cmd)
                created.append(os.path.join(xapp, filename))
            else:
                note_path = os.path.join(xapp_dir, "ZTX-A7_NOT_APPLICABLE.txt")
                with open(note_path, "w") as f:
                    f.write(
                        "Rule 6 (Unexpected Peer xApp Contact, ZTX-A7) is structurally impossible to trigger for "
                        "security-observer: its own declared allow-list (allowed_peers) already includes all 4 "
                        "other dummy xApps, so there is no peer contact the rule could ever classify as "
                        "unexpected. No trigger script exists for this rule/xApp combination on purpose - this "
                        "file records why, so its absence isn't mistaken for an oversight.\n"
                    )
                created.append(os.path.join(xapp, "ZTX-A7_NOT_APPLICABLE.txt"))

            target, port, why = info["rule7_target"]
            filename = "ZTX-A17_unexpected_ric_service_contact.sh"
            desc = (f"Connects to {target}:{port}, a RIC platform service NOT on {xapp}'s own declared "
                     f"allow-list ({why}). Matches the rule's per-xApp profile check exactly.")
            cmd = ["python3", "-c",
                   f"import urllib.request; urllib.request.urlopen('http://{target}:{port}/', timeout=3)"]
            write_script(xapp_dir, filename, "Unexpected RIC Service Contact", "ZTX-A17", "WARNING", desc,
                         info["pod_pattern"], info["container"], cmd)
            created.append(os.path.join(xapp, filename))

    print(f"Generated {len(created)} files across {len(NON_PROFILED_XAPPS) + len(PROFILED_XAPPS)} xApp folders.")
    for c in sorted(created):
        print(" ", c)


if __name__ == "__main__":
    main()
