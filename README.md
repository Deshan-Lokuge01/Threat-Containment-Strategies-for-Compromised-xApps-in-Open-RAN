# Threat Containment Strategies for Compromised xApps in Open RAN

## Project Overview
This repository serves as the architectural foundation and research documentation for developing a **Zero‑Trust threat containment framework** within an Open RAN (O‑RAN) environment.

The primary objective of this project is to implement a security framework that enhances the resilience of the **Near‑Real‑Time RAN Intelligent Controller (Near‑RT RIC)** by actively authenticating workloads and isolating compromised third‑party microservices (xApps) at runtime.

**Team Members:**
- Dewmith M.K.J. (EG/2021/4474)
- Dilshan M.D.K. (EG/2021/4485)
- Sewinda L.L.D. (EG/2021/4807)
- Thilohith T.K. (EG/2021/4832)

**Supervisors:**
- Dr. Chatura Seneviratne
- Prof. Dr. An Braeken
- Mr. Pramitha Fernando

---

## 1. What is O‑RAN and Where is it Used?

Traditional Radio Access Networks (RAN) are fundamentally monolithic “black boxes”. In these legacy systems, all functionalities—from Radio Frequency (RF) processing up to Radio Resource Control (RRC)—are bundled into a single vendor’s proprietary hardware. This closed ecosystem limits flexibility, stifles innovation, and causes severe vendor lock‑in.

**Open RAN (O‑RAN)** shatters this paradigm by introducing three core principles:

1. **Architectural Disaggregation** – The 5G base station (gNB) is split into logical units: the Central Unit (O‑CU), Distributed Unit (O‑DU), and Radio Unit (O‑RU). This allows operators to deploy different layers of the 3GPP protocol stack across different hardware and geographic locations (e.g., edge clouds vs. cell sites).
2. **Open Interfaces** – Standardized interfaces (such as E2, A1, O1, and Open Fronthaul) connect these disaggregated components, ensuring seamless interoperability between different hardware and software vendors.
3. **Intelligent Orchestration** – O‑RAN introduces the RAN Intelligent Controllers (RICs)—specifically the Non‑Real‑Time RIC and the Near‑Real‑Time RIC. These platforms run machine learning algorithms and optimization routines to actively control the radio network.

**Where is it used?**  
O‑RAN is deployed in modern 5G Standalone (SA) networks, private enterprise 5G, and edge‑computing telecom data centers where operators require highly scalable, cloud‑native infrastructure.

<div align="center">
  <img src="images/fig1_evolution.png" alt="Evolution of Traditional Base Station to O-RAN" width="80%">
  <br><em>Figure 1: Evolution of the traditional base station to a virtualized, disaggregated gNB</em>
</div>

---

## 2. O‑RAN Architecture and Key Principles

The O‑RAN architecture is built on four key principles:

| Principle | Description |
|-----------|-------------|
| **Disaggregation** | Splitting the gNB into O‑CU, O‑DU, and O‑RU, each with well‑defined functions. |
| **Virtualization** | Running network functions as software on commodity hardware (the O‑Cloud), enabling cloud‑native deployment. |
| **Intelligent control** | Introducing RICs that use AI/ML to optimize network performance via closed‑loop automation. |
| **Open interfaces** | Standardizing interfaces between components to allow multi‑vendor interoperability. |

<div align="center">
  <img src="images/fig3_highlevel_arch.png" alt="High-level O-RAN architecture" width="90%">
  <br><em>Figure 2: High‑level O‑RAN architecture</em>
</div>

---

## 3. The O‑RAN Stack: CU, DU, RU and Functional Splits

The O‑RAN stack follows the 3GPP functional split, with the gNB divided into:

- **O‑CU (Central Unit)** – Hosts RRC, PDCP, and SDAP layers. It is further split into O‑CU‑CP (control plane) and O‑CU‑UP (user plane).
- **O‑DU (Distributed Unit)** – Hosts RLC, MAC, and the High‑PHY layer.
- **O‑RU (Radio Unit)** – Hosts the Low‑PHY layer and RF components.

The O‑RAN specifications define the **7.2x functional split** between the O‑DU and O‑RU, balancing fronthaul bandwidth, latency, and implementation complexity.

<div align="center">
  <img src="images/fig4_protocol_stack.png" alt="Protocol stack with 7.2x split" width="80%">
  <br><em>Figure 3: 3GPP protocol layers mapped to O‑RAN components</em>
</div>

---

## 4. The RAN Intelligent Controllers (RICs)

### 4.1 Near‑RT RIC and xApps
- **Operating timescale:** 10 ms – 1 s  
- **Role:** Real‑time optimization of RAN functions (handovers, scheduling, load balancing)  
- **xApps:** Microservices that run on the Near‑RT RIC and use the E2 interface to collect data and issue control actions to RAN nodes.  
- **Internal components:** Messaging infrastructure, Shared Data Layer (SDL), Network Information Base (NIB), conflict mitigation, and security sub‑system.

<div align="center">
  <img src="images/fig5_near_rt_ric.png" alt="Near-RT RIC internal architecture" width="80%">
  <br><em>Figure 4: Near‑RT RIC internal architecture</em>
</div>

### 4.2 Non‑RT RIC and rApps
- **Operating timescale:** > 1 s  
- **Role:** Higher‑level orchestration, policy management, AI/ML model training, and lifecycle management.  
- **rApps:** Applications that run on the Non‑RT RIC and provide network‑wide optimization, such as spectrum management, service assurance, and slicing.  
- **Interfaces:** A1 (to Near‑RT RIC), O1 (to managed elements), O2 (to O‑Cloud).

<div align="center">
  <img src="images/fig6_non_rt_ric.png" alt="Non-RT RIC and SMO architecture" width="80%">
  <br><em>Figure 5: Non‑RT RIC and SMO logical architecture</em>
</div>

---

## 5. Key O‑RAN Interfaces

| Interface | Connects | Purpose |
|-----------|----------|---------|
| **E2** | Near‑RT RIC ↔ O‑CU/O‑DU/eNB | Real‑time control and telemetry; supports multiple service models (KPM, NI, RC, etc.). |
| **A1** | Non‑RT RIC ↔ Near‑RT RIC | Policy guidance, enrichment information, and ML model management. |
| **O1** | SMO ↔ O‑RAN NFs | FCAPS management, configuration, performance monitoring, software upgrades. |
| **O2** | SMO ↔ O‑Cloud | Cloud infrastructure management, workload deployment, orchestration. |
| **Open Fronthaul** | O‑DU ↔ O‑RU | 7.2x split transport over Ethernet; includes C‑plane, U‑plane, S‑plane, M‑plane. |

<div align="center">
  <img src="images/fig7_interfaces.png" alt="O-RAN interfaces diagram" width="90%">
  <br><em>Figure 6: O‑RAN interfaces</em>
</div>

---

## 6. Security Challenges in O‑RAN

The openness and disaggregation of O‑RAN introduce new security challenges:

- **Expanded attack surface** – More interfaces, more components, and third‑party xApps/rApps.
- **Trust gaps** – Multi‑vendor components must trust each other; physical location no longer implies legitimacy.
- **xApp‑specific threats** – Malicious or compromised xApps can exhaust resources, leak UE data, manipulate control loops, or disrupt the network.
- **Supply chain risks** – Vulnerable third‑party libraries, backdoors, or poisoned CI/CD pipelines.
- **AI/ML vulnerabilities** – Poisoned training data, model theft, adversarial attacks.

These challenges necessitate a **Zero Trust** approach, where every component is continuously verified before being allowed to act.

<div align="center">
  <img src="images/fig8_threat_landscape.png" alt="Threat landscape in O-RAN" width="80%">
  <br><em>Figure 7: Threat landscape in O‑RAN</em>
</div>

---

## 7. Our Project: Threat Containment for Compromised xApps

### 7.1 Problem Statement
O‑RAN allows third‑party xApps to execute control actions inside the Near‑RT RIC. A compromised xApp can:
- Exhaust shared resources (CPU, memory), causing Denial of Service.
- Leak sensitive UE information (IMSI, location).
- Issue malicious control commands, disrupting RAN operations (e.g., power oscillations, incorrect handovers).
- Move laterally within the RIC platform and compromise other xApps.

Current security measures are largely static (pre‑deployment scanning, code signing) and do not handle runtime compromises. There is a critical need for **automated, runtime containment mechanisms**.

### 7.2 Objectives
- Implement a security framework that enhances the resilience of the Near‑RT RIC against compromised xApps.
- Integrate **remote attestation** (using TPM and Keylime) to verify the integrity of the host and xApp images before deployment.
- Implement **workload identity attestation** (using SPIRE/SPIFFE) to issue short‑lived, cryptographically verifiable identities to xApps.
- Develop an **automated isolation pipeline** that, upon detection of anomalies, quarantines the compromised xApp.
- Validate the framework experimentally in a realistic O‑RAN testbed.

### 7.3 Proposed Security Framework Overview
Our framework combines three complementary layers:

1. **Hardware‑rooted remote attestation** – ensures the underlying host and container images are untampered.
2. **Workload identity attestation** – verifies that each xApp is the intended, signed workload and issues a unique identity token (SVID).
3. **Runtime monitoring & automated isolation** – continuously observes xApp behaviour; on anomaly detection, the xApp is automatically isolated.

<div align="center">
  <img src="images/fig_workflow.png" alt="xApp validation and isolation workflow" width="80%">
  <br><em>Figure 8: Proposed security workflow – from deployment to runtime containment</em>
</div>

### 7.4 Remote Attestation with Keylime (TPM‑based)
**Keylime** is an open‑source remote attestation framework that uses a TPM as the Root of Trust. In our setup:
- The **attestation agent** runs on each O‑Cloud host.
- The **verifier** (co‑located with the SMO) periodically challenges the host to provide signed measurements (PCR values, file hashes).
- Before an xApp is deployed, the verifier checks that the host is in a known‑good state and that the container image hashes match a reference.
- If attestation fails, the xApp is blocked from starting.

<div align="center">
  <img src="images/fig_remote_attestation.png" alt="Remote attestation with Keylime" width="70%">
  <br><em>Figure 9: Remote attestation workflow</em>
</div>

### 7.5 Workload Identity Attestation with SPIRE/SPIFFE
**SPIRE (SPIFFE Runtime Environment)** automates workload attestation and identity issuance. The process:
- **Node attestation** – verifies the host using TPM (or cloud provider metadata).
- **Workload attestation** – inspects the container (cgroups, namespace, image digest) to confirm it is the expected workload.
- Upon success, SPIRE issues an **SVID (SPIFFE Verifiable Identity Document)** – a short‑lived X.509 certificate.
- The xApp uses this SVID to authenticate to the RIC platform (e.g., E2 interface, SDL) using mTLS.
- Access policies are based on the SPIFFE ID (e.g., `spiffe://oran.org/xapp/load-balancer`), ensuring least privilege.

<div align="center">
  <img src="images/fig_spire_workflow.png" alt="SPIRE workload attestation" width="80%">
  <br><em>Figure 10: SPIRE attestation and SVID issuance</em>
</div>

### 7.6 CU/DU Split Testbed Setup
We have deployed a disaggregated gNB following the 3GPP CU/DU split with O‑RAN 7.2x fronthaul. The testbed consists of:

| Component | Software | Location |
|-----------|----------|----------|
| **O‑CU** | srsRAN (O‑CU) | Virtual machine (10.53.1.2) |
| **O‑DU** | srsRAN (O‑DU) | Virtual machine (10.53.1.1) |
| **O‑RU** | srsRAN (O‑RU) + ZMQ | Same VM as DU (emulated) |
| **5G Core** | Open5GS | Docker containers (10.53.1.2) |
| **Near‑RT RIC** | OSC RIC / FlexRIC | Kubernetes cluster |
| **Monitoring** | Falco, cAdvisor, Prometheus | Kubernetes |

The O‑DU and O‑RU communicate via the **Open Fronthaul** interface over ZMQ. The O‑CU connects to the 5G Core via **N2 (NGAP)** and **N3 (GTP‑U)** interfaces. The Near‑RT RIC communicates with the O‑CU/O‑DU over the **E2** interface.


### 7.7 Isolation Pipeline
When a security violation is detected (e.g., CPU usage exceeds quota, unexpected file access, or failed identity attestation), the framework triggers automated containment:

1. **Alert** – Falco or cAdvisor sends a webhook to the orchestrator (e.g., Kubernetes admission controller).
2. **Quarantine** – The xApp’s Kubernetes pod is labelled `quarantine=true`; network policies block all egress/ingress except to a logging sidecar.
3. **Snapshot** – Memory and logs are captured for forensic analysis.
4. **Terminate** – After analysis (or if the violation is severe), the pod is deleted and the xApp is removed from the SDL.

This pipeline ensures that even if an xApp is compromised at runtime, the damage is contained within seconds.


### 7.8 Future Work
- **Integration of Zero‑Knowledge Virtual Machines (zkVMs)** – to provide cryptographic proof of correct computation without revealing internal data.
- **Machine learning‑based anomaly detection** – using network telemetry to detect subtle behavioural deviations.
- **Cross‑RIC coordination** – enabling the Non‑RT RIC to update isolation policies based on global threat intelligence.
- **Performance benchmarking** – measuring the latency overhead introduced by attestation and isolation loops to ensure 5G timing requirements are met.

---

# Part II — Implementation: ZT-XGuard

Everything above describes the design. This second part documents the working system we
actually built, deployed, and measured on a live O-RAN testbed. The runtime is called
**ZT-XGuard**. It watches every xApp in the Near-RT RIC, decides when one has been
compromised, and contains it automatically — with four independent locks applied in
parallel and the workload's cryptographic identity revoked at the same time.

<div align="center">
  <img src="images/dashboard/soc-dashboard-all-normal.png" alt="ZT-XGuard SOC dashboard, steady state" width="95%">
  <br><em>ZT-XGuard SOC dashboard — the live RIC map with all xApps healthy.</em>
</div>

## 9. How the system fits together

```
 RAN (OAI 5G core → gNB → UE)  ──E2──►  Near-RT RIC (ricplt + xApps)
                                              │
                        ┌─────────────────────┼──────────────────────┐
                        ▼                      ▼                      ▼
                  Falco (kernel)        T² collector (stats)     SPIRE / SPIFFE
                  behavioural           resource / DoS           workload identity
                        │                      │                      │
                        └──────────► Policy Engine (state engine) ◄────┘
                                              │  decision: NORMAL→SUSPICIOUS→COMPROMISED→ISOLATED
                                              ▼
                          Containment orchestrator — four locks in parallel
              (Calico NetworkPolicy · Service isolation · node iptables · SVID revoke)
```

| Layer | Folder | What it does |
|-------|--------|--------------|
| Control plane | [`policy-engine/`](policy-engine/) | Flask service: state engine, decision logic, containment orchestrator, live SOC dashboard |
| Behavioural detection | [`detection/falco/`](detection/falco/) | Falco rules per xApp (ZTX-A1…A17, LM-03) — shells, file access, egress, token theft, tamper |
| Statistical detection | [`detection/statistical-model/`](detection/statistical-model/) | T² MEWMA resource/DoS detector with a frozen, calibrated CPU-rate gate |
| **Containment** | [`containment/`](containment/) | ⭐ the four concurrent locks and the 30-second dwell auto-isolation |
| Identity | [`identity/`](identity/) | SPIRE/SPIFFE onboarding and SVID revocation on isolation |
| xApps | [`xapps/`](xapps/) | the guarded xApps and their declarative security profiles |
| Attacks | [`attacks/`](attacks/) | behavioural attack scripts + DoS resource-exhaustion scripts |
| Onboarding demo | [`dos-detector/`](dos-detector/) | a custom SPIRE-attested xApp added at runtime |
| Testbed | [`testbed/`](testbed/) | O-RAN testbed notes, run scripts, and our kpimon-go fix (upstream issue #13) |
| Evaluation | [`evaluation/`](evaluation/) | scalability campaigns, datasets, and the report figures |
| Forensics | [`forensics/`](forensics/) | the DFIR evidence vault and captured containment proofs |
| Deployment | [`deploy/`](deploy/) | Kubernetes manifests, Calico policies, SPIRE config |

## 10. ⭐ Automated containment — four concurrent locks

The heart of the project. When the policy engine confirms an xApp is **COMPROMISED**, a single
call fans out to four independent mechanisms at once, and revokes the workload's identity. Full
code and line references are in [`containment/CONTAINMENT-CODE.md`](containment/CONTAINMENT-CODE.md).

| # | Lock | Layer | Measured time-to-effect |
|---|------|-------|------------------------|
| 1 | Calico deny-all **NetworkPolicy** | CNI / pod network | ~0.1 s (control-plane apply) |
| 2 | **Service-selector isolation** | Kubernetes service | ~0.4–1 s (endpoints drain) |
| 3 | Node **iptables DROP** (raw/PREROUTING inside calico-node) | host kernel, CNI-independent | ~0.8–1.3 s (rule + verify) |
| 4 | **SPIFFE/SVID revocation** | zero-trust identity | ~3–5 s (full SPIRE withdrawal) |

Because the locks run in parallel, the wall-clock containment time is the slowest one — the
SVID withdrawal. Network access **and** the ability to authenticate are both gone. For resource
(DoS) incidents there is a deliberate **30-second dwell** after COMPROMISED before isolation, so a
human operator can intervene; the countdown is shown live on the dashboard.

<div align="center">
  <img src="images/dashboard/soc-dashboard-resource-attack.png" alt="A resource/DoS attack being detected and contained" width="95%">
  <br><em>A DoS (resource-exhaustion) attack on kpimon-go: the T² channel confirms it, then the four locks isolate the xApp and the SVID is revoked.</em>
</div>

## 11. Detection — two independent channels

- **Behavioural (Falco).** Kernel-level rules fire the instant an xApp does something its profile
  forbids — spawning a shell, reading a ServiceAccount token, touching SVID material, egressing to
  the internet, tampering with its own config. These are treated as immediate, high-confidence
  compromises. See [`detection/falco/`](detection/falco/).
- **Statistical / DoS (T²).** A MEWMA detector watches kpimon-go's resource metrics and confirms a
  resource-exhaustion (DoS, MITRE T1499) attack only after a 6-of-8 corroboration window plus a
  CPU-rate gate — roughly a minute of evidence, not a single spike. See
  [`detection/statistical-model/`](detection/statistical-model/).

## 12. The road we took (and the wrong turns)

We did not arrive at this design in a straight line. The honest account — including the
**machine-learning resource-detector we built first and then abandoned**, the network-policy-only
containment that turned out to be insufficient on its own, and the dwell-timing bug we chased — is
written up in [`docs/research-journey.md`](docs/research-journey.md). It is worth reading before the
results, because several design choices only make sense once you know what failed.

## 13. Evaluation

Scalability campaigns (detector scaling to N=80 contexts, evaluator throughput to saturation,
real 4-xApp concurrent isolation), the raw capture datasets, and every figure from the report live
under [`evaluation/`](evaluation/). Headline results and the figures are collected in
[`docs/results.md`](docs/results.md).

## 14. Testbed and our upstream contribution

The RAN side runs on the NIST [O-RAN-Testbed-Automation](https://github.com/usnistgov/O-RAN-Testbed-Automation)
(OAI 5G core → gNB → UE → OSC Near-RT RIC). We do not vendor the multi-gigabyte upstream here; the
[`testbed/`](testbed/) folder holds our run scripts and a write-up of the **kpimon-go ↔ OSC Near-RT
RIC connectivity bug we fixed**, reported upstream as
[issue #13](https://github.com/usnistgov/O-RAN-Testbed-Automation/issues/13), with the deployment
evidence and our actuator xApp.

## 15. Publications

- **IEEE CCNC (6 pages)** — the conference paper drawn from this work is in [`paper/`](paper/).
- **Final Report** — the full project report is in [`Docs/`](Docs/).

---

## 8. References
1. M. Polese, L. Bonati, S. D'Oro, S. Basagni, and T. Melodia, “Understanding O-RAN: Architecture, Interfaces, Algorithms, Security, and Research Challenges,” *IEEE Communications Surveys & Tutorials*, vol. 25, no. 2, pp. 1376–1411, 2023.
2. O-RAN Working Group 1, “O-RAN Architecture Description,” O-RAN ALLIANCE, Tech. Rep. TR.0-R004-v15.00, Oct. 2025.
3. O-RAN Working Group 3, “Near-RT RIC Architecture,” O-RAN ALLIANCE, Tech. Rep. TR.0-R004-v07.00, Feb. 2025.
4. O-RAN Working Group 11, “Study on Security for Near Real Time RIC and xApps,” Tech. Rep. TR.0-R004-v06.00.
5. srsRAN Project Documentation: https://docs.srsran.com/
6. Open5GS: https://open5gs.org/
7. Keylime Project: https://keylime.dev/
8. SPIFFE/SPIRE: https://spiffe.io/

---

## 📄 License
This work is part of an academic Final Year Project. All rights reserved.
