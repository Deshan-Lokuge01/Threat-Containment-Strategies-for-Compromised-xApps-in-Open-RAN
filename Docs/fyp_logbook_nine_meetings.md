# ZT-XGuard Final Year Project Logbook

Dates use the `DD/MM/YYYY` format. The entries follow the verified project progression from model development through evaluation, reporting, and demonstration preparation.

## Meeting - 18/05/2026

### Work carried out since the last meeting

- Reviewed literature on O-RAN xApp threats and narrowed the project scope toward continuous monitoring, trust assessment, and automated containment.
- Identified CPU, memory, network, filesystem, process, and operational metrics suitable for representing normal and abnormal xApp behaviour.
- Investigated multivariate anomaly-detection methods and selected MEWMA for detecting gradual, correlated deviations across runtime resource measurements.
- Defined the initial separation between anomaly evidence, trust-state decisions, and containment enforcement within the proposed ZT-XGuard architecture.

### Work planned for the coming week

- Finalize the normal-behaviour data-collection methodology, including traffic conditions, sampling frequency, observation duration, and required metadata.
- Analyse candidate runtime metrics for missing values, skewness, correlation, stability, and their relevance to compromised xApp behaviour.
- Develop a reproducible preprocessing pipeline covering transformation, robust centring, scaling, windowing, and multivariate feature construction.
- Compare suitable MEWMA window sizes and smoothing parameters using interpretable response speed and baseline stability criteria.

## Meeting - 01/06/2026

### Work carried out since the last meeting

- Established controlled collection conditions using consistent RAN traffic, xApp workloads, sampling cadence, and Kubernetes resource configurations.
- Designed robust preprocessing using median-based centring, MAD or IQR scaling, and transformations for highly skewed resource measurements.
- Developed the sliding-window approach for converting one-second telemetry into stable multivariate features before calculating MEWMA statistics.
- Investigated shrinkage covariance estimation and selected Ledoit-Wolf covariance to improve numerical stability across correlated runtime metrics.

### Work planned for the coming week

- Deploy hardened runtime-monitoring rules and verify that collected events distinguish legitimate xApp activity from security-relevant behaviour.
- Implement the three-state trust assessment using NORMAL, SUSPICIOUS, and COMPROMISED while tracking containment state independently.
- Collect representative clean telemetry for model fitting, detector calibration, and untouched normal-behaviour evaluation under realistic traffic.
- Define controlled attack families and benign high-load controls required to evaluate detection sensitivity without inflating false alarms.

## Meeting - 15/06/2026

### Work carried out since the last meeting

- Integrated hardened Falco runtime rules for suspicious shells, sensitive-file access, privilege activity, unexpected egress, and integrity violations.
- Implemented deterministic transitions between NORMAL, SUSPICIOUS, and COMPROMISED using evidence persistence, severity, and explicit machine-readable reasons.
- Corrected trust-state transitions, service containment behaviour, and dashboard scenario handling within the initial ZT-XGuard framework.
- Verified xApp security-profile access and refined profile-based behaviour so evaluator logic remained independent from specific xApp names.

### Work planned for the coming week

- Separate the framework into evaluator, responder, detector, integration, storage, API, and dashboard responsibilities with clear interfaces.
- Complete scripts for collecting normal datasets N1, N2, and N3 under reproducible Kubernetes and RAN conditions.
- Implement offline model fitting, calibration, covariance estimation, threshold selection, and persistence analysis using the collected clean datasets.
- Finalize R1-R6 controlled attack protocols and document the expected resource or behavioural evidence produced by each scenario.

## Meeting - 22/06/2026

### Work carried out since the last meeting

- Prepared the canonical modular architecture and migration approach for separating trust evaluation from Kubernetes containment responsibilities.
- Refined declarative xApp profiles, per-xApp signal histories, evidence deduplication, expiration rules, and machine-readable decision explanations.
- Prepared normal-data collection scripts, quality checks, run metadata, and controlled traffic conditions for repeatable statistical modelling.
- Defined evaluation boundaries separating model fitting, clean calibration, untouched normal testing, attacks, and benign high-load controls.

### Work planned for the coming week

- Complete the canonical ZT-XGuard architecture foundation and verify evaluator behaviour using focused unit and quality-gate tests.
- Collect N1-N3 normal datasets and inspect run health, metric completeness, correlations, and stability before model fitting.
- Tune window, smoothing, covariance, threshold, and persistence parameters before freezing the final MEWMA detector configuration.
- Execute controlled resource attacks and normal controls while preserving untouched datasets for defensible final performance evaluation.

## Meeting - 06/07/2026

### Work carried out since the last meeting

- Completed the canonical architecture foundation, declarative xApp profiles, deterministic evaluator, domain models, and associated unit tests.
- Collected normal N1-N3 telemetry with run-health records, quality timelines, raw metrics, and consistent one-second sampling conditions.
- Tuned and froze robust preprocessing, MEWMA state parameters, covariance, thresholds, persistence rules, and the trust-state policy.
- Collected controlled attack, diagnostic, and benign high-load datasets covering resource exhaustion, stealth behaviour, bursts, and normal-operation boundaries.

### Work planned for the coming week

- Analyse held-out attack and control datasets for detection rate, delay, false-positive episodes, recovery, and threshold sensitivity.
- Generate publication-quality figures showing calibration, MEWMA scores, covariance structure, state transitions, and benign high-load immunity.
- Integrate statistical anomaly evidence with trust assessment while keeping resource anomalies normally limited to SUSPICIOUS without corroboration.
- Prepare the resource-detection report section and submit an updated project-report draft for supervisor review by 15 July.

## Meeting - 20/07/2026

### Work carried out since the last meeting

- Evaluated attack and benign-control datasets, documenting threshold behaviour, detection timelines, evasion boundaries, and high-load false-positive immunity.
- Produced publication-quality detector figures covering calibration, covariance, MEWMA scores, trust transitions, attack timelines, and gate ablation.
- Completed the resource-anomaly detection report section and organized supporting datasets, scripts, figures, and technical interpretation.
- Sent the updated project-report draft on 15 July, incorporating the statistical model, evaluation methodology, and preliminary results.

### Work planned for the coming week

- Audit Falco rules against real KPI-monitoring xApp behaviour and eliminate startup, credential-access, and legitimate-egress false positives.
- Strengthen containment using network policy, service isolation, workload-identity withdrawal, direct packet filtering, and clean-pod recreation.
- Run repeated Falco attack trials and collect detection, per-mechanism containment, end-to-end latency, overhead, and recovery measurements.
- Develop reproducible analysis scripts and figures for the final report and the planned IEEE conference paper.

## Meeting - 30/07/2026

### Work carried out since the last meeting

- Corrected Falco false positives involving changing platform addresses, legitimate xApp binaries, loopback probes, and expected startup behaviour.
- Verified network policy, service isolation, SVID withdrawal, direct iptables blocking, and clean-pod recreation as independent containment actions.
- Completed 400 Falco trials across eight attack scenarios, capturing detection, containment, mechanism latency, overhead, and restoration evidence.
- Built the MATLAB figure pipeline, generated final evaluation graphics, and developed the main structure and results narrative for publication.

### Work planned for the coming week

- Review the complete report for trust-state consistency, dataset traceability, methodological accuracy, unsupported claims, and missing limitations.
- Submit the next report draft on 2 August after integrating corrected figures, containment results, and revised technical explanations.
- Conduct rigorous scalability experiments covering detector contexts, evaluator request rates, and concurrent isolation of real deployed xApps.
- Incorporate supervisor feedback, finalize the scalability section, and prepare the complete report version for submission review.

## Meeting - 11/08/2026

### Work carried out since the last meeting

- Submitted the revised report draft on 2 August with updated evaluation figures, containment results, and technical discussion.
- Corrected report inconsistencies concerning three trust states, independent enforcement state, attack naming, latency origins, and testbed boundaries.
- Completed three scalability experiments covering detector capacity, evaluator saturation, and simultaneous containment of four real deployed xApps.
- Sent the final report draft on 8 August and submitted the completed Final Year Project report on 9 August.

### Work planned for the coming week

- Prepare a reliable demonstration environment showing secure onboarding, live monitoring, trust assessment, containment, restoration, and audit evidence.
- Develop a clearer operational dashboard with real xApp topology, live metrics, security states, attack controls, and containment status.
- Verify representative behavioural and resource attacks end-to-end, ensuring visible detections and repeatable recovery during the demonstration.
- Develop final presentation slides emphasizing motivation, architecture, methodology, results, limitations, project contributions, and defensible conclusions.

## Meeting - 26/08/2026

### Work carried out since the last meeting

- Deployed the refactored demonstration framework and verified genuine isolation using network policy, service removal, SVID withdrawal, and iptables.
- Built the primary security dashboard with live xApp topology, resource graphs, trust states, RAN connectivity, and incident visualization.
- Implemented the attack console and per-xApp views for launching behavioural and resource scenarios while displaying corresponding evidence.
- Corrected parallel containment timing, measured actual SVID revocation, improved restoration reliability, and refined conference-paper scalability content.

### Work planned for the coming week

- Rehearse the complete demonstration repeatedly, covering normal operation, attacks, detection, containment, restoration, and dashboard evidence without manual delays.
- Finalize presentation slides and speaking responsibilities, ensuring the architecture, methodology, results, contributions, and limitations remain consistent.
- Prepare backup recordings, screenshots, datasets, deployment manifests, and recovery commands in case the live environment becomes unstable.
- Practise answers for likely examiner questions concerning novelty, statistical validity, false positives, scalability, containment latency, and deployment limitations.
