# SOC Analyst Portfolio

A portfolio of practical cybersecurity learning projects focused on SOC operations, blue-team investigation, security event analysis and incident response documentation.

## 🌐 Portfolio Website

A responsive portfolio homepage is included in this repository. To publish it, open **Settings → Pages**, choose **Deploy from a branch**, select **main** and **/(root)**, then save. GitHub Pages will show the published URL after deployment.

## Practical Work and Evidence

### Authentication investigation
- [Worked sample authentication report](incident-reports/sample-authentication-investigation.md) — a fictional event timeline with findings and limitations.
- [Synthetic Windows authentication CSV](datasets/synthetic-authentication-events.csv) — small, reproducible dataset used for the sample scenario.
- [Splunk authentication query pack](splunk-investigations/authentication-investigation-query-pack.md) — searches for event discovery, timelines and failure summaries.
- [Incident report template](incident-reports/REPORT-TEMPLATE.md) — reusable evidence-based reporting structure.

### Windows and Sysmon
- [Sysmon Event ID 11 vs Event ID 3 guide](windows-event-analysis/sysmon-event-11-vs-3.md) — file creation and network connection telemetry, sample SPL and investigation cautions.

### Phishing and suspicious-file triage
- [Synthetic phishing triage exercise](phishing-analysis/synthetic-phishing-triage.md) — fictional email indicators and a safe analysis workflow.
- [Suspicious file alert triage](malware-analysis/suspicious-file-alert-triage.md) — metadata, endpoint correlation and defensive assessment workflow.
- [Suspicious download response playbook](playbooks/suspicious-download-playbook.md) — triage, escalation and analyst handoff checklist.

## Technical Areas

- Splunk and SIEM investigations
- Windows Security Event Logs and Sysmon
- Linux fundamentals
- Wireshark and network traffic analysis
- Alert triage and event correlation
- Phishing and suspicious-file analysis
- Incident response and technical reporting

## Evidence and Accuracy

This repository distinguishes worked fictional examples, reusable guides and live lab results. The authentication dataset and sample report are synthetic. SPL snippets are examples and have not been represented as successful live searches. No client engagements, production incidents or certifications are claimed unless explicitly documented.

All practical demonstrations must use authorized lab environments and synthetic or sanitized data. No confidential organization data, credentials or malware binaries are included.
