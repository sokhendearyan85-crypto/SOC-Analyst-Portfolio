# SOC Analyst Portfolio

This repository documents my cybersecurity learning and practical blue-team work. It includes home-lab investigations, Splunk query notes, synthetic exercises and reusable response checklists. Evidence and limitations are labelled clearly.

## Connect

- [LinkedIn profile](https://www.linkedin.com/in/aryan-sokhende-980186368/)
- [GitHub profile](https://github.com/sokhendearyan85-crypto)
- [Live portfolio website](https://sokhendearyan85-crypto.github.io/SOC-Analyst-Portfolio/)

## Portfolio website

- [Portfolio website source](index.html)
- [Stylesheet](styles.css)
- GitHub Pages deployment: configure **Settings → Pages → Deploy from a branch → main → /(root)**.

## Practical work

### 1. Ubuntu SSH authentication review — screenshot-based lab investigation
Reviewed Ubuntu `/var/log/auth.log` events in Splunk and documented failed SSH authentication messages alongside a separate accepted password event.

- [Investigation report](incident-reports/ubuntu-ssh-authentication-review.md)
- [Original Splunk screenshots](incident-reports/)
- Tools: Ubuntu, Splunk Enterprise, SSH authentication logs

### 2. Windows authentication — synthetic worked example
A fictional example showing how failed and successful Windows logon events can be correlated and reported.

- [Sample report](incident-reports/sample-authentication-investigation.md)
- [Synthetic CSV dataset](datasets/synthetic-authentication-events.csv)

### 3. Splunk query notes
- [Authentication event review](splunk-investigations/authentication-event-review.md)
- [Windows authentication query pack](splunk-investigations/authentication-investigation-query-pack.md)

### 4. Windows and Sysmon notes
- [Sysmon Event ID 11 vs Event ID 3](windows-event-analysis/sysmon-event-11-vs-3.md)

### 5. PhishGuard — Gmail outgoing email scanner
A personal Chrome-extension prototype that reviews outgoing Gmail messages and displays risk warnings. During local testing, a high-risk test message was blocked. This is a prototype, not a production or independently audited security product.

- [PhishGuard project overview](phishguard/README.md)
- Status: prototype; extension source code is not included in this repository yet.

### 6. Phishing and suspicious-file triage
- [Synthetic phishing email triage exercise](phishing-analysis/synthetic-phishing-triage.md)
- [Suspicious file alert triage workflow](malware-analysis/suspicious-file-alert-triage.md)
- [Suspicious download response playbook](playbooks/suspicious-download-playbook.md)

## Training

- [Tutedude Cyber Security Course — completion record](training/README.md)
- [View / download original Tutedude certificate (PDF)](training/certificate_TD-ARYA-CS-0613.pdf)
- Completed: 11 November 2026
- Certificate ID: `TD-ARYA-CS-0613`

## Tools and topics practised

- Splunk Enterprise and SPL
- Ubuntu and Linux authentication logs
- Windows Security Event Logs and Sysmon concepts
- Wireshark
- SSH authentication investigation
- Alert triage and incident reporting

These are areas I have practised or studied, not claims of expert-level proficiency.

## Investigation approach

1. Record the alert, data source and time range.
2. Preserve the original evidence.
3. Separate direct observations from assumptions.
4. Correlate relevant events where the data supports it.
5. State the assessment, confidence and limitations.
6. Recommend proportionate defensive follow-up.

- [Incident report template](incident-reports/REPORT-TEMPLATE.md)

## Evidence and safe use

Some entries are based on screenshots from my own lab. Others are explicitly labelled synthetic examples, query references or reusable playbooks. I do not claim client engagements, production incident response, or certifications not documented here.

Practical demonstrations should use authorized lab environments and synthetic or sanitized data. Do not upload credentials, private user data, confidential company information or live malicious files.
