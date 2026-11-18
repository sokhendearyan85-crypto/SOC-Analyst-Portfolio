# SOC Analyst Portfolio

This repository is where I document my cybersecurity learning and practical blue-team work. It includes a mix of lab investigations, query notes, synthetic exercises and reusable response checklists. I try to keep the evidence and limitations clear so a reader can see what I actually reviewed.

## Portfolio website

The source for my portfolio website is in this repository:
- [Open the website source](index.html)
- [Open the stylesheet](styles.css)

The site is not live yet. GitHub Pages still needs to be enabled in **Settings → Pages** (Deploy from a branch → `main` → `/(root)`).

## Practical work

### 1. Ubuntu SSH authentication review — screenshot-based lab investigation
I reviewed Ubuntu `/var/log/auth.log` events in Splunk and documented failed SSH authentication messages alongside a separate accepted password event.

- [Read the investigation](incident-reports/ubuntu-ssh-authentication-review.md)
- [View the four original Splunk screenshots](incident-reports/)
- Tools: Ubuntu, Splunk Enterprise, SSH authentication logs
- Evidence: screenshots supplied from my own VirtualBox lab

### 2. Windows authentication — synthetic worked example
A small fictional example showing how failed and successful Windows logon events can be correlated and reported.

- [Read the sample report](incident-reports/sample-authentication-investigation.md)
- [Open the synthetic CSV dataset](datasets/synthetic-authentication-events.csv)

### 3. Splunk query notes
- [Authentication event review](splunk-investigations/authentication-event-review.md)
- [Windows authentication query pack](splunk-investigations/authentication-investigation-query-pack.md)

These are example SPL searches. They are not presented as live search results unless screenshots or exported lab evidence are attached.

### 4. Windows and Sysmon notes
- [Sysmon Event ID 11 vs Event ID 3](windows-event-analysis/sysmon-event-11-vs-3.md)

### 5. PhishGuard — Gmail outgoing email scanner
A personal Chrome-extension prototype that reviews outgoing Gmail messages, shows risk warnings and was observed blocking a high-risk test message during local testing. It is not a production or independently audited security product.

- [Read the PhishGuard project overview](phishguard/README.md)
- Status: prototype; extension source code is not included in this repository yet.

### 6. Phishing and suspicious-file triage
- [Synthetic phishing email triage exercise](phishing-analysis/synthetic-phishing-triage.md)
- [Suspicious file alert triage workflow](malware-analysis/suspicious-file-alert-triage.md)
- [Suspicious download response playbook](playbooks/suspicious-download-playbook.md)

These are learning exercises and defensive reference notes, not claims of completed real-world client investigations.

## Training

- **Cybersecurity Course — Tutedude:** Completed. [Training record](training/README.md).
- A certificate image or verification link has not been added to this repository yet.

## Tools and topics I have worked with

- Splunk Enterprise and SPL
- Ubuntu and Linux authentication logs
- Windows Security Event Logs and Sysmon concepts
- Wireshark
- SSH authentication investigation
- Alert triage and incident reporting

I describe these as areas I have practised or studied, not as expert-level proficiency.

## How I document an investigation

1. Record the alert, data source and time range.
2. Preserve the original evidence.
3. Separate direct observations from assumptions.
4. Correlate relevant events where the data supports it.
5. State the assessment, confidence and limitations.
6. Recommend proportionate defensive follow-up.

[Incident report template](incident-reports/REPORT-TEMPLATE.md)

## About the evidence

Some entries are based on screenshots from my own lab. Other entries are explicitly marked as synthetic examples, query references or reusable playbooks. I do not claim client engagements, production incident response, or certifications that are not documented here.

All practical demonstrations should use authorized lab environments and synthetic or sanitized data. Do not upload credentials, private user data, confidential company information or live malicious files.
