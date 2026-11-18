# SOC Analyst Portfolio

This repository documents my cybersecurity learning and practical blue-team work. It includes a home-lab SSH investigation and Python security tools. Every project listed here has evidence or source code in this repository, and limitations are stated clearly.

## Connect

- [LinkedIn profile](https://www.linkedin.com/in/aryan-sokhende-980186368/)
- [GitHub profile](https://github.com/sokhendearyan85-crypto)
- [Live portfolio website](https://sokhendearyan85-crypto.github.io/SOC-Analyst-Portfolio/)

## Portfolio website

- [Portfolio website source](index.html)
- [Stylesheet](styles.css)

## Practical work

### 1. Ubuntu SSH authentication review (screenshot-based lab investigation)

Reviewed Ubuntu `/var/log/auth.log` events in Splunk and documented failed SSH authentication messages alongside a separate accepted password event.

- [Investigation report](incident-reports/ubuntu-ssh-authentication-review.md)
- [Original Splunk screenshots](incident-reports/)
- Tools: Ubuntu, Splunk Enterprise, SSH authentication logs

### 2. VulnShield (Python tool)

Streamlit dashboard that searches the NIST NVD, flags CISA Known Exploited Vulnerabilities and tracks remediation status.

- [Project folder and source code](vulnshield/)
- Tools: Python, Streamlit, NVD API, CISA KEV

### 3. Malware Detection Tool (Python tool)

Flask web app that checks a file or SHA-256 hash against a MalwareBazaar/ThreatFox hash database, ClamAV and a YARA rule. Includes a harmless test sample; no real malware is stored.

- [Project folder and source code](malware-detection-tool/)
- Tools: Python, Flask, ClamAV, YARA

### 4. IP Reputation Checker (Python tool)

Command-line tool that matches IP addresses against 5 public threat feeds, with optional VirusTotal lookup, CSV output and an HTML report.

- [Project folder and source code](ip-reputation-checker/)
- [Scan results from my test runs](ip-reputation-checker/scan_results.csv)
- Tools: Python, threat-intelligence feeds, VirusTotal API

### 5. Sensitive Data Detector (Python tool)

Python scanner that finds email addresses, API keys and passwords in text files using regular expressions. Tested on dummy data included in the repository.

- [Project folder and source code](sensitive-data-detector/)
- Tools: Python, regex

## Training

- Tutedude Cyber Security Course: completed 11 November 2026
- Certificate ID: `TD-ARYA-CS-0613`
- [Course certificate (PDF)](training/certificate_TD-ARYA-CS-0613.pdf)

## Notes

Project READMEs explain how to run each tool and what its limits are. Results from these tools are indicators only and need analyst validation.
