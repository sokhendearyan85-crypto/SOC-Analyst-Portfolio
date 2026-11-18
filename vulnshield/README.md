# VulnShield

A Streamlit dashboard for searching public vulnerabilities and tracking remediation.

## What it does
- Searches CVEs through the **NIST NVD REST API (v2.0)** by keyword.
- Cross-checks results against the **CISA Known Exploited Vulnerabilities (KEV)** catalog.
- Shows severity, description, affected products (CPE) and vendor/NVD references.
- Gives defensive remediation guidance based on severity and exploitation status.
- Includes a remediation tracker and a summary report table.

## Run
```bash
pip install -r requirements.txt
streamlit run app.py
```
Needs internet access (NVD and CISA feeds).

## Limits
NVD keyword search can return different product versions, so results need manual verification.
