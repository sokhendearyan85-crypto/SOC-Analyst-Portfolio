# IP Reputation Checker

A command-line tool that checks IP addresses against public threat-intelligence feeds.

## What it does
- Validates the IP, then matches it against 5 feeds: IPsum Level 3, DShield, Feodo Tracker, AbuseIPDB 30-day list and a Threat Intel IPv4 list.
- Optional **VirusTotal** lookup when `VT_API_KEY` is set (otherwise it reports "NOT CONFIGURED").
- Saves every result to `scan_results.csv` and builds an HTML report.
- Optional Gmail alert with the report attached (`GMAIL_SENDER`, `GMAIL_RECIPIENT`, `GMAIL_APP_PASSWORD` environment variables).
- Standard library only.

## Run
```bash
python scanner.py
```
Type an IP address, or `exit` to quit. `ips.txt` has sample inputs, including invalid and private addresses.

## Evidence in this folder
- `scan_results.csv`: output from my own test runs (October 2026).

## Limits
A feed match means "listed", not "confirmed malicious". No match does not guarantee safety.
Keys and passwords are read from environment variables and are never stored in the code.
