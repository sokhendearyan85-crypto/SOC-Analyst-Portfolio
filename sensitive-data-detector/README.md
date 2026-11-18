# Sensitive Data Leak Detector

A simple Python scanner that searches text files for data that should not be exposed.

## What it detects (regex based)
- Email addresses
- `API_KEY = ...` style values
- `password = ...` style values

## Run
```bash
python scanner.py
```
It scans every file in `test_files/` and prints a warning for each match.

## Limits
Regex matching gives false positives and misses. Learning project, not a DLP product.
