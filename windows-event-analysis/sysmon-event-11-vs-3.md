# Sysmon Event ID 11 vs Event ID 3: Investigation Notes

**Type:** Defensive learning guide  
**Dataset:** Event-field reference and query examples; not a report of a real incident  
**Goal:** Distinguish file creation telemetry from network connection telemetry.

## Why this distinction matters

Sysmon Event ID 11 is **FileCreate**. It records a file creation event and can help an analyst investigate a file appearing in a location such as a user's Downloads directory.

Sysmon Event ID 3 is **NetworkConnect**. It records a network connection associated with a process when network connection logging is enabled.

These events answer different questions. Event ID 11 does not prove that a file was downloaded from the internet; Event ID 3 does not, by itself, prove that a transfer contained a particular file.

## Fields to review

| Field | What it can tell you |
|---|---|
| UtcTime | Event timestamp in UTC |
| Image | Process executable associated with the event |
| ProcessId | Process identifier at event time |
| TargetFilename | File path created (Event ID 11) |
| User | Account context |
| Hashes | File hash values, if configured and captured |
| DestinationIp / DestinationPort | Remote endpoint (Event ID 3) |
| Protocol | Network protocol, when available |

Field availability depends on Sysmon version and configuration. Confirm the actual event XML or extracted fields in your data.

## Example Splunk searches

### Find file creation events

```spl
index=* (EventCode=11 OR EventID=11)
| table _time host User Image ProcessId TargetFilename Hashes
| sort 0 _time
```

### Find network connection events

```spl
index=* (EventCode=3 OR EventID=3)
| table _time host User Image ProcessId DestinationIp DestinationPort Protocol
| sort 0 _time
```

### Review a process name across both event types

```spl
index=* (EventCode=3 OR EventCode=11 OR EventID=3 OR EventID=11)
| search Image="*\\update.exe"
| table _time host EventCode EventID Image TargetFilename DestinationIp DestinationPort
| sort 0 _time
```

Adjust index, sourcetype and field names to match the lab's data model. Do not assume both EventCode and EventID exist.

## Investigation workflow

1. Record the alert timestamp, host, user and alert source.
2. Locate the matching Event ID 11 record and preserve the full event details.
3. Record the created file path, process image, process ID, user and available hashes.
4. Search nearby process-creation telemetry (for example, Sysmon Event ID 1) to understand the process lineage, if collected.
5. Review nearby Event ID 3 records for network context, if network logging is enabled.
6. Correlate timestamps carefully and account for UTC/local-time differences.
7. Validate the file's reputation using approved defensive tools and trusted sources. Do not execute an unknown file to test it.
8. State what is confirmed, what is only suspected, and what evidence is missing.

## Interpretation cautions

- A file in Downloads is a location clue, not proof of maliciousness.
- A filename such as `update.exe` is not enough to identify a threat.
- A network connection near the file-creation time is correlation, not proof that the connection delivered that file.
- Missing Event ID 3 records do not prove that no network activity occurred; collection may be disabled or incomplete.

## Report-ready conclusion wording

"Sysmon Event ID 11 records file creation at the observed path. This establishes that a file was created, but does not independently establish its origin or whether it is malicious. Additional process, network, hash and reputation evidence is required before assigning a verdict."

## Evidence checklist

- [ ] Original event record or sanitized screenshot
- [ ] Host and user context
- [ ] Timestamp and timezone
- [ ] TargetFilename and process Image
- [ ] Hash and file metadata, if available
- [ ] Related process and network events, if collected
- [ ] Assessment rationale and limitations

---
This guide is educational. Replace examples with evidence from an authorized lab before writing a case-specific report.