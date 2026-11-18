# Playbook: Suspicious Download or File-Creation Alert

**Purpose:** Consistent defensive triage when an endpoint alert reports a suspicious downloaded or newly created file.  
**Audience:** SOC analyst / authorized incident responder.

## Phase 1 — Validate the alert

1. Record alert ID, timestamp, timezone, hostname, user and detection source.
2. Record the exact file path, filename and SHA-256 if available.
3. Identify whether the security product blocked, quarantined, allowed or merely detected the file.
4. Check whether the alert is duplicated or linked to an existing case.

## Phase 2 — Establish context

1. Review file-creation telemetry (for example, Sysmon Event ID 11).
2. Review process-creation telemetry (for example, Sysmon Event ID 1) to identify the process associated with the activity.
3. Review network telemetry (for example, Sysmon Event ID 3) if collected.
4. Compare event times using a consistent timezone.
5. Check whether the user expected the download and whether the software is approved.

## Phase 3 — Assess risk

Consider:
- File hash and reputation
- Digital signature and publisher
- File type and location
- Process lineage and execution evidence
- Network destination context
- Related detections and scope across other endpoints

Do not classify a file as malicious solely because its name looks unusual or it is located in Downloads.

## Phase 4 — Respond through approved controls

- If the product already blocked or quarantined the file, verify the action and preserve the alert evidence.
- If suspicious activity may be ongoing, escalate to the incident responder.
- Endpoint isolation, quarantine, removal and account actions must follow approved authorization and change procedures.
- If the user interacted with the file, document what is known and escalate for further endpoint review.

## Phase 5 — Close and document

Record the verdict (true positive, false positive or inconclusive), confidence, impact, actions taken, owner and follow-up. State missing logs and any limits on attribution.

## Escalation triggers

Escalate promptly when there is evidence of execution, repeated detections, suspicious child processes, unexpected outbound connections, security-control tampering or impact to multiple endpoints.

## Analyst handoff template

| Field | Value |
|---|---|
| Alert ID / time | |
| Host / user | |
| File path / SHA-256 | |
| Detection and product action | |
| Related process events | |
| Related network events | |
| Scope / impact | |
| Current assessment | |
| Actions authorized and completed | |
| Outstanding questions / owner | |

**Boundary:** This playbook is for authorized defensive response. Follow local policy and do not execute unknown files to validate an alert.