# Sample Authentication Activity Investigation

**Data type:** Synthetic Windows Security event records  
**Purpose:** Portfolio demonstration  
**Status:** Completed example based on fictional data

## 1. Alert summary

A sequence of failed sign-in events was followed by a successful sign-in for the same test account.

- Account: `lab.user`
- Host: `LAB-WIN-01`
- Date: `2026-10-15`
- Time zone: UTC
- Data source: Windows Security log
- Relevant event IDs: 4625 (failed logon), 4624 (successful logon)

## 2. Evidence reviewed

The following events are fictional and created only to demonstrate report structure.

| Time (UTC) | Event ID | Account | Source address | Observation |
|---|---:|---|---|---|
| 09:14:02 | 4625 | lab.user | 192.0.2.25 | Failed logon |
| 09:14:19 | 4625 | lab.user | 192.0.2.25 | Failed logon |
| 09:14:41 | 4625 | lab.user | 192.0.2.25 | Failed logon |
| 09:15:08 | 4624 | lab.user | 192.0.2.25 | Successful logon |

The address `192.0.2.25` is from a documentation-only IP range and is not a real public source attribution.

## 3. Analysis

The synthetic event sequence shows three failed logons followed shortly by a successful logon for the same account and source address.

This pattern can be consistent with repeated authentication failures followed by a successful sign-in. The event sequence alone does not prove that the successful sign-in was unauthorized. The logon type, workstation context, account owner confirmation, surrounding endpoint activity, and other authentication records would be needed for a stronger assessment.

## 4. Findings

- Three failed logon events were recorded for the test account.
- A successful logon followed within approximately one minute.
- The same documentation-only source address appears in all four sample events.
- No evidence in this synthetic dataset establishes who controlled the source or whether the successful sign-in was legitimate.

## 5. Assessment

- **Verdict:** Inconclusive
- **Confidence:** Medium for the event sequence; low for attributing malicious intent
- **Severity:** Requires environment-specific context

The sequence warrants review, but the available sample is insufficient to confirm account compromise.

## 6. Recommended defensive actions

1. Confirm whether the account owner recognizes the successful sign-in.
2. Review the successful event's logon type and workstation details.
3. Check nearby authentication events for the same account and host.
4. Review endpoint activity around the successful sign-in.
5. Escalate according to the organization's incident response process if the activity is not recognized.

## 7. Limitations

This report uses fictional records, not an actual Windows event export. No real user, host, or incident is represented. The report does not claim that a real attack occurred.

## 8. Conclusion

The sample demonstrates how a SOC analyst can correlate failed and successful authentication events, document what is known, identify missing context, and avoid overstating the evidence.
