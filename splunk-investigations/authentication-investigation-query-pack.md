# Splunk Query Pack: Windows Authentication Review

**Type:** Reusable lab query pack  
**Dataset:** Windows Security events; field names vary by input method  
**Purpose:** Triage authentication activity without overstating what the logs prove.

## 1. Confirm which events are present

```spl
index=* (EventCode=4624 OR EventCode=4625)
| stats count by host sourcetype EventCode
| sort - count
```

If this returns nothing, widen the time picker and confirm the correct index and field names before concluding that events are absent.

## 2. Build a chronological sign-in timeline

```spl
index=* (EventCode=4624 OR EventCode=4625)
| eval outcome=if(EventCode=4625,"Failed","Successful")
| table _time host user src_ip Logon_Type EventCode outcome
| sort 0 _time
```

## 3. Summarize failures by account and source

```spl
index=* EventCode=4625
| stats count min(_time) as first_seen max(_time) as last_seen by host user src_ip
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

## 4. Review successful logons for the same account

```spl
index=* EventCode=4624 user="lab.user"
| table _time host user src_ip Logon_Type Workstation_Name Authentication_Package
| sort 0 _time
```

Replace the sample account with an account from your authorized lab. Do not paste real organization usernames into a public portfolio.

## 5. Analyst interpretation

- Event ID 4625 indicates a failed logon attempt.
- Event ID 4624 indicates a successful logon.
- Repeated failures followed by a success may justify investigation, but do not alone prove brute force or account compromise.
- Logon type, source context, account-owner confirmation, MFA records and surrounding endpoint activity can materially change the assessment.

## Common field differences

Some environments use `EventID` instead of `EventCode`, or extract account/source fields under different names. Inspect a raw event and adapt the search. The `src_ip` field may be absent for some logon types.

## Investigation record

| Item | Record |
|---|---|
| Index and sourcetype | |
| Time range and timezone | |
| Account/host scope | |
| Search run | |
| Events observed | |
| Missing context | |
| Assessment | |
| Follow-up | |

**Evidence status:** These are example SPL searches, not captured output from a live Splunk instance. Add sanitized screenshots or exported synthetic events when you run them in your own lab.