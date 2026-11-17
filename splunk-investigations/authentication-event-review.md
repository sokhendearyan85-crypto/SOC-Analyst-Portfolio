# Authentication Event Review in Splunk

**Type:** Learning demonstration  
**Dataset:** Synthetic Windows Security events  
**Status:** Example query; validate field names and sourcetype against your own lab data before use.

## Objective

Review failed and successful logon events for a test account and build a short timeline.

## Example SPL

```spl
index=wineventlog sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| eval outcome=case(EventCode=4625, "Failed logon", EventCode=4624, "Successful logon")
| table _time host user src_ip EventCode outcome
| sort 0 _time
```

Some Splunk deployments use different index names, sourcetypes, or field extractions. Confirm these in the lab before relying on the query. If your events use a different field for the source address or account, adjust the table fields accordingly.

## Investigation notes

1. Set a narrow time range around the alert.
2. Confirm that the events belong to the same account and relevant host.
3. Compare timestamps and source details.
4. Review the successful event's logon type and surrounding activity.
5. Record missing context and avoid treating failed logons followed by a success as proof of compromise by themselves.

## Reporting

Document the data source, time range, query, observations, limitations, assessment, and recommended follow-up.

## Limitations

This is a query example, not the output of a completed live Splunk search. No real incident or organization data is represented.
