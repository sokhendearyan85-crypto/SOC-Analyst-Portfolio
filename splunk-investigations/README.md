# Splunk Investigations

## Lab investigations

- [Ubuntu SSH authentication review](../incident-reports/ubuntu-ssh-authentication-review.md) — Splunk evidence from `/var/log/auth.log`, including failed SSH authentication, PAM retry-limit messages and a separate accepted password event for `vboxuser`.

## Query references

- [Authentication event review](authentication-event-review.md) — SPL example and analyst notes for Windows Security Event IDs 4624 and 4625.
- [Authentication investigation query pack](authentication-investigation-query-pack.md) — reusable searches for event discovery, timeline review, failure summaries and successful sign-ins.

The Ubuntu report is based on screenshots supplied from a local lab. Any suggested follow-up SPL is clearly identified as a query to run, not as a search already executed.