# Synthetic Phishing Email Triage Exercise

**Scenario type:** Fictional training example  
**Status:** Worked analytical example; no real email or live malicious infrastructure is involved.

## 1. Scenario

A staff member reports an unexpected email claiming that their mailbox will be restricted unless they review an account notice. The message asks the recipient to open an unfamiliar link.

The sample indicators below are deliberately reserved examples, not live infrastructure:

- Display name: "IT Helpdesk"
- Sender: `support@example.invalid`
- Reply-To: `reply@example.invalid`
- Link text: "Review mailbox"
- Example destination: `https://account-check.example.invalid/`
- Attachment: None in this scenario

## 2. Triage steps

1. Preserve the original message as an approved evidence format, such as an EML export, without forwarding it to other users.
2. Compare the display name, sender address and Reply-To address.
3. Inspect the message headers for Received chain, SPF, DKIM and DMARC results where available.
4. Review the actual hyperlink destination without opening it.
5. Check whether the message uses urgency, threats or an unexpected request for credentials.
6. Search for other reports or matching messages using approved mail-security tooling.
7. Record the evidence and escalate according to the organization's process.

## 3. Header review notes

Authentication results need context. A pass result does not automatically make a message safe, and a fail result can occur for legitimate forwarding or configuration reasons. Review the aligned domains and the complete header chain.

## 4. Assessment of this fictional scenario

| Observation | Meaning | Limitation |
|---|---|---|
| Unexpected account restriction warning | Pressure/urgency indicator | Legitimate notices can also be urgent |
| Sender uses an example.invalid domain | Training placeholder only | Not a real sender attribution |
| Link asks user to review mailbox | Link requires destination validation | Link text alone does not reveal destination safety |
| No attachment in scenario | No attachment to inspect | Does not reduce link-related risk |

**Training verdict:** Suspicious indicators are present in the fictional narrative. No real message was analyzed, and no real sender or domain is being accused.

## 5. Recommended response

- Do not interact with the link.
- Preserve the message and report it through the approved channel.
- If a recipient entered credentials, follow the organization's account-protection and incident-escalation process.
- Search for similar messages and assess whether other recipients were affected.
- Block or remove messages only through authorized mail-security procedures and after validation.

## 6. Evidence to add for a real lab exercise

- [ ] Sanitized EML/header screenshot
- [ ] SPF, DKIM and DMARC results
- [ ] Sender and Reply-To comparison
- [ ] URL text and safely recorded destination
- [ ] Mail gateway or message trace evidence
- [ ] Scope and recipient impact
- [ ] Verdict, confidence and limitations

Never include real recipient personal data, credentials, active malicious URLs or unsafe attachments in this public repository.