# PhishGuard — Gmail Outgoing Email Security Scanner

## Overview

PhishGuard is a personal defensive security project: a Chrome extension designed to review an outgoing email in Gmail's compose/send workflow and warn the user when message content appears suspicious or high risk.

The goal is to provide a warning before an email is sent, rather than relying only on a separate file-upload scanner.

## Intended workflow

1. The user writes an email in Gmail.
2. The extension inspects the message content during the compose/send flow.
3. It evaluates the content using its configured risk checks.
4. If the message is assessed as high risk, the extension displays a warning and is intended to prevent sending until the user reviews it.

## Current project notes

- Implemented as an unpacked Chrome extension for local testing.
- Main extension files include `manifest.json` and `content.js`.
- Tested in the user's personal Gmail / Chrome profile.
- A high-risk warning and send-blocking behavior were observed in local testing.
- This is a prototype and has not been independently security-audited or tested for broad compatibility.

## Scope and limitations

- Personal learning project; not deployed as a production email security product.
- Designed for the user's personal Gmail profile, not company accounts or company systems.
- Detection is heuristic/prototype-level; warnings can be missed or incorrectly triggered.
- Do not use it as the only control for sensitive or business-critical email.

## Skills demonstrated

- Chrome extension structure and content-script concepts
- DOM interaction in a web application
- Defensive email-security thinking
- Risk warnings and user-facing security controls
- Iterative testing and debugging

## Evidence and honest status

The project overview is documentation of the prototype and the behavior observed during personal local testing. The extension source code is not included in this portfolio repository, so reviewers cannot independently reproduce the implementation from this repository yet. Do not treat the prototype as a production email-security control.

## Suggested next documentation milestones

- Add sanitized screenshots of the Gmail warning state (remove personal email addresses and message content).
- Add a short architecture diagram describing the compose detection, risk evaluation and send-interception stages.
- Add a small test matrix with benign, suspicious and high-risk synthetic examples, recording expected and observed outcomes.
- Include the extension source only after removing secrets, personal data and account-specific identifiers.
