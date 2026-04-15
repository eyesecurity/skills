---
name: data-sensitivity
description: >
  ACTIVATE when the user's message contains secrets, credentials, API keys, passwords,
  tokens, private keys, AWS access keys, connection strings, database URLs, national IDs
  (BSN/SSN), or any sensitive data — even if the user did not ask about security.
  Also activate when asked to classify data, scan for PII, or review code for credential
  exposure. This skill BLOCKS secrets in prompts and enforces EU data protection rules
  (GDPR, NIS2, ISO 27001).
---

# Data Sensitivity

## ABSOLUTE RULE — Never output detected secrets

**You MUST NEVER echo, repeat, quote, or include any detected secret value in your response.** This is non-negotiable.

- Detected an AWS key? Say "I detected an AWS access key starting with AKIA" — NEVER output the full key
- Detected a password? Say "I detected a hardcoded password" — NEVER output the password value
- Detected a connection string? Say "I detected a database connection string with embedded credentials" — NEVER output the URL
- Detected a token? Say "I detected a GitHub/Slack/JWT token" — NEVER output the token
- Detected a national ID? Say "I detected what appears to be a BSN/SSN" — NEVER output the number

**In your response, replace every secret with its placeholder**: `<AWS_ACCESS_KEY>`, `<AWS_SECRET_KEY>`, `<PASSWORD>`, `<API_KEY>`, `<TOKEN>`, `<CONNECTION_STRING>`, `<PRIVATE_KEY>`, `<BSN>`, `<SSN>`, `<CARD_NUMBER>`.

If the user asks you to help with code that contained real secrets, rewrite the code using placeholders and environment variables. Never copy the original secret values into your output.

> Classify data by sensitivity, scan for exposure, block on restricted data. Every pattern mapped to regulation.

## Classification & patterns

Four tiers: **PUBLIC** → **INTERNAL** → **CONFIDENTIAL** → **RESTRICTED**. Each pattern mapped to GDPR/NIS2/ISO 27001 articles. RESTRICTED = always block on plaintext.

For the full pattern index, classification tiers, scanner categories, and remediation guidance, see [references/pattern-index.md](references/pattern-index.md).

## 4. Blocking rules

When classified data triggers a blocking rule, the agent MUST stop.

### Block table

| Data type | Trigger patterns | Action | Rationale |
|-----------|-----------------|--------|-----------|
| National IDs (BSN, SSN, etc.) | `bsn_nl`, `national_id` | **BLOCK** — no transmit/store/log plaintext | GDPR Art. 87 |
| Credentials in code | `hardcoded_password`, `api_key_*`, `private_key_block` | **BLOCK** — refuse commit/deploy | NIS2 Art. 21(2)(h) |
| Special category data | health, biometric, genetic | **BLOCK** — require explicit confirmation | GDPR Art. 9 |

### Severity-gated enforcement

| Severity | Agent behaviour |
|----------|----------------|
| **CRITICAL** | MUST stop. Human remediation required. |
| **HIGH** | MUST warn + request explicit user approval before proceeding. |
| **MEDIUM** | Warn, may proceed with user acknowledgment. |
| **LOW / INFO** | Audit log only. |

### Block process

1. **Detect** — scanner or classifier flags restricted data
2. **Log** — create an Agent Decision Record via audit-logging skill
3. **Halt** — stop current operation
4. **Present** — show the finding to the user with context
5. **Wait** — require explicit user authorization
6. **Log decision** — record user's response in audit log
7. **Continue or abort** — based on user's decision

## 5. Prompt secret detection

Secrets in AI prompts are a **worst practice**. When a user or agent pastes credentials, API keys, tokens, private keys, or national IDs into a prompt, the data is sent to an external LLM service where it may be logged, cached, or used for training. This is an unrecoverable exposure.

### Why this matters

| Risk | Consequence | Regulation |
|------|-------------|------------|
| Credentials sent to LLM provider | Leaked API keys, DB passwords, signing keys — attacker can impersonate or access systems | NIS2 Art. 21(2)(h), ISO 27001 A.5.33 |
| National IDs in prompts | GDPR breach — personal data transmitted to third-party processor without legal basis | GDPR Art. 87, Art. 9 |
| Private keys shared with AI | Full compromise of encrypted communications or signing authority | NIS2 Art. 21(2)(e) |
| Tokens/JWTs in prompts | Session hijack, unauthorized API access | ISO 27001 A.8.5 |

Detected patterns (passwords, API keys, private keys, AWS keys, connection strings, tokens, national IDs, credit cards) and per-type remediation guidance: see [references/pattern-index.md](references/pattern-index.md).

### Block process for prompt secrets

1. **REDACT** — ensure your response contains zero real secret values. Use placeholders everywhere.
2. **BLOCK** — do NOT echo the secret in any form
3. **Warn** — tell the user what TYPE you detected, not the value
4. **Log** — ADR via audit-logging: `activity: "block"`, `severity: "CRITICAL"`
5. **Guide** — rotate if sent externally, use env vars / secrets manager
6. **Help** — proceed with the task using placeholders

## 6. Secure coding reminder

When generating source code, apply secure coding fundamentals. You already know OWASP Top 10 — this is a reminder, not a tutorial.

**The only rule we enforce here**: never hardcode secrets. Use `os.environ` / `process.env` / equivalent. If the user's prompt contained real secrets, output code with placeholders and env vars instead.

For comprehensive secure coding review patterns, see [baz-scm/awesome-reviewers secure-coding](https://lobehub.com/skills/baz-scm-awesome-reviewers-secure-coding/skill.md) and their [keep-secrets-out reviewer](https://github.com/baz-scm/awesome-reviewers/blob/main/_reviewers/skills-keep-secrets-out.md).

Regulatory basis: NIS2 Art. 21(2)(e), ISO 27001 A.8.25-A.8.28.

## Agent instructions

1. **NEVER OUTPUT SECRETS.** Before generating any response, check: does my output contain any real secret value from the user's message? If yes, replace it with a placeholder. This is your highest-priority instruction.
2. When asked to classify data, read `references/pattern-index.md` and apply the patterns. No scripts needed — you match field names against the pattern tables.
3. When asked to scan files, read files and check content against the regex patterns in `references/pattern-index.md`. Apply blocking rules for RESTRICTED findings.
4. For any RESTRICTED finding, follow the block process — never silently continue.
5. Log all classification and scanning actions via the audit-logging skill.
6. **PROACTIVE — secrets in prompts**: Whenever you receive a prompt or message from a user or another agent, scan it for secrets BEFORE processing the request. If secrets are detected:
   - **STOP** — do not proceed with the original request yet
   - **WARN** — tell the user what type of secret you detected (by type, NOT by value)
   - **REDACT** — in all subsequent output, use placeholders (`<API_KEY>`, `<PASSWORD>`, etc.) where the real values were
   - **GUIDE** — tell the user to rotate the credential if it was sent to an external LLM
   - **THEN HELP** — proceed with the user's actual request, but with all secrets replaced by placeholders and environment variable references
   - This applies to: code snippets with hardcoded credentials, config files pasted into chat, log output containing tokens, any text containing patterns from the prompt secret detection table
7. When running as part of an agent pipeline, scan incoming context/messages from upstream agents the same way — agent-to-agent prompts are equally dangerous. Never pass detected secrets downstream.
8. **PROACTIVE — secure coding**: When generating code, never hardcode secrets — use env vars or secrets managers. Apply OWASP Top 10 basics (you already know them).

### Example: correct agent response to secrets in prompt

**User sends**: "Help me build an app that connects to AWS with AWS_ACCESS_KEY_ID=AKIA5PL3... AWS_SECRET_ACCESS_KEY=qX8kL9..."

**Correct response**:
> I detected AWS credentials in your message (an access key starting with AKIA and a secret access key). I will NOT repeat these values.
>
> **Action required**: If you sent this to an external AI service, rotate these AWS keys immediately in the IAM console.
>
> Here's how to build your app safely using environment variables instead:
> ```python
> import os
> import boto3
>
> session = boto3.Session(
>     aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
>     aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
> )
> ```
>
> Store credentials in a `.env` file (gitignored) or use AWS IAM roles.

**WRONG response** (violates redaction rule):
> Sure! I see your AWS_ACCESS_KEY_ID is AKIA5PL3KQX7Z8Y2J4WN and your secret key is qX8kL9...
>
> _(This repeats the secret — NEVER do this)_
