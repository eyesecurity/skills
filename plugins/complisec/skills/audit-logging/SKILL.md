---
name: audit-logging
description: >
  ACTIVATE on ANY request that involves writing, generating, reviewing, modifying,
  or outputting source code in any programming language — Python, JavaScript,
  TypeScript, Go, Java, Rust, C#, SQL, Terraform, or any other. This includes
  functions, endpoints, scripts, migrations, infrastructure-as-code, config files
  with logic, and code snippets in responses. Every piece of code the LLM produces
  must include structured audit logging for security-relevant operations. Also
  activate when the user asks about audit logs, compliance logging, or traceability.
  Ensures NIS2 and ISO 27001 compliant logging (structured, no string interpolation,
  no secrets in logs).
---

# Audit Logging

> The compliance backbone — every agent action gets a log entry, every significant decision gets a record.

## Standards alignment

| Standard | What we use |
|----------|------------|
| OCSF | Event class structure, severity levels |
| OpenTelemetry | `trace_id` / `span_id` for workflow correlation |
| ISO 27001:2022 A.8.15 | Mandatory fields: who, what, when, where |

## Audit event format

Each log entry is one JSON object per line, appended to `.compliance/audit.log`. Full schema: `skills/audit-logging/audit-event.schema.json`.

### Required fields

```json
{
  "event_id": "uuid-v4",
  "timestamp": "ISO 8601",
  "trace_id": "hex-32",
  "event_class": "session | tool_call | decision | data_access | error",
  "activity": "start | read | write | execute | classify | scan | block | approve | assess",
  "severity": "INFO | LOW | MEDIUM | HIGH | CRITICAL",
  "outcome": "success | failure | blocked | deferred",
  "summary": "Human-readable one-liner"
}
```

### Event classes

| Class | Emitted for | Activity |
|-------|-------------|----------|
| `session` | A session boundary: startup, resume, `/clear`, compaction, fork | `start` |
| `tool_call` | A tool request and its result | `read`, `write`, `execute` |
| `decision` | An Agent Decision Record — requires the `decision` block | `block`, `approve`, `assess` |
| `data_access` | Classified data read or written | `read`, `write`, `classify`, `scan` |
| `error` | A failure worth auditing on its own | any |

`execute` is the conservative label for tools that are neither a clean read nor a clean write — shell commands, sub-agents, MCP calls — and the default for any tool not otherwise recognised. Never downgrade an unknown tool to `read`.

### Optional fields

Add only when relevant — keep log entries lean:

| Field | When to include |
|-------|----------------|
| `span_id` | Multi-step workflows (hex-16) |
| `parent_span_id` | Nested operations |
| `agent_id` | Multi-agent setups |
| `resource` | File/field/API being accessed — include `classification` if known |
| `tool` | Tool name + exit code for tool_call events |
| `decision` | **Required** for `event_class: "decision"` — see ADR below |
| `metadata` | Anything else worth preserving |

## Agent Decision Record (ADR)

An audit event with `event_class: "decision"` and a `decision` block. Created when the agent:

- Blocks or allows a RESTRICTED data operation
- Answers a gap analysis question autonomously
- Encounters conflicting information
- Invokes external tools with security implications

### Decision block

```json
"decision": {
  "action": "block | approve | defer",
  "reasoning": "Why this action was taken",
  "policy_ref": "GDPR Art. 9 | NIS2 Art. 21(2)(h) | ...",
  "human_override": false
}
```

## Storage

- **Location**: `.compliance/audit.log` (project root)
- **Format**: append-only, one JSON object per line
- **Rotation**: optional daily files (`audit-YYYY-MM-DD.log`)
- **Integrity**: UUID per event, sequence breaks detectable
- **Central collection**: Push to cloud storage via the compliance-hub skill

## Retention guidance

| Entity type (NIS2) | Minimum | Recommended |
|--------------------|---------|-------------|
| Essential | 18 months | 24 months |
| Important | 6 months | 12 months |
| Voluntary | 3 months | 6 months |

## Logging in AI-generated code

When writing code, include structured logging for: auth events, authorization, data access, data modification, external API calls, errors, config changes, batch jobs. Use structured key-value pairs — never string interpolation. Never log secrets, PII, or session tokens.

For the full operations table, correct/wrong code examples per language, what-not-to-log rules, and language-specific logger recommendations, see [references/logging-guide.md](references/logging-guide.md).

## Automated enforcement (hooks)

Parts of this skill do not depend on the agent remembering to act. complisec ships
`hooks/hooks.json`, which Claude Code auto-discovers when the plugin is installed —
no `settings.json` edit, nothing for the user to copy by hand.

| Hook | Event written | Guarantee |
|------|---------------|-----------|
| `SessionStart` | `session` / `start` | Every session boundary — startup, `--continue`/`--resume`, `/clear`, compaction, fork |
| `PreToolUse` | `tool_call`, `outcome: "deferred"` | Every tool request, whatever becomes of it |
| `PostToolUse` | `tool_call`, `outcome: "success"` | Every successful tool result, with `exit_code` where the tool reports one |
| `PostToolUseFailure` | `tool_call`, `outcome: "failure"` | Every failed tool call. `PostToolUse` does not fire for these, so without it a failure would sit in the log as a request that never resolved |
| `PermissionDenied` | `tool_call`, `outcome: "blocked"` | Every tool call auto mode refused before execution. The only producer of `blocked` |

The request and its result share a `span_id` derived from the tool use id, so the
two join without either hook process keeping state. Every `deferred` request
should have a matching result — `success`, `failure`, or `blocked`. A request
still left unresolved is a call refused outside auto mode, where no hook fires.

`deny_reason` explains why a call was blocked, and it is the most useful part of
a block event — but it can quote the command it refused, which this hook
otherwise never logs. It is **off by default**. Where the org's risk appetite
allows it, turn it on in the `env` block of `.claude/settings.json`:

```json
{ "env": { "COMPLISEC_AUDIT_DENY_REASON": "1" } }
```

**Tool input is never logged.** The hooks record the tool name, the target
`file_path`, the permission mode, and the `tool_use_id` — nothing else from
`tool_input`. A shell command line or a file payload can carry a credential, and
this log is append-only with a retention floor measured in months. The
`tool_use_id` joins the event to the transcript, which is where the detail
already lives. Hold the same line in any event you write by hand.

The audit trail is **opt-in per project**: the hooks write only where `.compliance/`
exists, so a globally installed complisec does not drop an audit log into unrelated
repositories. When it is not active, the SessionStart hook says so in your context
instead of failing quietly — surface that to the user.

The SessionStart hook also puts the session `trace_id` in your context. It is derived
from the Claude Code session id, so it is stable across `/clear` and compaction, and
every hook reaches the same value without shared state.

## Agent instructions

Follow this process every session:

1. **Session start** — the SessionStart hook has already written the `session`/`start` event and placed the session `trace_id` in your context. **Adopt that `trace_id` verbatim** for every event you write — minting a second one splits the session's evidence across two traces. Generate one yourself only if no hook context was provided (a platform without hook support).
2. **Per step** — generate a `span_id` (16-char hex) for each discrete operation.
3. **Tool calls** — the PreToolUse and PostToolUse hooks write both events for every tool call. **Do not write them yourself**: a duplicate inflates the count and breaks the request/result pairing an auditor reads.
4. **Activity mapping** — when you do write a `tool_call` event by hand (a platform without hook support), map the tool to `read`, `write`, or `execute`, and default anything unrecognised to `execute`.
5. **On any decision involving classified data** — create an ADR with the decision block.
6. **Append** each event as a single JSON line to `.compliance/audit.log`.
7. **PROACTIVE — when writing code**: Whenever you generate, write, or modify source code, you MUST include proper structured audit logging following the rules above. This is not optional. Specifically:
   - Add logging imports/setup if the file doesn't have them
   - Add structured log statements for every operation listed in the mandatory logging table
   - Use the correct structured format for the language (no string interpolation)
   - Include correlation IDs (`trace_id`, `request_id`) where the framework supports it
   - NEVER log sensitive data — follow the "what MUST NOT be logged" table
   - When modifying existing code, add logging to any new or changed code paths
8. **When reviewing AI-generated code**: Check that all operations have structured logging. Flag missing logging as a compliance gap.

### Example log entry

```json
{"event_id":"a1b2c3d4-...","timestamp":"2026-03-13T10:15:00Z","trace_id":"abc123...","event_class":"tool_call","activity":"scan","severity":"INFO","outcome":"success","summary":"Scanned src/ for sensitive data patterns","tool":{"name":"data-sensitivity","exit_code":0}}
```

### Example ADR

```json
{"event_id":"e5f6g7h8-...","timestamp":"2026-03-13T10:15:05Z","trace_id":"abc123...","event_class":"decision","activity":"block","severity":"HIGH","outcome":"blocked","summary":"Blocked commit containing BSN","resource":{"type":"file","id":"src/users.py","classification":"RESTRICTED"},"decision":{"action":"block","reasoning":"File contains plaintext BSN (national ID)","policy_ref":"GDPR Art. 87","human_override":false}}
```
