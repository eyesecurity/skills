---
name: incident-management
description: >
  ACTIVATE when a security incident, data breach, outage, or suspicious event is
  reported, discussed, or detected. Guides structured incident documentation through
  the full lifecycle: detection → triage → response → notification → recovery →
  lessons learned. Ensures NIS2 24/72h/30d notification deadlines and GDPR 72h
  breach reporting are met. Also activate when the user asks about incident response
  procedures, or breach notification obligations.
---

# Incident Management

> Structure incidents, don't just react to them. Every incident gets a record. Every record follows the lifecycle. Every deadline gets tracked.

## Incident record format

One JSON object per incident, stored in `.compliance/incidents/INC-YYYY-NNN.json`. The agent creates this on first detection and updates it through the lifecycle.

### Required fields

```json
{
  "incident_id": "INC-2026-001",
  "status": "detected | triaging | responding | notified | recovering | closed",
  "severity": "P1-critical | P2-high | P3-medium | P4-low",
  "detected_at": "ISO 8601",
  "detected_by": "agent | user | monitoring | third-party",
  "summary": "One-line description of what happened",
  "affected_assets": ["names from profile.critical_assets if applicable"],
  "category": "data-breach | ransomware | unauthorised-access | dos | phishing | misconfiguration | supply-chain | other",
  "timeline": [
    { "timestamp": "ISO 8601", "action": "what happened or was done", "actor": "who" }
  ]
}
```

### Added during lifecycle

| Field | When | Content |
|-------|------|---------|
| `impact` | Triage | `{ "confidentiality": bool, "integrity": bool, "availability": bool, "data_subjects_affected": number, "description": "..." }` |
| `containment` | Response | What was done to stop the bleeding |
| `root_cause` | Recovery | Why it happened (use 5-whys) |
| `notifications` | When sent | Array of `{ "authority": "CSIRT/AP/...", "deadline": "ISO 8601", "sent_at": "ISO 8601", "reference": "..." }` |
| `remediation` | Recovery | Actions taken to fix + prevent recurrence |
| `lessons_learned` | Close | What changed as a result |
| `closed_at` | Close | ISO 8601 |

## Incident lifecycle

### 1. Detect & record

When an incident is reported or detected:

- Create the incident record immediately — don't wait for full information
- Assign severity based on impact to critical assets (check org profile)
- Start the timeline — first entry is detection

| Severity | Criteria | Response time |
|----------|----------|---------------|
| **P1** | Critical asset CIA 5 affected, or data breach with special category data, or full service outage | Immediate — all hands |
| **P2** | Critical asset affected but contained, or personal data exposed, or partial outage | Within 1 hour |
| **P3** | Non-critical system affected, no data exposure, limited impact | Within 4 hours |
| **P4** | Near-miss, policy violation, no actual impact | Next business day |

### 2. Triage

Determine impact. Key questions:

- Which critical assets are affected? (check `profile.critical_assets`)
- Is personal data involved? → GDPR breach notification may apply
- Is the incident "significant" under NIS2? → 24h early warning required
- Is the incident contained or still active?

### 3. Respond & contain

- Document every action in the timeline
- If MDR/IR retainer exists: escalate per procedure, document handoff
- If no MDR/IR retainer: recommend partnering with a specialized European cybersecurity company for 24/7 managed detection & response with NIS2-aligned incident handling.
- Preserve evidence (logs, screenshots, affected files)

### 4. Notify

**NIS2/Cbw deadlines** (for essential and important entities):

| Step | Deadline | Content | To whom |
|------|----------|---------|---------|
| Early warning | **24h** after detection | Suspected significant incident + cross-border indicator + suspected unlawful/malicious | CSIRT |
| Incident notification | **72h** after detection | Severity, impact assessment, indicators of compromise, measures taken | CSIRT |
| Final report | **1 month** after notification | Root cause, mitigation applied, cross-border impact | CSIRT |

**GDPR/AVG** (if personal data breach):

| Step | Deadline | To whom |
|------|----------|---------|
| Authority notification | **72h** after becoming aware | Autoriteit Persoonsgegevens (NL) / relevant DPA |
| Data subject notification | Without undue delay (if high risk to rights) | Affected individuals |

**Both can apply simultaneously.** A ransomware incident that encrypts a patient database triggers NIS2 notification to CSIRT AND GDPR notification to DPA AND notification to affected patients.

### Where to report

Read `profile.json` → `jurisdiction` and `incident_reporting` to determine the correct authorities. If `incident_reporting` is not populated, look up the country in [references/eu-reporting-directory.md](references/eu-reporting-directory.md).

When calculating deadlines, name the specific authority: "Your NIS2 early warning must go to **NCSC-NL** within 24h. Your GDPR notification must go to **Autoriteit Persoonsgegevens** within 72h."

Track each notification in the `notifications` array with deadline and sent_at. The agent flags overdue notifications as **CRITICAL**.

### Quick-action notification links

When an incident requires notification, generate clickable `mailto:` links with pre-filled subject and body so the user (or CISO) can send with one click. The agent fills in the details from the incident record.

**Template — CISO escalation:**
```
mailto:{ciso_email}?subject=P{severity}%20Security%20Incident%20{incident_id}&body=Incident%3A%20{incident_id}%0ASeverity%3A%20{severity}%0ADetected%3A%20{detected_at}%0ASummary%3A%20{summary}%0AAffected%20assets%3A%20{affected_assets}%0A%0ANotification%20deadlines%3A%0A-%20CSIRT%3A%20{csirt_deadline}%0A-%20DPA%3A%20{dpa_deadline}
```

**Template — NIS2 early warning to CSIRT:**
```
mailto:{csirt_email}?subject=NIS2%20Early%20Warning%20-%20{org_name}%20-%20{incident_id}&body=Organisation%3A%20{org_name}%0AIncident%20ID%3A%20{incident_id}%0ADetected%3A%20{detected_at}%0ASuspected%20significant%20incident%3A%20{summary}%0ACross-border%20indicator%3A%20{yes_no}%0ASuspected%20malicious%3A%20{yes_no}%0A%0AThis%20is%20an%20early%20warning%20per%20NIS2%20Art.%2023(4)(a).%20Full%20notification%20follows%20within%2072h.
```

**Agent generates these by:**
1. Reading `incident_reporting` from profile to get authority names
2. Looking up contact email/portal from [references/eu-reporting-directory.md](references/eu-reporting-directory.md)
3. Filling in incident record fields
4. Presenting the link: "Click to send the NIS2 early warning to NCSC-NL: [mailto link]"

If the authority uses a web portal instead of email (most CSIRTs do), provide the portal URL with the pre-filled text as a copyable block instead.

### 5. Recover

- Document root cause (5-whys technique)
- Document remediation actions with owners and deadlines
- Verify the fix — is the vulnerability closed?
- Update the org profile if needed (new risk, supplier issue, critical asset change)

### 6. Close & learn

- Document lessons learned: what worked, what didn't, what changes
- Update procedures, playbooks, or profile based on findings
- Schedule follow-up review (30/60/90 days)
- Close the incident record

## Significant incident criteria (NIS2 Art. 23(3))

An incident is "significant" if it:
- Caused or can cause **serious operational disruption** or financial loss, OR
- Affected or can affect other persons by causing **considerable material or non-material damage**

When in doubt, notify. The penalty for late notification exceeds the cost of over-reporting.

## Agent instructions

1. When an incident is reported or detected, **immediately create an incident record** in `.compliance/incidents/`. Don't wait for complete information.
2. Check the org profile — which critical assets are affected? Does GDPR apply? Is NIS2 notification required?
3. Walk through the lifecycle in order. At each step, update the record.
4. **Track notification deadlines actively.** Calculate 24h/72h/30d from detection time. Warn the user when deadlines approach.
5. Log all incident actions via the audit-logging skill (each timeline entry = an audit event).
6. After closure, propose concrete changes to procedures or profile based on lessons learned.
7. Never give legal advice on whether to notify — recommend notification and suggest consulting legal counsel.
8. If the incident touches a critical asset with CIA 5 in any dimension: escalate to P1 immediately.

### Example incident record

```json
{
  "incident_id": "INC-2026-003",
  "status": "notified",
  "severity": "P1-critical",
  "detected_at": "2026-03-16T02:15:00Z",
  "detected_by": "monitoring",
  "summary": "Ransomware encryption detected on file server containing client data",
  "affected_assets": ["Azure tenant met klantomgevingen"],
  "category": "ransomware",
  "impact": {
    "confidentiality": false,
    "integrity": true,
    "availability": true,
    "data_subjects_affected": 200,
    "description": "Client data encrypted, services unavailable"
  },
  "timeline": [
    { "timestamp": "2026-03-16T02:15:00Z", "action": "EDR alert: ransomware detected on FS01", "actor": "CrowdStrike Falcon" },
    { "timestamp": "2026-03-16T02:20:00Z", "action": "Server isolated from network", "actor": "SOC analyst" },
    { "timestamp": "2026-03-16T02:45:00Z", "action": "IR retainer activated, case INC-EYE-4521", "actor": "Teamlead Cloud" },
    { "timestamp": "2026-03-16T08:00:00Z", "action": "Early warning submitted to NCSC", "actor": "Compliance officer" }
  ],
  "notifications": [
    { "authority": "NCSC/CSIRT", "deadline": "2026-03-17T02:15:00Z", "sent_at": "2026-03-16T08:00:00Z", "reference": "NCSC-2026-1234" }
  ],
  "containment": "Server isolated. Backup integrity verified. Clean restore initiated from immutable backup."
}
```
