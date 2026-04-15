---
name: vendor-risk
description: >
  ACTIVATE when integrating a new service, API, SaaS tool, SDK, npm/pip/maven package,
  Docker image, or any third-party dependency — or when discussing suppliers, vendors,
  processor agreements, or supply chain security. Also activate on imports from unknown
  packages or adding external webhooks/endpoints. Ensures every new vendor or dependency
  is assessed against the org's critical assets, data residency, and NIS2 Art. 21(2)(d)
  supply chain requirements.
---

# Vendor Risk Management

> Every new integration is a supply chain decision. No vendor gets access without assessment.

## Storage

- **Vendor assessments**: `.compliance/vendors/VND-YYYY-NNN-slug.json` — one file per assessment
- **Approved vendor summary**: `profile.json` → `suppliers[]` — kept in sync after approval

## Vendor assessment record

One JSON per vendor assessment. Created on first contact, updated through lifecycle.

```json
{
  "assessment_id": "VND-2026-001-hubspot",
  "vendor_name": "HubSpot",
  "status": "proposed | under-review | approved | conditional | rejected | offboarded",
  "assessed_at": "ISO 8601",
  "assessed_by": "agent | user",
  "type": "saas | infra | service | library | api",
  "data_shared": ["klantdata", "email", "contactgegevens"],
  "criticality": "critical | important | standard",
  "touches_critical_assets": ["Klant-administratiedata (CRM)"],
  "checks": {
    "dpa_signed": false,
    "hosting_location": "EU (Ireland)",
    "hosting_compliant": true,
    "certification": "SOC2 Type II",
    "access_scope": "API read/write to CRM contacts",
    "least_privilege": true,
    "exit_strategy": "CSV export available"
  },
  "decision": "approved | conditional | rejected",
  "decision_reasoning": "Why this decision was made",
  "conditions": ["DPA must be signed before go-live"],
  "review_date": "ISO 8601 — next scheduled review",
  "timeline": [
    { "timestamp": "ISO 8601", "action": "what happened", "actor": "who" }
  ]
}
```

## Vendor lifecycle

### 1. Identify

When the agent detects a new vendor (user mentions a tool, code imports a new SDK, API call to unknown service):

- Check `profile.suppliers` — is this vendor already known?
- If unknown: **flag immediately** and start the assessment

### 2. Assess

| Check | Question | Fail = |
|-------|----------|--------|
| **Data flow** | What data does this vendor access or receive? | If it touches a critical asset → criticality = critical |
| **DPA/processor agreement** | Is a Data Processing Agreement (DPA) signed? | Required if personal data is shared (GDPR Art. 28) |
| **Hosting location** | Where is data stored/processed? | If org has data residency constraints → check compliance |
| **Security posture** | Does the vendor have ISO 27001, SOC2 Type II, or equivalent? | No certification for critical vendor = HIGH risk |
| **Access scope** | What systems/APIs does the vendor need access to? Least privilege? | Broader than necessary = flag |
| **Exit strategy** | Can you extract your data and switch vendors? | Vendor lock-in on critical asset = risk |

### 3. Decide

| Outcome | When | Action |
|---------|------|--------|
| **Approve** | All checks pass, DPA in place, hosting compliant | Add to `profile.suppliers` with status "approved" |
| **Conditional** | Minor gaps (e.g. DPA pending, certification in progress) | Approve with deadline for remediation, flag for follow-up |
| **Reject** | Fails data residency, no DPA possible, touches critical asset without security posture | Do not integrate. Log decision via audit-logging |

### 4. Monitor

- Set `contract_review_date` — review vendors annually at minimum, critical vendors every 6 months
- When a vendor's certification expires or a breach is disclosed: re-assess
- Track vendor incidents — if a vendor reports a breach, start incident-management lifecycle

### 5. Offboard

When a vendor relationship ends:
- Revoke all access (API keys, accounts, network access)
- Verify data deletion or return per DPA terms
- Set `offboard_date` and `status: "offboarded"`
- Log via audit-logging

## Triggers for the agent

The agent flags a vendor risk event when:

- Code imports a new external dependency (`pip install`, `npm install`, new API client)
- User discusses integrating a new SaaS tool
- Code makes HTTP calls to a domain not in the approved supplier list
- A vendor's `contract_review_date` is past due
- The agent discovers an undocumented data flow to an external service

## Agent instructions

1. When a new vendor or service appears in conversation or code, check `profile.suppliers`. Unknown = create assessment record in `.compliance/vendors/` and start the lifecycle.
2. Cross-reference vendor data access against `profile.critical_assets`. Touches a critical asset = criticality=critical.
3. Check data residency constraints from `profile.constraints`. Flag hosting location violations.
4. For every vendor decision, log an ADR via audit-logging (`policy_ref: "NIS2 Art. 21(2)(d)"`).
5. On approval: add vendor to `profile.suppliers` and set `review_date`.
6. Remind about overdue reviews based on `review_date`.
7. On offboard: verify access revocation, update assessment record, set status "offboarded".
