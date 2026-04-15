---
name: change-management
description: >
  ACTIVATE when making changes that affect critical assets: deployments, database
  migrations, schema changes, Terraform/IaC modifications, access control or IAM
  changes, firewall rules, TLS certificates, environment variables on production,
  or dependency upgrades. Ensures every change is documented, impact-assessed,
  approved, and reversible per NIS2 Art. 21(2)(e) and ISO 27001 A.8.32.
---

# Change Control

> Every change to a critical asset gets a record. No exceptions.

## Change record format

## Storage

All change records: `.compliance/changes/CHG-YYYY-NNN.json` — one file per change.

## Change record format

### Required fields

```json
{
  "change_id": "CHG-2026-001",
  "status": "proposed | approved | implementing | completed | rolled-back | rejected",
  "requested_at": "ISO 8601",
  "requested_by": "agent | user | system",
  "summary": "One-line description of what changes",
  "affected_assets": ["names from profile.critical_assets if applicable"],
  "impact": "critical | high | medium | low",
  "change_type": "code | config | infrastructure | access | data-schema | dependency",
  "risk_assessment": "What could go wrong",
  "rollback_plan": "How to reverse this change",
  "approval": {
    "required": true,
    "approved_by": "name or null",
    "approved_at": "ISO 8601 or null"
  }
}
```

### Added after implementation

| Field | When | Content |
|-------|------|---------|
| `implemented_at` | After execution | ISO 8601 |
| `verified_by` | After testing | Who confirmed it works |
| `closed_at` | After verification | ISO 8601 |
| `actual_impact` | If different from expected | What actually happened |

## Impact classification

Impact is determined by which critical assets are affected:

| Impact | Criteria | Approval |
|--------|----------|----------|
| **Critical** | Touches critical asset with CIA 5 in any dimension | Human approval required before execution |
| **High** | Touches any critical asset, or changes access controls | Human approval required |
| **Medium** | Touches systems connected to critical assets | Agent may proceed with notification |
| **Low** | No critical asset impact | Agent may proceed, log only |

## Change lifecycle

### 1. Propose

Before making a change to a critical asset:

- Create the change record
- Identify affected critical assets (check `profile.critical_assets`)
- Classify impact
- Define rollback plan — **every change must be reversible**

### 2. Approve

- **Critical/High**: present change record to user, wait for explicit approval
- **Medium**: notify user, proceed unless they object
- **Low**: proceed, record for audit trail

### 3. Implement

- Log the change via audit-logging (`event_class: "tool_call"`, linked to change_id)
- Execute the change
- Record `implemented_at`

### 4. Verify

- Confirm the change works as expected
- Check that no unintended side effects occurred
- Record `verified_by`

### 5. Close or roll back

- If successful: close the change record
- If problems: execute rollback plan, log the rollback, document what went wrong

## What counts as a change to a critical asset

| Change type | Examples | Impact signal |
|-------------|----------|---------------|
| **Code** | New feature touching critical asset data, DB migration, API endpoint changes | Schema changes = high. New queries = medium |
| **Config** | Firewall rules, conditional access policies, MFA settings, backup config | Security config = critical. Feature flags = low |
| **Infrastructure** | Server migration, cloud region change, scaling changes, DNS | Hosting change = check data residency. Scale = medium |
| **Access** | New user/service account, permission changes, admin role grants | Admin access to critical asset = critical |
| **Data schema** | New columns, table changes, data model modifications | On critical asset DB = high. On non-critical = medium |
| **Dependency** | New library, SDK update, vendor API version change | Check vendor-risk skill for vendor assessment |

## External ticketing integration

If the organisation uses a ticketing system, create change tickets there instead of (or in addition to) local JSON files. The local `.compliance/changes/` path is the fallback when no external system is available.

| Platform | How to integrate | Official skill |
|---|---|---|
| **Jira** | Use Jira MCP or REST API to create issues in the compliance project. Map: `change_id` → Jira key, `impact` → priority, `status` → workflow state, `affected_assets` → labels. | [Jira MCP](https://github.com/modelcontextprotocol/servers/tree/main/src/atlassian) |
| **Linear** | Use Linear MCP to create issues. Map: `impact` → priority (Urgent/High/Medium/Low), `change_type` → label. | [Linear MCP](https://github.com/modelcontextprotocol/servers/tree/main/src/linear) |
| **ServiceNow** | Use ServiceNow Change Management API. Map: `impact` → risk level, CHG record fields align 1:1 with ServiceNow change request schema. | ServiceNow REST API |
| **GitHub Issues** | Use `gh issue create` with labels for impact level and affected assets. Lightweight option for dev teams. | Built-in GitHub CLI |

When creating external tickets, always also write the local `.compliance/changes/CHG-*.json` record — it feeds into the compliance-hub for retention and audit trail.

## Agent instructions

1. Before modifying any file, config, or system: check if it's a critical asset or connected to one (read `profile.critical_assets`).
2. If it is: create a change record before proceeding. For critical/high impact, present to user and wait for approval.
3. If a ticketing system (Jira, Linear, ServiceNow) is available in the environment, create the ticket there AND write the local JSON record. If no external system: local record only.
4. Always define a rollback plan. For code changes: the previous commit. For config: the previous value. For infra: document how to revert.
5. Log every change via audit-logging, linking to the change_id.
6. After implementation, verify the change works and close the record.
7. If something goes wrong: execute rollback, document in the change record, consider whether to start an incident record via incident-management.
8. Cross-reference with vendor-risk: if the change introduces a new dependency, run vendor assessment first.
