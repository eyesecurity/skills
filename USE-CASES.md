# complisec — Use Cases & Activation Scenarios

> How complisec should behave in real-world agentic workflows. Every scenario below is a situation where the skill activates and adds value that the base model doesn't have: organisation-specific context from the profile, critical assets, risk appetite, and regulatory constraints.

## Core principle: the org profile IS the skill

A skill without context is a generic checklist. What makes complisec valuable is that it carries **the organisation's profile** into every conversation — critical assets, suppliers, legal obligations, risk appetite, data residency constraints. The profile turns a generic "don't hardcode secrets" into "this org is ABDO-certified and cannot store data outside the Netherlands, and your code sends data to an AWS region in Ireland."

The agent MUST read `.compliance/profile.json` at the start of every activation. If it doesn't exist, the first action is to create it through conversation.

---

## Scenario 1: Data residency violation in code

**Context**: Organisation is ABDO-certified (Dutch government), data may not leave the Netherlands.
**Profile captures**: `data_residency: "NL only"`, `legal: ["ABDO"]`

**Trigger**: User asks agent to write code or review code that uses a cloud service.

**What the agent does**:
- Reads profile → sees ABDO constraint
- Sees `boto3.client('s3', region_name='eu-west-1')` (Ireland) or `openai.ChatCompletion.create(...)` (US-hosted API)
- Flags: "Your org profile indicates ABDO certification — data must stay in the Netherlands. This code sends data to eu-west-1 (Ireland). Use eu-central-1 or nl-ams-1 equivalent, or verify with your ABDO officer that this processing is covered by an exception."
- Logs an ADR with policy_ref: "ABDO / data residency requirement"

**Without complisec**: The base model has no idea about the org's ABDO status and would happily generate code pointing to any AWS region.

---

## Scenario 2: MSSP with CrowdStrike as critical asset

**Context**: Organisation is an MSSP. CrowdStrike is their core detection platform — it's a critical asset with CIA 5/5/5.
**Profile captures**: `critical_assets: [["CrowdStrike Falcon", "sys", [5,5,5], "SOC lead"]]`

**Trigger**: User or agent discusses CrowdStrike API integration, access management, data export, or connecting a new tool to CrowdStrike.

**What the agent does**:
- Reads profile → sees CrowdStrike is a critical asset with max CIA
- Any conversation about CrowdStrike access, API keys, data flows, or integrations triggers heightened awareness
- Warns: "CrowdStrike is identified as your highest-criticality critical asset (CIA 5/5/5). Changes to access, API integrations, or data flows require extra scrutiny. Consider: who has API access? Is the key scoped to minimum permissions? Is the integration logged? Does this create a new data flow outside your current scope?"
- If code contains CrowdStrike API keys: BLOCK + redact + warn about rotation

**Without complisec**: The base model treats CrowdStrike like any other API integration.

---

## Scenario 3: Healthcare platform — patient database as critical asset

**Context**: SaaS platform for healthcare. Patient dossier database is the most critical asset.
**Profile captures**: `critical_assets: [["Patientendossier DB", "data", [5,5,4], "CTO"]]`, `legal: ["GDPR controller", "NEN7510"]`

**Trigger**: Any code that touches the patient database, changes to access control, new API endpoints that expose patient data, log configuration changes.

**What the agent does**:
- Reads profile → sees patient DB is a critical asset with GDPR Art. 9 special category
- When generating a new API endpoint that queries patient data: "This endpoint accesses your patient dossier database (critical asset, GDPR Art. 9 special category). Ensure: (1) access control checks on every request, (2) audit logging of who accessed which record, (3) no patient data in application logs, (4) DPIA has been updated for this new processing."
- When reviewing code that changes DB schema: "Schema change on your most critical asset. Has the DPIA been updated? Does the new field contain special category data?"

**Without complisec**: The base model doesn't know this specific database is the crown jewel, or that GDPR Art. 9 applies.

---

## Scenario 4: Risk appetite enforcement

**Context**: Organisation has defined risk appetite — they accept medium risk for availability but zero tolerance for confidentiality breaches.
**Profile captures**: `risk_appetite: { "c": "zero_tolerance", "i": "low", "a": "medium" }`

**Trigger**: Agent is asked to make an architectural decision or trade-off.

**What the agent does**:
- User asks: "Should we use a cheaper hosting provider that has occasional outages but saves 40% on costs?"
- Reads profile → risk appetite says availability=medium (acceptable), but checks if any critical assets with availability=5 would be affected
- Response: "Your risk appetite allows medium availability risk. However, your Azure tenant (critical asset, availability=5) and helpdesk process (critical asset, availability=5) are hosted there. For non-critical-asset systems, this trade-off aligns with your board's risk appetite. For critical asset systems, the 4h downtime tolerance does not apply."

**Without complisec**: The base model makes generic cost/reliability trade-off suggestions without knowing the org's specific risk appetite.

---

## Scenario 5: Supplier touches a critical asset

**Context**: Organisation onboards a new SaaS tool that needs access to data covered by a critical asset.
**Profile captures**: `critical_assets` + `suppliers` + `saas_landscape`

**Trigger**: User asks agent to integrate a new tool, write an API connector, or evaluate a vendor.

**What the agent does**:
- User: "Help me connect HubSpot to our CRM database"
- Reads profile → CRM database is a critical asset (klantdata, confidentiality=4)
- Reads suppliers → HubSpot not in current supplier list
- Warns: "Your CRM database is a critical asset (confidentiality=4). Connecting HubSpot creates a new data flow to a supplier not yet in your profile. Before proceeding: (1) Is there a verwerkersovereenkomst (DPA) with HubSpot? (2) Where does HubSpot store data? (EU/US — check Schrems II) (3) Add HubSpot to your supplier list with criticality assessment. (4) Update your register van verwerkingsactiviteiten."
- Updates profile.json with the new supplier entry (pending DPA status)

---

## Scenario 6: First-time onboarding — profile doesn't exist

**Trigger**: User asks any compliance question but `.compliance/profile.json` doesn't exist yet.

**What the agent does**:
- "I don't have an organisation profile yet. Let me help you create one — this takes about 10 minutes and makes all future compliance assessments organisation-specific."
- Guides through: name, jurisdiction, sector, size → activities → critical assets → key suppliers → legal obligations
- For critical assets, uses probing questions: "Which systems are so critical that 4+ hours of downtime directly hits customers or revenue?"
- Creates `.compliance/profile.json` and confirms with user
- Then proceeds with the original question, now informed by the profile

---

## Scenario 7: Code review flags compliance risk

**Trigger**: Agent is asked to review a PR or code change.

**What the agent does**:
- Reads profile to understand what matters
- Scans code for:
  - Secrets in source (always, regardless of profile)
  - Data flows to regions outside org's jurisdiction constraints
  - New database queries touching critical asset data without audit logging
  - New external API calls to services not in the supplier list
  - Logging of data that should not be logged (PII, special category)
- Frames findings as compliance risks, not just code quality: "This change adds a call to an external geocoding API. Your profile doesn't list this as an approved supplier, and it sends customer addresses (GDPR Art. 4(1) personal data) to an external processor without a DPA."

---

## How critical assets drive everything

Critical assets are the centre of gravity. Every scenario above comes back to: **does this action touch a critical asset, and if so, what are the implications?**

```
User action                        complisec checks
─────────────────────────────────  ──────────────────────────────────────
Write/review code                  → Does it touch a critical asset? Data residency ok?
Integrate a new service            → Does it access critical asset data? DPA in place?
Change infrastructure              → Does it affect critical asset availability/integrity?
Discuss access/permissions         → Who gets access to critical assets? Least privilege?
Architectural decision             → How does this affect critical asset CIA ratings?
Onboard/offboard a supplier        → Does the supplier touch critical assets?
Handle an incident                 → Which critical assets are affected? Meldplicht?
```

The profile.json is the persistent context that makes this possible. Without it, every conversation starts from zero.

---

## Can a skill modify itself?

**Technically yes** — the agent can edit any file, including SKILL.md. But this is the wrong pattern.

**The right pattern**: skills stay stable, org context is dynamic data.

- `SKILL.md` files = instructions (how to behave) → stable, versioned, shared across orgs
- `.compliance/profile.json` = org context (what matters) → dynamic, updated through conversation, org-specific
- The skill reads the profile at activation time and adapts its behaviour

On Claude Code specifically, skills support `!`command`` syntax for dynamic context injection — a command runs before the skill loads and its output gets injected into the prompt. This means we can inject the live profile:

```yaml
## Organisation context
!`cat .compliance/profile.json 2>/dev/null || echo '{"status": "no profile yet — guide user through onboarding"}'`
```

On LangDock, the agent reads the profile through tool calls (file read) after the skill body loads. Same result, different mechanism.

**We should NOT** modify SKILL.md based on the org — that breaks distribution. One complisec zip works for every organisation. The profile.json is what makes it org-specific.

---

## Adding risk appetite to the profile

The profile should capture risk appetite so the agent can make trade-off recommendations:

```json
"risk_appetite": { "c": "zero_tolerance", "i": "low", "a": "medium" }
```

Levels: `zero_tolerance` | `low` | `medium` | `high`

The agent uses this to calibrate warnings. A `medium` availability risk appetite means the agent doesn't flag every potential uptime issue — only those affecting critical assets with availability >= 4.
