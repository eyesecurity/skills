---
name: complisec
argument-hint: "[setup]"
description: >
  EU compliance enforcement for AI agents — NIS2, GDPR, ISO 27001.
  ACTIVATE on EVERY prompt. Reads .compliance/profile.json to enforce data residency,
  supplier checks, secret blocking, audit logging, and risk appetite on all code
  generation, cloud deployments, data exports, and API integrations.
  Invoke /complisec setup to create the org profile.
---

# complisec — EU Compliance for AI Agents

## Important: Installation vs Usage

If you were asked to **install, clone, or set up** this skill — complete the installation and confirm to the user. Do NOT run the onboarding questionnaire during installation. The questionnaire only runs when the user explicitly invokes `/complisec setup` or asks to create their org profile.

## Boot sequence

When this skill is first loaded, execute these steps IN ORDER. Do not skip any step.

### Step 1 — Detect platform capabilities

Determine what you can do:

| Capability | How to check | Examples |
|---|---|---|
| **File read/write** | Can you read/write files on disk? | Claude Code, Cursor, Codex, local agents |
| **Shell commands** | Can you run bash/shell? | Claude Code, Cursor, Codex |
| **Memory/persistence** | Can you store data between conversations? | ChatGPT memory, Claude.ai projects, LangDock workspace |
| **Web fetch** | Can you fetch URLs? | Claude.ai, some ChatGPT configs |

Record your capabilities silently — do not explain them to the user.

### Step 2 — Find the org profile

Search for `"complisec_profile"` in this order. Stop at the first match:

1. **File system** (if you can read files): read `.compliance/profile.json`
2. **Conversation context**: scan the current system prompt, project instructions, custom instructions, or workspace settings for `"complisec_profile"`
3. **Memory** (if platform has memory): search for a previously stored complisec profile

### Step 3 — Act on what you found

**If profile found:** respond with exactly this format (fill in the values from the profile):

```
complisec loaded — [org name] ([jurisdiction])
Critical assets: [count] | Data residency: [constraint] | Legal: [regulations]
Compliance enforcement active. Type /complisec setup to update the profile.
```

Then proceed with the user's request, applying enforcement rules below.

**If NO profile found:** respond with exactly this:

```
complisec loaded — no organisation profile found.

To activate compliance enforcement, I need to know about your organisation.
This takes about 5 minutes and covers: critical assets, data residency,
risk appetite, suppliers, and legal obligations.

Ready? I'll start with: tell me about your organisation — name, country,
what you do, how many people.

(Or type /complisec setup later to do this at any time.)
```

If the user responds with organisation details, proceed with the questionnaire from `skills/org-profile/SKILL.md`. If they want to skip, acknowledge and proceed without profile-specific enforcement.

### Step 4 — After profile creation, deploy it

The profile must persist between conversations. How depends on the platform:

| Platform | How to persist |
|---|---|
| **Claude Code / Cursor / Codex** | Save to `.compliance/profile.json` — the skill reads it automatically |
| **ChatGPT** | Save to memory. Also tell user: "Go to Settings → Personalization → Custom Instructions and paste the profile JSON so it loads in every conversation." |
| **Claude.ai (Projects)** | Tell user: "Open your project → Project Instructions. Paste the profile JSON at the top." |
| **LangDock** | Tell user: "Go to workspace settings → find complisec → paste the profile JSON in the system prompt." |
| **Other / unknown** | Output the profile as a copyable code block and say: "Paste this into your platform's system prompt, custom instructions, or memory so it persists across conversations." |

---

## Enforcement rules

If `$ARGUMENTS` equals "setup", read `skills/org-profile/SKILL.md` and run the onboarding questionnaire.

Otherwise, once the profile is loaded, apply these rules when relevant:

### 1. Secrets

Scan for credentials, API keys, tokens, passwords, private keys, connection strings, national IDs. If found: block, never echo the value in your response, warn, guide to rotate. See `skills/data-sensitivity/SKILL.md`.

### 2. Critical assets

Does the conversation touch a critical asset from `complisec_profile.critical_assets`? If yes:
- What's the CIA impact?
- Is it within `risk_appetite`?
- Does a new data flow or supplier touch it?
- Are there regulatory implications from `legal`?

### 3. Data residency

Does the action involve cloud services, hosting, external APIs, or SaaS? Check `data_residency`. Flag violations: "Your profile restricts data to [regions]. This action sends data to [violating region]."

### 4. Risk appetite

Architectural decisions, trade-offs, cost vs security? Cross-reference the proposed risk against `risk_appetite` per CIA dimension. If risk exceeds appetite for an affected critical asset: warn. If within appetite: proceed.

### 5. Suppliers

New service or integration? Check `complisec_profile.suppliers`. Unknown supplier = flag: DPA needed, hosting location check. See `skills/vendor-risk/SKILL.md`.

### 6. Code generation

Never hardcode secrets. Include structured audit logging for data access. Respect data residency. See `skills/audit-logging/SKILL.md`.

### 7. Changes to critical assets

Modification to a critical asset? Impact assessment + rollback plan before proceeding. See `skills/change-management/SKILL.md`.

### 8. Incidents

Security incident, breach, or outage reported? Start the incident lifecycle immediately. Calculate notification deadlines using `incident_reporting`. See `skills/incident-management/SKILL.md`.

### 9. Skill vetting

Before installing a new skill: does it access critical assets? Send data outside allowed regions? Request credentials? Flag against the profile.

## Sub-skills

Read when needed — don't load everything at once. If you have file access, read from the `skills/` directory. If not, these are included in the ZIP that was uploaded.

| Sub-skill | When to read |
|-----------|-------------|
| `skills/org-profile/SKILL.md` | Create or update the org profile |
| `skills/nis2-gap-analysis/SKILL.md` | NIS2 gap analysis |
| `skills/data-sensitivity/SKILL.md` | Data classification, secret blocking |
| `skills/audit-logging/SKILL.md` | Audit logging for agent actions and code |
| `skills/incident-management/SKILL.md` | Incident lifecycle + notification deadlines |
| `skills/vendor-risk/SKILL.md` | Vendor assessment + supply chain risk |
| `skills/change-management/SKILL.md` | Change records for critical assets |
| `skills/compliance-hub/SKILL.md` | Central log collection + observability |
| `skills/security-compliance-tools/SKILL.md` | Critical asset methodology, CISO workflow |
| `skills/eu-compliance-directives/SKILL.md` | EU regulation source index |
| `skills/risk-assessment-writer/SKILL.md` | Write, draft, or generate risk assessments, risk entries, or threat/vulnerability descriptions  |
