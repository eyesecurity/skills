---
name: org-profile
argument-hint: "[setup]"
description: "ACTIVATE when the user wants to create or update their organisation's compliance profile, or invokes /org-profile setup. Runs a questionnaire to capture identity, critical assets, data residency, risk appetite, suppliers, and legal obligations — outputs a compact profile for enforcement."
---

# Organisation Profile Builder

> One questionnaire. One compact JSON. Every prompt knows your compliance context.

If `$ARGUMENTS` equals "setup", start the questionnaire immediately.

## Questionnaire

Work through these in order. One topic per message — don't dump everything at once.

### 1. Identity

Ask: "Tell me about your organisation — name, country, what you do, how many people."

Derive: name, jurisdiction, sector, employee count, turnover. Use `skills/nis2-gap-analysis/nis2_check.py --list-sectors` as sector reference.

### 2. Critical assets

Start from business impact, not IT systems.

Ask one by one:
- "Which systems or data would cause the most damage if compromised or unavailable for a day?"
- "Which supplier has the deepest access to your environment?"
- "Is there a key person whose departure would leave critical knowledge gaps?"

Per asset: name (short), type (sys/data/process/person), CIA rating [1-5, 1-5, 1-5], owner.

**3-7 assets max.** Crown jewels, not an inventory.

### 3. Data residency

Ask: "Are there constraints on where your data may be stored or processed?"

Capture as a compact string: regions + reason. Examples: "EU only (contractual)", "NL for defense work, EU for general (ABDO)", "no constraints".

### 4. Risk appetite

Ask per dimension — zero_tolerance, low, medium, or high:
- Confidentiality: "If data leaks — how bad?"
- Integrity: "If data gets silently corrupted — how bad?"
- Availability: "How long can critical systems be down?"

### 5. Suppliers (top 5)

Ask: "Name your 5 most important suppliers — the ones with access to your systems or data."

Per supplier: name, hosting region, DPA signed (y/n), critical (y/n).

### 6. Legal obligations

**Calculate — don't ask.** From sector + size + jurisdiction:
- NIS2: essential / important / out of scope
- GDPR: almost always yes
- Sector-specific: DORA (finance), ABDO (NL defense), etc.

Look up CSIRT and DPA from `skills/incident-management/references/eu-reporting-directory.md`.

---

## Output format

Generate this compressed JSON. Designed for ~25 lines — fits in any system prompt.

```json
{
  "complisec_profile": {
    "org": "Bakker Logistics BV | NL | transport/road | 85 emp | important NIS2 | ISO27001",
    "critical_assets": [
      ["Fleet management", "sys", [4,5,5], "CTO"],
      ["Client shipment DB", "data", [5,5,4], "Ops dir"],
      ["SAP Business One", "sys", [4,4,5], "Finance dir"],
      ["Warehouse access", "sys", [3,4,5], "Facility mgr"]
    ],
    "data_residency": "EU only",
    "risk_appetite": { "c": "zero_tolerance", "i": "low", "a": "medium" },
    "suppliers": [
      ["SAP", "EU", true, true],
      ["AWS", "EU", true, true],
      ["Salesforce", "EU", true, false]
    ],
    "incident_reporting": "NCSC-NL 24/72h | AP 72h",
    "legal": ["NIS2 important", "GDPR controller", "ISO27001"]
  }
}
```

### Format rules

- **`org`**: single string — all key facts, pipe-separated
- **`critical_assets`**: arrays `[name, type, [c,i,a], owner]` — positional, no keys. Keep names short (drop "platform", "system" suffixes). No notes column — the name + CIA scores are enough.
- **`data_residency`**: single string, just the region constraint
- **`risk_appetite`**: `c/i/a` shorthand
- **`suppliers`**: arrays `[name, hosting, dpa, critical]` — no data description needed
- **`incident_reporting`**: single string, compact: `NCSC-NL 24/72h | AP 72h`
- **`legal`**: string array
- **`complisec_profile`** root key — so the agent can find it in a system prompt

---

## Deploy the profile

After generating the JSON, persist it so it loads in future conversations. You know what platform you're running on — be specific, not generic.

| Platform | How to persist |
|---|---|
| **Claude Code / Cursor / Codex** | Save to `.compliance/profile.json` — done automatically |
| **ChatGPT** | Save to memory. Also tell user: "Go to Settings → Personalization → Custom Instructions and paste the profile JSON." |
| **Claude.ai (Projects)** | Tell user: "Open your project → Project Instructions. Paste the profile JSON at the top." |
| **LangDock** | Tell user: "Go to workspace settings → find complisec → paste the profile JSON in the system prompt." |
| **Other** | Output as copyable code block: "Paste this into your platform's system prompt, custom instructions, or memory." |

After deploying, respond with exactly:

```
Profile saved — [org name] ([jurisdiction])
Critical assets: [count] | Data residency: [constraint] | Legal: [regulations]
Compliance enforcement is now active.
```

Then suggest: "Run `/compliance-hub` to set up central log collection for compliance records."

End with: "Test it now — ask me to write code that uses a cloud service, or mention one of your critical assets. I should flag compliance implications."

---

## Agent instructions

1. Run the questionnaire in order. One topic per message.
2. Critical assets: push back if more than 7. Crown jewels only.
3. Legal obligations: calculate from sector/size, don't ask the user.
4. Incident reporting: look up CSIRT + DPA from the EU reporting directory.
5. Output the compact profile. Confirm with user before saving/deploying.
6. **Always end with:** (a) platform-specific deployment instructions, (b) central logging recommendation via `/compliance-hub`, (c) a verification prompt.
