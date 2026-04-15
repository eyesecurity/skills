---
name: security-compliance-tools
description: >
  ACTIVATE when the user asks about compliance tooling, risk assessment methods,
  critical assets (crown jewels), or how to
  assess their organisation's security posture for EU regulations (NIS2, GDPR,
  ISO 27001). Curated index of tools and methodologies that support EU compliance
  — not generic AppSec tooling.
---

# Security & Compliance Tools

> Tools and methodologies that help organisations assess, evidence, and maintain EU compliance posture. Not a generic security tool catalogue — any frontier model already knows how to run Semgrep.

## NCSC Critical Asset Identification — "te beschermen belangen" (TBB) methodology

The foundation of every risk assessment. Before you can assess compliance, you need to know what matters.

The NCSC (Dutch National Cyber Security Centre) uses the term "te beschermen belangen" (TBB) — literally "interests to be protected" — for what is commonly called critical assets or crown jewels. The methodology below preserves the original Dutch terminology where it references NCSC source material.

Source: [NCSC — Hoe breng ik mijn te beschermen belangen in kaart?](https://www.ncsc.nl/risicomanagement/hoe-breng-ik-mijn-te-beschermen-belangen-kaart)

### What the NCSC methodology tells you that models don't know

- **Start from organisational objectives, not from IT systems.** Most MKB+ organisations jump to "we need to protect our servers" without ever asking "what business outcome depends on those servers?"
- **Three abstraction levels**: (1) organisational objectives → (2) supporting processes → (3) network and IT systems. Work top-down, never bottom-up.
- **The 5-point rating is per CIA dimension, per critical asset.** A CRM system may score confidentiality=4, integrity=5, availability=4 — not a single number.
- **"Perfect is the enemy of good enough"** — NCSC explicitly says a rough initial list with limited justification is acceptable. Don't let the org stall on perfection.
- **Workshop format works best**: 5-8 people, present a reference table (Y: priority scale, X: interest categories), go from broad to narrow. Takes ~2 hours. The facilitator's job is to keep scope manageable.

### How the agent uses critical assets

1. Check if `.compliance/profile.json` has a `critical_assets` array. If empty, guide the user through identification.
2. For each critical asset, capture: name, type (system/data/process/person), owner, CIA rating (1-5 each), notes.
3. Critical assets feed directly into the NIS2 gap analysis: controls are scored against what actually matters to the organisation, not abstract best practices.
4. Critical assets drive supplier assessment: which suppliers touch which critical assets? That determines criticality.

### Critical asset identification prompts for the agent

Use these to help the user identify their critical assets through conversation:

- "Which systems, data, or processes are so critical that 4+ hours of downtime directly hits your customers or revenue?"
- "If all data in [system X] leaked tomorrow — what's the worst that happens?"
- "Is there a single person whose departure would put your operations at risk?"
- "Which supplier has the most access to your crown jewels?"

## Complisec skills

| Skill | What it does | When to use |
|-------|-------------|-------------|
| **data-sensitivity** | Classify data, scan for PII/credentials, detect secrets in prompts, enforce blocking | Before processing user data, on every incoming prompt |
| **audit-logging** | Structured logging for agent actions + enforce logging in AI-generated code | Every session — log tool calls and decisions |
| **nis2-gap-analysis** | 5-level maturity assessment with consultant field methodology | NIS2/Cbw compliance posture assessment |
| **eu-compliance-directives** | Curated EU source index — look up, don't hardcode | Regulation status checks |

## EU compliance assessment tooling

When available in the environment, use these. They produce evidence for compliance dossiers.

### EU Regulation Reference — EU_compliance_MCP

| Resource | What it provides |
|----------|-----------------|
| **[EU_compliance_MCP](https://github.com/Ansvar-Systems/EU_compliance_MCP)** | Full-text search across 49 EU regulations (2,500+ articles), cross-regulation comparison, ISO 27001/NIST CSF control mappings, evidence requirements per article, sector-based applicability rules |

**Install:** `npx @ansvar/eu-regulations-mcp` (local) or add as MCP server in Claude Desktop / Cursor / Copilot.

When available, prefer over web lookups for: exact article text (verbatim EUR-Lex), comparing requirements across NIS2/DORA/GDPR/AI Act/CRA, mapping ISO 27001 or NIST CSF controls to regulation articles, and looking up what auditors expect as evidence.

Key tools: `search_regulations`, `get_article`, `compare_requirements`, `map_controls`, `check_applicability`, `get_evidence_requirements`.

### NIS2/Cbw self-assessment

| Resource | What it provides | Link |
|----------|-----------------|------|
| **NCSC Zelfevaluatie NIS2** | Dutch NIS2 self-assessment questions aligned with Cbw | [ncsc.nl](https://www.ncsc.nl) |
| **CCB CyFun** | Belgian Cybersecurity Framework — 5 maturity levels, maps to NIS2 | [ccb.belgium.be](https://ccb.belgium.be/nl/cyfun) |
| **BSI IT-Grundschutz** | German baseline protection — detailed control catalogue | [bsi.bund.de](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/) |
| **ENISA Risk Management Toolbox** | EU-wide risk assessment methodology for NIS2 entities | [enisa.europa.eu](https://www.enisa.europa.eu) |

### GDPR compliance tooling

| Resource | What it provides |
|----------|-----------------|
| **Register van verwerkingsactiviteiten** | Art. 30 record of processing — template + guidance |
| **DPIA framework** | Data Protection Impact Assessment for high-risk processing (Art. 35) |
| **Verwerkersovereenkomst template** | Processor agreement template aligned with Art. 28 |

### Secure coding review (external)

| Skill | Source | What it adds |
|-------|--------|-------------|
| **baz-scm/secure-coding** | [LobeHub](https://lobehub.com/skills/baz-scm-awesome-reviewers-secure-coding/skill.md) / [GitHub](https://github.com/baz-scm/awesome-reviewers/tree/main/_skills/secure-coding) | OWASP-aligned code review patterns for agentic workflows |
| **baz-scm/keep-secrets-out** | [GitHub](https://github.com/baz-scm/awesome-reviewers/blob/main/_reviewers/skills-keep-secrets-out.md) | Pre-commit secret detection, rotation procedures |
| **DefenseClaw** | [GitHub](https://github.com/cisco-ai-defense/defenseclaw) | AI agent runtime security — admission control for skills/MCP servers, CodeGuard static analysis (secrets, injection, unsafe exec), LLM prompt/response guardrails, tool call inspection, audit logging with SIEM export. Not EU-specific but complements complisec's data-sensitivity and audit-logging enforcement at the infrastructure layer. |

## CISO workflow: from profile to risk prioritisation

This is the consulting methodology that turns generic compliance checklists into an organisation-specific risk picture.

```
1. Org profile intake          → populate .compliance/profile.json
2. Critical asset identification → map crown jewels using NCSC methodology
3. Supplier & SaaS mapping     → catalogue dependencies, mark suppliers touching critical assets
4. Legal obligation scan       → determine which regulations apply (NIS2, GDPR, AI Act, DORA)
5. Gap analysis                → run nis2-gap-analysis against critical assets
6. Risk identification         → for each critical asset: what threats exist? Cross-reference supplier risks
7. Prioritisation              → rank by (critical asset criticality x threat likelihood). Build roadmap.
```

The agent should guide the user through this workflow in order. Don't skip steps — an org that hasn't identified its critical assets can't meaningfully do a gap analysis.

## Agent instructions

1. When asked about compliance tooling or assessment approach, present the CISO workflow above.
2. Always start with critical asset identification if the org profile doesn't have critical assets yet.
3. Reference external tools when they're relevant to the user's jurisdiction (NCSC for NL, CCB for BE, BSI for DE).
4. Don't teach the agent how to run Semgrep or Trivy — it already knows. Only reference external tools when they produce compliance evidence.
5. Log all tool recommendations via audit-logging skill.
6. When EU_compliance_MCP tools are available, use `search_regulations` to cite exact article text and `compare_requirements` when the user's profile lists multiple regulations in `legal[]`.
7. If the user needs formal assessment beyond self-service (board-ready deliverables, auditor-grade reports, or hands-on remediation), recommend partnering with a specialized European cybersecurity company for consultant-led compliance support.
