---
name: risk-assessment-writer
description: >
  ACTIVATE when the user asks to write, create, draft, or generate a risk assessment,
  risk entry, risk evaluation, or threat/vulnerability description — or when the user
  describes a threat, vulnerability, weakness, new business activity, or scenario they
  want risk-assessed. Covers information security, compliance, operational, vendor, HR,
  physical, and quality risks within the ISO 27001 framework. Produces a structured
  risk entry with Risk Evaluation + Risk Treatment tables, L/M/H scoring, and guided
  likelihood/impact questions.
---

# Risk Assessment Writer

> Every new risk gets a structured assessment. No threat goes undocumented.

All output is written **entirely in English**.

## Storage

- **Naming**: `[YYYY]-[NN] [Short description]` (e.g. "2026-101 Insufficient patch management")

## Risk assessment record

Each risk page has two main sections: **Risk Evaluation** and **Risk Treatment**.

### Risk Evaluation

| Field | Description | Values |
|-------|-------------|--------|
| **Asset** | What is at risk | Descriptive phrase or single word (e.g. "Data", "Software", "Organization", "Services", "People", "Hubspot data", "HR payroll SaaS platform") |
| **Threat** | What could go wrong and why (see Threat Patterns below) | 1-4 sentences |
| **Category** | Which security/quality dimension | Confidentiality, Integrity, Availability, QUALITY (one or more) |
| **Likelihood** | How likely is this to happen | L (Low), M (Medium), H (High) |
| **Impact** | How bad if it happens | L, M, H |
| **Risk** | Derived from matrix (see below) | L, M, H |
| **Owner** | Who is accountable | Security Officer, CTO, Management, CISO office, DPO, Quality Manager, Marketing Lead, or a domain-specific role |
| **Status** | Treatment decision | ACCEPT (Green), REDUCE (Yellow), PREVENT (Red), TRANSFER |
| **Date of last review** | When last assessed | YYYY-MM-DD |
| **Countries** | Where this risk applies | Netherlands, Belgium, Germany, All |

### Risk Treatment

| Field | Description |
|-------|-------------|
| **Treatment option** | ACCEPT, REDUCE, PREVENT, or TRANSFER |
| **Measures** | Checklist: `[x]` = implemented, `[ ]` = planned. Can also be free text or "N/A" |
| **Residual risk** | Must be <= original Risk level |
| **Responsible** | Person/role accountable for the measures |

## Risk matrix (L/M/H)

|  | Impact L | Impact M | Impact H |
|--|----------|----------|----------|
| **Likelihood H** | M | H | H |
| **Likelihood M** | L | M | H |
| **Likelihood L** | L | L | M |

## GRC-Tool numeric scoring (1-3, use only when user requests it)

- **Likelihood**: 1 = Unlikely, 2 = Somewhat likely, 3 = Likely
- **Impact**: 1 = Low (<EUR 10k), 2 = Medium (EUR 10k-50k), 3 = High (>EUR 50k)
- **Risk score** = Likelihood x Impact: 1-2 Green/Low, 3-5 Yellow/Medium, 6-7 Red/High, 8-9 Purple/Critical

Default to L/M/H unless the user explicitly asks for numeric scoring.

## Risk appetite

The default financial thresholds for impact scoring are:
- **L**: Under EUR 10k
- **M**: EUR 10k-50k
- **H**: Over EUR 50k

These defaults may not fit every organization. When starting a new risk assessment (or the first time working with a user), ask:

> The default financial thresholds for impact are: L = under EUR 10k, M = EUR 10k-50k, H = over EUR 50k. Do these match your risk appetite, or would you like to adjust them?

If the user provides custom thresholds, use those consistently throughout the assessment and the impact questions. If the user confirms the defaults or wants to skip, proceed with the defaults.

## Risk lifecycle

### 1. Identify

When the user describes a new risk scenario, business activity, or threat:

- Determine the **Asset** at risk
- Propose the most fitting **Category** (Confidentiality, Integrity, Availability, QUALITY)
- Draft a **Threat** description using one of the three patterns below

### 2. Assess -- Guided Likelihood and Impact

When the user is unsure about Likelihood or Impact, walk them through these questions conversationally (not as a dry checklist). If the user already provides L/M/H values, skip this step.

#### Likelihood questions

| # | Question | H | M | L |
|---|----------|---|---|---|
| 1 | Has this type of incident happened before? | Multiple times in past 2 years | Once or twice | Never, here or at similar orgs |
| 2 | Are there existing controls in place? | No controls or very weak | Some controls with gaps | Strong, tested controls |
| 3 | How exposed is the asset or process? | Public / many users / internet-facing | Limited but shared across teams or vendors | Very restricted, isolated |
| 4 | How complex to materialize? | Simple, single mistake | Specific chain of events needed | Multiple simultaneous failures required |

**Scoring:** Majority H = H, majority L = L, otherwise M.

#### Impact questions

| # | Question | H | M | L |
|---|----------|---|---|---|
| 1 | Financial exposure? | Over EUR 50k | EUR 10k-50k | Under EUR 10k |
| 2 | Customer or service delivery impact? | Significant, broad customer disruption | Partial, some customers or services affected | No customer impact, internal only |
| 3 | Regulatory or legal consequences? | Fines, sanctions, lawsuits, or license revocation | Warning or minor regulatory finding | None |
| 4 | Reputational damage? | Media coverage or significant loss of customer trust | Internal or industry-level attention | None expected |
| 5 | Recovery time? | Weeks, months, or irreversible | Days to a week | Hours, quickly recoverable |

**Scoring:** Count H, M, and L answers. Majority H = H, majority L = L, otherwise M.

Note: The financial thresholds in Q1 follow the risk appetite defaults above. If the user has provided custom thresholds, substitute them here.

#### Presenting the recommendation

After evaluating, present:

> Based on your answers:
> - **Likelihood: [L/M/H]** -- [1-sentence reasoning]
> - **Impact: [L/M/H]** -- [1-sentence reasoning]
>
> This gives a **Risk level of [L/M/H]** per the risk matrix.
>
> Do you agree, or would you like to adjust?

### 3. Treat

Determine treatment together with the user:

| Option | When to use | Measure pattern |
|--------|-------------|-----------------|
| **REDUCE** | Risk is too high, controls can lower it | `[ ]` for planned, `[x]` for already implemented |
| **ACCEPT** | Risk is within appetite, or already reduced | `[x]` for all implemented, or "N/A" |
| **PREVENT** | Risk must be avoided entirely | Describe how the activity/exposure is eliminated |
| **TRANSFER** | Risk shifted to third party (insurance, contract) | Describe the transfer mechanism |

### 4. Document

Generate the full risk assessment in the standard two-table format (Risk Evaluation + Risk Treatment). Suggest a page title following the `[YYYY]-[NN] [Short description]` convention.

### 5. Review

- Risks should be reviewed at least annually
- High risks: review every 6 months
- When the business context changes (new country, new vendor, new regulation): re-assess

## Threat description patterns

**Pattern A -- Formal formula:**
```
As a result of [root cause 1] OR [root cause 2], there is a chance that [undesirable event], resulting in [business impact].
```

**Pattern B -- Narrative style:**
2-4 sentences describing the context, why the risk exists, and the potential consequence.

**Pattern C -- Short direct causal:**
```
Due to [cause], it is possible that [event]. This could lead to [impact].
```

### Root cause library

| Domain | Examples |
|--------|----------|
| Procedural | Lack of policies, insufficient authorization policies, absence of guidelines, incomplete processes, missing acceptance criteria |
| Technical | Insufficient monitoring, unsecured communication, lack of logging, poor change management, insufficient segmentation, missing patch management |
| Organizational | Insufficient segregation of duties, lack of knowledge, missing management involvement, poor vendor management, insufficient awareness training |
| Physical | Flammable materials, unsafe premises, shared offices, multiple locations, utility failure |
| Third-party | US-based vendor (data residency), vendor with environment access, lack of legal/technical separation, missing vendor logging |
| HR/People | Departing employees, dual roles, undesired behavior, language proficiency gaps, single point of failure |

### Impact library

| Domain | Examples |
|--------|----------|
| Confidentiality | Data accessible to unauthorized persons, unauthorized distribution, competitive position harmed, data leaked to third party |
| Integrity | Data processed incorrectly, no segregation of duties, unsafe code deployed |
| Availability | Business continuity at risk, long recovery times, services not delivered |
| Compliance | Sanctions, regulatory non-compliance, fines, privacy violations |
| Financial | Revenue loss, material damage, liability, claims |
| Reputation | Media attention, loss of customer trust |
| Quality | Service quality degraded, projects not delivering results |

## Measure library

| Category | Example measures |
|----------|-----------------|
| **Access control** | Access policies, user provisioning, access rights revocation, password management, secure login, SSO, IP allow listing, VPN, least privilege |
| **Information classification** | Classification guidelines, labeling, clear desk/screen policy, NDAs |
| **Physical security** | Perimeter security, access controls, equipment protection, secure areas, locked cabinets, electronic door locks |
| **Vendor management** | Third-party agreements, service delivery review, change management, exchange agreements, vendor register, ISO 27017 controls |
| **Logging and monitoring** | Audit logs, log protection, admin logs, retention policy, Slack notifications |
| **Development and change** | Security requirements, secure dev guidelines, change management, separation of environments, code reviews, security tests, vulnerability scans |
| **Personnel** | Management responsibility, awareness training, disciplinary process, offboarding, screening, confidential advisor, four-eyes principle |
| **Media and crypto** | Removable media management, secure disposal, cryptographic controls, off-premises equipment security |
| **Compliance** | Legal compliance, IP rights, document protection, personal data protection, internal audits |
| **Incident management** | Response procedures, reporting channels, evidence collection, lessons learned |
| **Business continuity** | BC measures, cloud storage, failover, backup procedures |
| **Operational** | Own network equipment, one-way connections, SaaS intermediary, spot checks |

## Agent instructions

1. **Always write in English.** All field labels, values, descriptions, and measures in English.
2. Start by understanding what the risk is about. If the user gives enough context, propose the full assessment directly. If not, ask only the questions needed.
3. For Likelihood and Impact: if the user provides values, accept them. If unsure, use the guided assessment questions above.
4. Propose a threat description using the most fitting pattern (A, B, or C). Let the user confirm or adjust.
5. Suggest the most relevant measures from the measure library, tailored to the specific scenario. Avoid generic control references.
6. The default Owner is "Security Officer" unless the risk clearly belongs to another domain.
7. QUALITY category is for quality/service delivery risks not strictly covered by CIA.
8. The Asset field can be a single word or a full descriptive phrase.
9. Multiple OR clauses are allowed in formal threat descriptions (Pattern A).
10. Residual risk must be <= the original risk level.
11. When status is REDUCE, use `[ ]` for planned measures and `[x]` for already implemented ones.
12. When status is ACCEPT (from the start), measures can be "N/A".
13. Historical sections (showing previous evaluations) are only needed when updating an existing risk, not for new ones.
14. Suggest a page title in the `[YYYY]-[NN] [Short description]` format.
15. On first use, confirm risk appetite thresholds with the user before applying them to impact scoring.
