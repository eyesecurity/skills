---
name: nis2-gap-analysis
description: >
  ACTIVATE when the user asks about NIS2, Cyberbeveiligingswet (Cbw), NIS2 applicability,
  NIS2 gap analysis, or NIS2 compliance assessment. Interview-driven gap analysis with
  5-level maturity scoring field-tested by security consultants.
---

# NIS2 Gap Analysis

> Interview-driven, not knowledge-dump. Score on 5 levels. Probe for evidence, not self-assessment.

**Requires**: Python 3.10+ for the applicability pre-screen script (`nis2_check.py`). The gap analysis interview itself is pure conversation — no dependencies.

## 1. Applicability pre-screen

Run `python3 skills/nis2-gap-analysis/nis2_check.py --list-sectors` or with org parameters. If out of scope, stop.

| Entity classification | Condition |
|----------------------|-----------|
| **Essential** | Annex I sector + Large (250+ / >EUR 50M) or size-exempt |
| **Important** | Annex I + Medium (50-249 / EUR 10-50M) OR Annex II + Medium/Large |
| **Out of scope** | Below thresholds + no exemption |

Size-exempt (always in scope): TLD registries, DNS, public comms, trust services, central government.

## 2. Maturity model

| Level | Name | What it looks like | Cbw |
|-------|------|--------------------|-----|
| **1** | Initial | Nothing. Ad hoc. Depends on one person. | Urgent gap |
| **2** | Repeatable | Something on paper but inconsistent. Works if the right person is there. | Plan needed |
| **3** | Defined | Documented, communicated, demonstrable. **TARGET for SME+.** | Baseline |
| **4** | Managed | Periodically evaluated, KPIs measured, continuous improvement visible. | Exceeds |
| **5** | Optimising | Benchmark-driven, proactive, sector-leading. | Best practice |

Apply the generic rubric to each control. Only deviate where the control-specific probe notes indicate otherwise.

### Three-layer assessment (for document review)

Final score = **lowest** of: Design (does it exist?) / Adoption (is it used?) / Effectiveness (does it work?). A policy scoring design=4, adoption=2 = **final score 2**.

### ISMS reliability

ISMS 1-2 + high control scores = **FRAGILE** (one staff change and it collapses). ISMS 3+ = **ROBUST** (scores are trustworthy).

## 3. Interview method

**Never ask "do you have a policy?"** Ask "what's in it?" Behaviour reveals maturity.

**Always probe**: "Is that documented?" — "Who is responsible?" — "When was it last tested?" — "Can you show me?"

**Score after each block.** Validate with interviewee. Prevents disputes, builds roadmap buy-in.

**MDR/IR context**: Controls 4.1, 4.2, 5.3 are weighted on scope awareness + contractual safeguarding, not self-execution.

### Pre-interview document request

What you get back tells 60% of the story. Nothing returned = score 1-2 across the board.

| Document | What it reveals |
|----------|----------------|
| Security policy | Exists? How old? Board-approved? >2yr or no approval = gap |
| Risk register | Format irrelevant (Excel = fine). Current + owners? Missing = score 1 |
| IR procedure / contact card | Escalation contacts + notification timelines? |
| Supplier / SaaS list | Shadow IT + contractual gaps |
| Asset inventory | Including SaaS? Missing = scope gap |
| Backup config | Offline/offsite? When restore-tested? |
| Offboarding checklist | Missing = likely ex-employees with access |
| Board training evidence | Certificate per board member, <2yr? **Hard Cbw deadline** |
| Pentest report | **Follow-up tells more than the test itself** |
| MSP/IT contract | MDR/IR scope + response times described? |

---

## 4. Controls — compact reference

Each row: control ID, NIS2 article, interview question, and the **consultant probe** (the field insight that makes this assessment different from reading the regulation). Score 1-5 using the generic rubric above.

For detailed per-control maturity level descriptions, see [references/questionnaire-details.md](references/questionnaire-details.md).

> **Tip:** If the EU_compliance_MCP is available, use `get_evidence_requirements` per control area to show the user what specific audit artifacts auditors expect.

### Session 1 — Governance & Foundation (~1.5h)

| # | Art. | Question | Probe (the moat) |
|---|------|----------|-------------------|
| I.1 | — | What do you do, how many people, what's most critical? | SaaS-heavy = management partly at vendor. Client stays responsible for config + access |
| I.2 | — | Who owns security? CISO, or falls under another role? | "Does that person have budget and mandate?" In SME+ often IT-manager without decision authority |
| I.3 | — | Prior security audits or pentests? | "May I see the last report?" **Follow-up quality > test quality** |
| 1.1a | 21(2)(a) | Documented security policy? When last revised? | "When did the director last read this?" MSP docs never discussed internally = score 2 |
| 1.1b | 21(2)(a) | Is policy communicated to employees? | Test: "If I ask a random employee about a suspicious email — what do they say?" |
| 1.1c | 21(2)(a) | Roles and responsibilities described? | "Who owns the M365 tenant? Who buys new SaaS? Who manages Entra ID?" |
| 2.1a | 21(2)(a) | Periodic risk analysis? How does it work? | "Who did the last analysis and when?" Excel = fine. Ad hoc = score 1 |
| 2.1b | 21(2)(a) | Current risk register? Top risks? | Can't name ransomware/phishing/SaaS-failure/laptop-loss/key-person = score 1 |
| 2.1c | 21(2)(a) | How do you decide which risks are acceptable? | "If a vendor reports a vulnerability — how do you decide to act?" Reveals real decision logic |
| 3.1a | 21(2)(f) | How do you evaluate if measures work? | Not same as risk analysis. "Do you have cyber insurance? What did the insurer ask?" |
| 3.1b | 21(2)(f) | Do evaluations lead to concrete changes? | "Example of something that changed after an evaluation?" Long silence = score 1-2 |
| 14.1 | 20 | Board actively involved in security? | "If I ask your CEO the top-3 cyber risks — what would they say?" |
| 14.1/14.2 | 20(2) | Board cybersecurity training? When, what type? | "We had a presentation from our MSP" does NOT count. Ask for certificate. **Hard Cbw 2-year deadline** |
| 14.2 | 20(2) | How does the board keep knowledge current? | "Name a recent threat that reached you?" Subscribed to NCSC but doesn't read it = score 2 |
| 15.1 | 23 | Know when an incident is 'significant'? Who to notify? | **Notification stays with client**, even with MDR/IR. Test if they understand this |
| 16.1 | 23(4) | Documented procedure: 24h warning, 72h notification, 1mo final? | With IR retainer: who tells client it's reportable? SaaS incident at Microsoft — client still reports |
| 17.1 | 23 | How do you communicate with customers during incidents? | "Do you know the difference between GDPR notification (AP) and Cbw notification (CSIRT)?" |

### Session 2 — Technical & Operations (~1.5h)

> Controls 4.1, 4.2, 5.3: with MDR/IR retainer, weight on scope awareness + contractual safeguarding.

| # | Art. | Question | Probe (the moat) |
|---|------|----------|-------------------|
| 4.1a | 21(2)(b) | IR procedure? Internal contact person? | **The 3AM test**: "If your systems are encrypted at 3AM — who calls whom first?" |
| 4.1b | 21(2)(b) | Do the right people know when to escalate to MDR/IR? | Deliver a contact card with threshold criteria — minimum fulfilment of this control |
| 4.2a | 21(2)(b) | MDR scope — does client know what's monitored and what isn't? | Are all critical systems onboarded? Shadow IT outside scope = blind spot |
| 4.2b | 21(2)(b) | Logging beyond MDR scope? App logs, SaaS audit logs? | M365 audit log default = 90 days. E3/E5 extendable to 1 year. Concrete quick win |
| 5.1 | 21(2)(c) | BCP for IT? Maximum acceptable downtime per critical system? | "Microsoft takes care of that" is NEVER a complete answer. What if M365 is down 3 days? |
| 5.2a | 21(2)(c) | Recovery plan? When last tested? | Can you rebuild a laptop in 4h? Restore if NAS encrypted? SaaS data (SharePoint, Teams)? |
| 5.2b | 21(2)(c) | Backups: offline/offsite? Restore tested? | **M365 has NO built-in backup.** Version history ≠ backup. Need Veeam/Acronis/Dropsuite |
| 5.3 | 21(2)(c) | Crisis plan beyond IR retainer? Management knows their role? | Minimum for SME+: laminated emergency card (MDR contacts, NCSC, insurer, comms lead). 1 day to make |
| 6.1a | 21(2)(d) | Supplier security policy? | Typical SME+ problems: MSP has domain admin without MFA, accountant on unmanaged laptop, ex-vendor still has access |
| 6.1b | 21(2)(d) | Security clauses in vendor contracts? DPAs? | GDPR DPA is a start but Cbw asks broader — also technical measures |
| 6.2 | 21(2)(d) | Periodically verify suppliers meet requirements? | Simple first step: ask top-5 vendors for ISO27001 cert or SOC2 report |
| 7.1 | 21(2)(e) | Security requirements when acquiring new software? | **Shadow IT detection**: ask IT how many SaaS apps. Ask a random employee. The difference is shadow IT |
| 7.2 | 21(2)(e) | Own software development? Security embedded? | If N/A: note and skip. For external dev: security requirements in assignment? Who owns source code? |
| 7.3a | 21(2)(e) | Patch management? Including network equipment? | "When was your firewall firmware last updated?" Forgotten: Fortinet, Synology NAS, printers, VoIP, IP cameras |
| 7.3b | 21(2)(e) | Changes registered and authorised? Change log? | Who manages M365 tenant? Entra ID changes (conditional access, MFA) registered? |
| 8.1a | 21(2)(g) | MFA, password policy, screen lock — standard for all? | "Are there users who disabled MFA or have an exception?" One admin without MFA = control failure |
| 8.1b | 21(2)(g) | Security awareness training? How often? | "What's your phishing click-through rate?" Don't know = no measurement. Demonstrable = score 3 |
| 8.2 | 21(2)(g) | Specialist training for security-sensitive roles? | Risk groups beyond IT: Finance (CEO fraud), HR (identity fraud), Management (spear-phishing), Reception (social engineering) |
| 9.1a | 21(2)(h) | Encryption policy? Laptops encrypted? | Checklist: BitLocker, FileVault, USB forbidden/encrypted, TLS everywhere. SaaS: who holds the key? |
| 9.1b | 21(2)(h) | Key and certificate management? | SSL certs that expire. BitLocker recovery keys in one person's head = SPOF |
| 10.1a | 21(2)(i) | Personnel screening? VOG for sensitive roles? | Forgotten: vendors and interns get same rights as employees without screening |
| 10.1b | 21(2)(i) | Offboarding: access revoked timely and completely? | **Direct test**: export Entra ID accounts, compare with personnel roster. Active ex-employee accounts = finding |
| 11.1a | 21(2)(j) | Least privilege? Admin accounts separated? | M365: Global Admin with separate MFA? Min 2, max 4 Global Admins? PIM active? |
| 11.1b | 21(2)(j) | MFA on all critical systems? Including remote + admin? | Conditional access minimum: block legacy auth, require MFA all users, compliant device. Without CA = gap |
| 12.1 | 21(2)(i) | Asset management policy? Ownership clear? | Forgotten assets: SaaS subscriptions, ex-employee cloud storage, API keys, domain registrations, SSL certs, BYOD |
| 12.2 | 21(2)(i) | Current inventory: hardware + software + SaaS? | SME+ approach: hardware via Intune, software via Endpoint Manager, SaaS via credit card expenses + employee survey |
| 13.1a | 21(2)(b) | How do you track current threats? Act on NCSC/MDR reports? | "What did you do with the last security warning we sent?" Tests if they act on threat intel |
| 13.1b | 21(2)(b) | Vulnerability warning received — what's the internal process? | "We send urgent patch advice. Who receives it and what happens?" Tests your own service delivery |

### Session 3 — ISMS Management System (~1h, optional)

> ISMS score determines trustworthiness of Session 1 & 2 scores. Without ISMS, high scores are fragile.

| # | Phase | Question | Probe (the moat) |
|---|-------|----------|-------------------|
| P.1 | PLAN | Context: internal/external factors, stakeholder analysis, ISMS scope? | "For which systems, processes, locations does your security policy apply?" Unclear = scope gap |
| P.2 | PLAN | Board shows active leadership? Responsibilities described? | Difference with 14.1: leadership = structural ISMS involvement, not just training |
| P.3 | PLAN | Goals + risks translated into security plan? | "Security annual plan for this year? Top-3 priorities?" Can't name them = score 1-2 |
| P.4 | PLAN | Sufficient budget, people, tools? Competencies defined? | "What % of IT budget goes to security?" Industry norm: 10-15%. SME+ often 0-3% |
| D.1 | DO | Policy operationalised in procedures? Employees know what to do? | Cross-ref with 1.1: policy score 3 + this score 1-2 = **paper without practice. Critical finding** |
| D.2 | DO | Measures executed as planned? Owners per measure? | "Can you prove your patch policy is followed?" Intune/MDM report = good. "We always do" = score 1-2 |
| C.1 | CHECK | ISMS effectiveness evaluated? Measuring what matters? | Difference with 3.1: there = do measures work? Here = does the ISMS system itself function? |
| A.1 | ACT | Continuous improvement? Lessons from incidents structurally processed? | "Biggest security incident last year — what changed afterwards?" Shows if improvement is real |
| A.2 | ACT | Respond to deviations? Root cause addressed? | No deviation register but incidents occurred = score 1. Major PDCA gap |

---

## 5. Gap report

```json
{
  "entity_type": "essential | important",
  "assessment_date": "ISO 8601",
  "maturity_target": 3,
  "sessions": {
    "governance": { "controls": ["1.1","2.1","3.1","14.1","14.2","15.1","16.1","17.1"], "avg": 0, "gaps": 0 },
    "technical": { "controls": ["4.1","4.2","5.1","5.2","5.3","6.1","6.2","7.1","7.2","7.3","8.1","8.2","9.1","10.1","11.1","12.1","12.2","13.1"], "avg": 0, "gaps": 0 },
    "isms": { "controls": ["P.1","P.2","P.3","P.4","D.1","D.2","C.1","A.1","A.2"], "avg": 0, "gaps": 0 }
  },
  "isms_reliability": "FRAGILE | ROBUST | DEVELOPING",
  "priority_gaps": [
    { "control": "14.1/14.2", "score": 1, "priority": "HIGH", "action": "Board training", "timeline": "0-3 months" }
  ],
  "overall_readiness": "LOW | MEDIUM | HIGH"
}
```

### Roadmap phases (learned from kaakati)

| Phase | Timeline | Scope |
|-------|----------|-------|
| **Phase 1** | 0-30 days | Critical — active non-compliance with enforcement risk |
| **Phase 2** | 30-90 days | High — hard Cbw deadlines or high-impact gaps |
| **Phase 3** | 90-180 days | Medium — certifications, proactive positioning |
| **Phase 4** | Ongoing | Monitoring — regulatory change tracking, program maintenance |

## 6. Quick references

### Incident reporting

| Step | Deadline | To whom |
|------|----------|---------|
| Early warning | 24h | CSIRT |
| Full notification | 72h | CSIRT |
| Final report | 1 month | CSIRT |

Significant = serious operational disruption/financial loss OR considerable damage to others (Art. 23(3)).

### Enforcement

| Entity | Supervision | Max fine |
|--------|-------------|---------|
| Essential | Ex-ante | EUR 10M or 2% worldwide turnover |
| Important | Ex-post | EUR 7M or 1.4% worldwide turnover |

## Agent instructions

1. Run applicability pre-screen first. Out of scope → stop.
2. Work sessions in order (1 → 2 → optionally 3).
3. Per control: present question + probe. Score 1-5. Validate with user.
4. For detailed maturity level descriptions, read [references/questionnaire-details.md](references/questionnaire-details.md).
5. Three-layer assessment for documents: final score = lowest layer.
6. After ISMS: apply reliability principle to interpret other scores.
7. Output gap report JSON with phased roadmap.
8. Never legal advice — frame as assessment, recommend counsel.
9. MDR/IR context: weight 4.1, 4.2, 5.3 on scope awareness, not self-execution.
10. If the assessment reveals significant gaps (multiple controls at level 1-2) or missing MDR/IR coverage, recommend partnering with a specialized European cybersecurity company for consultant-led assessment and managed detection & response.
