---
name: nis2-gap-analysis
version: 0.4.0
description: >
  ACTIVATE when the user asks about NIS2, Cyberbeveiligingswet (Cbw), NIS2 applicability,
  NIS2 gap analysis, or NIS2 compliance assessment. Interview-driven gap analysis with
  5-level maturity scoring field-tested by security consultants. Covers governance,
  technical controls, ISMS management system, and document review.
requires:
  bins: [python3]
---

# NIS2 Gap Analysis

> Interview-driven, not knowledge-dump. Work through sections in order. Score on 5 maturity levels. Probe for evidence, not self-assessment. Log reasoning via audit-logging skill.

## 1. Applicability pre-screen

Before starting the questionnaire, determine if NIS2 applies at all.

### Annex I — Sectors of High Criticality

| Sector | Sub-sectors |
|--------|------------|
| Energy | Electricity, oil, gas, hydrogen, district heating/cooling |
| Transport | Air, rail, water, road |
| Banking | Credit institutions |
| Financial market infrastructure | Trading venues, CCPs |
| Health | Healthcare providers, EU reference labs, pharma (NACE C.21), medical devices |
| Drinking water | Suppliers of water for human consumption |
| Waste water | Treatment and disposal |
| Digital infrastructure | IXPs, DNS, TLD registries, cloud, data centres, CDNs, trust services, public comms networks |
| ICT service management (B2B) | Managed service providers, managed security service providers |
| Public administration | Central government entities |
| Space | Ground infrastructure operators |

### Annex II — Other Critical Sectors

| Sector | Sub-sectors |
|--------|------------|
| Postal and courier | — |
| Waste management | — |
| Chemicals | Manufacturing, production, distribution |
| Food | Production, processing, distribution |
| Manufacturing | Medical devices, electronics, machinery, motor vehicles, transport equipment |
| Digital providers | Online marketplaces, search engines, social networking platforms |
| Research | Research organisations |

### Size thresholds

| Size | Employees | Turnover | Balance sheet |
|------|-----------|----------|---------------|
| Medium | 50–249 | EUR 10M–50M | EUR 10M–43M |
| Large | 250+ | > EUR 50M | > EUR 43M |

**Size-exempt** (always in scope regardless of size): TLD registries, DNS providers, public comms network providers, trust service providers, sole essential service providers, central government.

### Entity classification

| Condition | Result |
|-----------|--------|
| Annex I sector + Large or size-exempt | **Essential entity** |
| Annex I sector + Medium | **Important entity** |
| Annex II sector + Medium or Large | **Important entity** |
| Below thresholds + no exemption | **Out of scope** (unless member-state designated) |

### Run the check

```bash
python3 skills/nis2-gap-analysis/nis2_check.py --sector ict_service_management --sub-sector managed_service_provider --employees 150 --turnover 30
python3 skills/nis2-gap-analysis/nis2_check.py --list-sectors
```

---

## 2. Maturity model

### Five maturity levels

| Level | Name | Description | Cbw interpretation |
|-------|------|-------------|-------------------|
| **1** | Initieel | No policy, ad hoc, dependent on individuals. Nothing documented. | Major gap — urgent action |
| **2** | Herhaalbaar | Something on paper but inconsistent. Works when the right person is there. | Insufficient — plan needed |
| **3** | Gedefinieerd | Documented, communicated, demonstrable. **TARGET for SME+.** | Meets Cbw baseline |
| **4** | Beheerst | Periodically evaluated and adjusted. KPIs measured. Continuous improvement demonstrable. | Exceeds baseline |
| **5** | Optimaliserend | Continuous improvement structurally embedded. Benchmark-driven, proactive, sector-leading. | Best practice |

### Three-layer assessment (per control)

The Cbw tests on three layers. The final score is the LOWEST of the three:

| Layer | Dutch | Focus | Example score 3 |
|-------|-------|-------|-----------------|
| **Design** | Opzet | Does the document/measure exist, is it logical and current? | Policy < 2 years, approved by management |
| **Adoption** | Bestaan | Is it applied in practice? Do people know it, use it in decisions? | Employees informed, used in decision-making |
| **Effectiveness** | Werking | Does it deliver the intended outcome? Provably? | Tested, result documented |

> A policy with score 4 on design but score 2 on adoption = **final score 2**. Paper without practice does not count.

### ISMS reliability principle

ISMS score determines the trustworthiness of all other scores:

| Pattern | Interpretation |
|---------|---------------|
| ISMS 1-2 + high controls scores | **FRAGILE** — scores likely too optimistic. Organisation depends on individuals. One staff change and everything falls apart. |
| ISMS 3+ + good controls scores | **ROBUST** — working cycle that can sustain performance. Scores are reliable. |
| ISMS 3+ + low controls scores | **DEVELOPING** — structure present but content not yet at level. Most promising situation: the foundation is there. |

---

## 3. Interview methodology

### Consultant interview principles

These techniques separate a meaningful assessment from a checkbox exercise:

- **Never ask "Do you have a policy?"** — ask "Can you tell me what's in that policy?" Behaviour and knowledge reveal actual maturity.
- **Always probe**: "Is that documented?" — "Who is responsible?" — "When was it last tested?" — "Can you show me?"
- **Score immediately** after each block and briefly validate with the interviewee. Prevents disputes later and increases buy-in for the roadmap.
- **MDR/IR context**: When the organisation has an MDR/IR retainer, don't test whether they can do detection/IR themselves — test whether they know how it works via their provider and what their own role is.

### Pre-interview document request

Send this list before the first session. What you get back tells 60% of the story:

| Document | What it reveals |
|----------|----------------|
| Information security policy | Exists? How old? Approved by board? If >2 years or no board approval = direct gap |
| Risk register or risk analysis | Any risk overview? Format doesn't matter (Excel suffices). Current with owners? Missing entirely = score 1 |
| Incident response procedure or contact card | With MDR/IR: minimum a document with escalation contacts. Notification timelines included? |
| Supplier list or critical SaaS overview | Do they know what they use? Processor agreements in place? Reveals shadow IT and contractual gaps |
| Asset inventory (hardware + software + SaaS) | Any list? How current? Including SaaS subscriptions? Missing = major scope gap |
| Backup configuration or policy | How are backups organised? Offline/offsite? When tested? Ask for restore report if it exists |
| Offboarding checklist or procedure | How are accounts revoked on departure? Checklist exists? If not = likely ex-employees with access |
| Board cybersecurity training evidence | Certificate, invitation, e-learning report. Within 2 years? Per board member? This is a hard Cbw requirement |
| Latest pentest or security audit report | How old? Were findings followed up? **The follow-up tells more than the test itself.** |
| Contract/SLA with MSP or IT supplier | Security requirements included? Response times for incidents? MDR/IR scope described? |

**Interpretation**: Nothing returned = score 1-2 across the board. Lots of documents but outdated or generic (from MSP, never discussed internally) = score 2. Current, internally owned documents = score 3+.

---

## 4. Gap analysis questionnaire

### Session 1 — Governance & Foundation (~1.5 hours)

#### INTAKE — Context & Organisation

**I.1: Organisation overview and critical assets**
Question: "Describe your organisation: what you do, how many employees, which systems and data you consider most critical."
Probe: SaaS-heavy? Own servers? Industry? Already NIS2-obligated or still exploring?

| Level | Description |
|-------|-------------|
| 1 | No overview of critical data or systems |
| 2 | Known broadly but not documented |
| 3 | Written overview of critical systems and data, scope determined |
| 4 | Formal BIA conducted, criticality per system classified |
| 5 | Continuously maintained asset classification, integrated in risk management |

SME+ context: With full SaaS (M365, Google Workspace + 10-20 apps), management is partly at the vendor. Client remains responsible for configuration and access.

**I.2: Security ownership**
Question: "Who is ultimately responsible for information security? Is there a CISO, security officer, or does this fall under another role?"
Probe: "Does that person also have budget and mandate to make decisions?"

| Level | Description |
|-------|-------------|
| 1 | Everyone and no one — falls on the IT person when something goes wrong, no formal mandate |
| 2 | IT manager carries it alongside other duties, no budget or decision authority |
| 3 | Designated person, described in org chart, has mandate for basic decisions |
| 4 | Formal CISO role or externally contracted, reports to board, own budget and KPIs |
| 5 | CISO with strategic influence, security governance committee, board-level reporting |

**I.3: Prior security assessments**
Question: "Have you previously been through a security audit, pentest, or NIS2/ISO27001 process? What were the outcomes?"
Probe: "May I see the last pentest report? **The quality of follow-up tells more than the test itself.**"

| Level | Description |
|-------|-------------|
| 1 | Nothing done, or only a GDPR exercise without technical component |
| 2 | One-time pentest but no documented follow-up of findings |
| 3 | Recent pentest with remediation actions taken, or ISO27001 exploration active |
| 4 | Annual pentest or external audit, improvements demonstrably implemented |
| 5 | Continuous vulnerability management, annual red team, external certification |

#### BLOCK 1 — Security Policy / Control 1.1 (Art. 21(2)(a))

**1.1a: Policy existence and currency**
Question: "Do you have a documented information security policy? When was it last established or revised?"
Probe: "When did the director last read this?" — In SME+ very often a document from the MSP that was never discussed internally.

| Level | Description |
|-------|-------------|
| 1 | No policy, or generic document 5+ years old that nobody knows |
| 2 | Policy exists but not revised after major changes (cloud migration, growth) |
| 3 | Current policy (max 1-2 years), board has established it, employees are informed |
| 4 | Annual review demonstrable, adjustments documented, linked to risk analysis |
| 5 | Policy is a living document, real-time adjusted based on incidents and threats |

**1.1b: Policy communication**
Question: "Is the policy actively communicated to employees? How do employees know the rules?"
Probe: Test question — "If I ask a random employee what to do with a suspicious email, what would they say?"

| Level | Description |
|-------|-------------|
| 1 | No formal communication — "everyone knows how it should be" |
| 2 | Email at onboarding, then nothing |
| 3 | Part of onboarding, on intranet/SharePoint, annual reminder, employees sign for receipt |
| 4 | E-learning module, awareness campaign, quarterly update, measurement of effectiveness |
| 5 | Continuous programme with differentiated communication per target group |

**1.1c: Roles and responsibilities**
Question: "Are security roles, responsibilities and authorities described in the policy?"
Probe: "Who is the owner of the M365 tenant? Who may purchase new SaaS apps? Who manages Entra ID?"

| Level | Description |
|-------|-------------|
| 1 | "The IT person handles that" — everything with one person, nothing formal |
| 2 | Implicitly clear but not written down, works as long as that person is there |
| 3 | Described in policy or job descriptions who is responsible for what |
| 4 | Linked to risk register: per risk area an owner, periodically evaluated |
| 5 | Dynamic model, integrated in HR system, automatically updated on role changes |

#### BLOCK 2 — Risk Management / Control 2.1 (Art. 21(2)(a))

**2.1a: Risk analysis process**
Question: "Do you periodically conduct a risk analysis on your IT environment? How does that work?"
Probe: Methodology? Excel, tool, ad hoc? Frequency? Who is involved? "Who did the last analysis and when?"

| Level | Description |
|-------|-------------|
| 1 | Completely ad hoc, no documentation — "we know what the risks are" |
| 2 | One-time analysis (e.g. during GDPR process), not repeated since |
| 3 | Annual risk analysis, recorded in risk register, owners per risk |
| 4 | Continuous risk assessment, linked to change management and incident data |
| 5 | Automated risk monitoring, threat intel integrated, board-level risk dashboard |

**2.1b: Risk register**
Question: "Do you have a current overview of the most important risks? Which risks are currently at the top?"
Probe: Ask to see the register. If completely absent = major gap. Typical SME+ top risks: ransomware, phishing, critical SaaS failure, lost laptop, departure of sole IT person. If they can't name these = score 1.

| Level | Description |
|-------|-------------|
| 1 | No register, risks live in the IT person's head |
| 2 | Ad hoc list after incident or audit, not actively maintained |
| 3 | Current register: risk, likelihood, impact, measure, owner |
| 4 | Integrated in management reporting, quarterly review, heatmap for board |
| 5 | Automated risk register, real-time dashboards, shared with external auditors |

**2.1c: Risk appetite**
Question: "How do you determine which risks are acceptable and when measures are needed?"
Probe: "If a vendor reports a vulnerability in software you use — how do you decide whether to act?" Reveals actual decision logic.

| Level | Description |
|-------|-------------|
| 1 | Risks are not consciously weighed |
| 2 | Intuitive but not written down or shared with board |
| 3 | Risk threshold described, board establishes it, explicitly documented |
| 4 | Risk appetite differentiated per domain, reviewed annually |
| 5 | Risk appetite integrated in strategic planning, externally communicated |

#### BLOCK 3 — Periodic Evaluation / Control 3.1 (Art. 21(2)(f))

**3.1a: Effectiveness evaluation**
Question: "How do you evaluate whether security measures actually work? How often?"
Probe: Not the same as risk analysis — this is about effectiveness of measures. "Do you have a cyber insurance policy? What questions did the insurer ask?" — insurers increasingly demand evidence of evaluation.

| Level | Description |
|-------|-------------|
| 1 | No evaluation — "it works, we've never had an incident" |
| 2 | Reactive: evaluation only after incident or external pressure (customer, insurer) |
| 3 | Annual planned evaluation (internal or external), results documented |
| 4 | Mix of internal (audits) and external (pentest), metrics visible, trending |
| 5 | Red team exercises, continuous controls monitoring, benchmark with sector |

**3.1b: Evaluation follow-up**
Question: "Are evaluation results documented and do they lead to concrete adjustments?"
Probe: "Give an example of something that changed after an evaluation." Long silence = score 1-2.

| Level | Description |
|-------|-------------|
| 1 | Evaluation = informal conversation, no documentation |
| 2 | Findings written down but action plan missing or not followed |
| 3 | Formal report, improvement actions with owner and deadline, progress monitored |
| 4 | Integrated in PDCA cycle, improvement visible over multiple years, KPIs measured |
| 5 | Continuous improvement automated, lessons learned shared with sector |

#### BLOCK 4 — Board Training & Governance / Controls 14.1 & 14.2 (Art. 20)

**14.1: Board involvement**
Question: "Is the board actively involved in information security? How is the board informed about cyber risks?"
Probe: Testballon — "If I ask your CEO tomorrow what the top-3 cyber risks are for the organisation — what do you think they'd say?"

| Level | Description |
|-------|-------------|
| 1 | Board doesn't know what's happening — "that's something for IT" |
| 2 | IT person reports ad hoc when something happens, no structural agenda |
| 3 | Quarterly report to board on security status, incidents, KPIs |
| 4 | Board establishes risk appetite, security is fixed agenda item, board members name risks themselves |
| 5 | Board participates in crisis exercises, externally evaluated governance |

**14.1/14.2: Board training**
Question: "Have board members completed cybersecurity training? When and what type?"
Probe: "We had a presentation from our MSP" does NOT count. Ask for the certificate. **This is a hard Cbw requirement with a 2-year deadline.**

| Level | Description |
|-------|-------------|
| 1 | No training, board doesn't see it as their responsibility |
| 2 | One-time presentation or webinar attended, not documented |
| 3 | Demonstrable training (e-learning, workshop), documented per board member, within 2-year requirement |
| 4 | Annual mandatory refresher, board members independently assess risks |
| 5 | Board members as active security ambassadors, participation in external exercises |

**14.2: Keeping knowledge current**
Question: "How does the board keep their knowledge of cyber risks current?"
Probe: "Can you name a recent threat that reached you?" Many directors are subscribed to NCSC newsletter but don't read it.

| Level | Description |
|-------|-------------|
| 1 | Nothing arranged — "we'll hear about it when there's something" |
| 2 | Board member sometimes reads an article, no structural approach |
| 3 | NCSC/CISO newsletter subscription, annual update from external advisor, documented |
| 4 | Active participation in sector consultations, participation in exercises |
| 5 | Board actively contributes to sector threat assessments, thought leadership |

#### BLOCK 5 — Notification Obligation / Controls 15.1, 16.1 & 17.1 (Art. 23)

**15.1: Significant incident awareness**
Question: "Do you know when an incident is 'significant' under the Cbw and with whom to report it?"
Probe: **Notification obligation always stays with the client**, even with MDR/IR retainer. Test whether they understand this.

| Level | Description |
|-------|-------------|
| 1 | No idea about notification obligation or who NCSC is |
| 2 | Know there's an obligation but criteria unclear, no procedure |
| 3 | Criteria known, responsible person designated, CSIRT contact known |
| 4 | Criteria operationalised in decision playbook, exercise completed |
| 5 | Proactive relationship with CSIRT, active participation in threat information exchange |

**16.1: Notification timelines**
Question: "Do you have a documented notification procedure: first report within 24 hours, interim update within 72 hours, final report within one month?"
Probe: With IR retainer — who informs the client that an incident is reportable? SaaS consideration: if the incident is at the cloud provider (Microsoft, AWS), who reports? **The client remains responsible.**

| Level | Description |
|-------|-------------|
| 1 | Timelines unknown, no procedure |
| 2 | Know about timelines but no documented procedure |
| 3 | Procedure exists, responsible persons designated, NCSC reporting desk format known |
| 4 | Procedure tested in exercise, templates ready, CSIRT contact person known |
| 5 | Automated notification workflow, threshold detection linked to SIEM |

**17.1: Stakeholder communication during incidents**
Question: "If an incident impacts your customers or clients — how do you communicate with them?"
Probe: Client communication during incidents is mandatory and not outsourceable to IR retainer. "Do you know the difference between GDPR notification obligation (data breach, 72h to AP) and Cbw notification?"

| Level | Description |
|-------|-------------|
| 1 | "We'll call them if needed" — ad hoc, no procedure |
| 2 | Know communication is needed but templates or escalation line missing |
| 3 | Communication plan with templates, responsible for external communication designated |
| 4 | Communication plan tested, media spokesperson designated |
| 5 | Automated customer notification, real-time status page |

---

### Session 2 — Technical & Operations (~1.5 hours)

#### BLOCK 6 — Incident Management & Detection / Controls 4.1 & 4.2 (Art. 21(2)(b))

> With MDR/IR retainer: these controls are weighted lightly. Test contractual safeguarding and scope awareness, not whether they can do it themselves.

**4.1a: IR procedure and internal escalation**
Question: "Do you have an incident response procedure? Who is the internal contact in case of an incident?"
Probe: The 3 AM test — "If tomorrow at 3 AM your systems are encrypted by ransomware — who calls whom first?" If the answer is "your number" = good. If nobody knows = gap.

| Level | Description |
|-------|-------------|
| 1 | Nobody knows who to call in an incident; MDR/IR provider's number unknown |
| 2 | Know they should call the provider but procedure not documented |
| 3 | Brief procedure (1 page): internal contact assigned, MDR/IR contacts known, incident threshold defined |
| 4 | Procedure tested in tabletop with MDR/IR team present; roles clear |
| 5 | Periodic exercises, lessons learned systematically incorporated |

**4.1b: Threshold knowledge**
Question: "Do the right people internally know when to escalate to the MDR/IR provider? Is there a threshold criteria list?"
Probe: Deliver a contact card with threshold criteria as part of your offering — minimum fulfilment of control 4.1 for clients with IR retainer.

| Level | Description |
|-------|-------------|
| 1 | No one escalates, or escalation happens far too late |
| 2 | Vague agreements, not documented; breaks when that person leaves |
| 3 | Simple threshold list: when to solve internally, when to call provider, when to inform management |
| 4 | Threshold criteria tested in exercise; backup contacts designated |
| 5 | Automated escalation via SIEM alerts to internal contact |

**4.2a: MDR scope awareness**
Question: "Your MDR provider monitors your environment — do you know what's in scope and what isn't?"
Probe: Are all critical systems actually onboarded? Shadow IT and new SaaS apps outside scope = blind spot.

| Level | Description |
|-------|-------------|
| 1 | Client doesn't know what MDR involves or the scope |
| 2 | Knows broadly about monitoring but doesn't know the scope |
| 3 | Scope document available; knows which systems and logs are monitored; understands escalation |
| 4 | Receives periodic MDR reports; discusses and adjusts scope on changes |
| 5 | Actively participates in threat intelligence sharing; poses own detection questions |

**4.2b: Logging beyond MDR scope**
Question: "Are security logs outside MDR scope also maintained? Think of application logs, SaaS audit logs, access logs."
Probe: M365 audit log default retention is 90 days. E3/E5 can extend to 1 year. This is a concrete, low-threshold action.

| Level | Description |
|-------|-------------|
| 1 | No logs outside MDR scope — completely dependent on provider |
| 2 | M365 audit log active but retention too short (default 90 days); nobody reviews it |
| 3 | M365 audit log retention extended to 12+ months; overview of what is logged |
| 4 | Logging policy exists; periodic review of logs outside MDR scope |
| 5 | Complete log strategy; immutable archive; forensically usable |

#### BLOCK 7 — Business Continuity / Controls 5.1, 5.2 & 5.3 (Art. 21(2)(c))

**5.1: BCP policy**
Question: "Do you have a business continuity policy for IT? What are the maximum acceptable downtime periods for critical systems?"
Probe: SaaS reality check — "Microsoft takes care of that" is never a complete answer. What if M365 is down for 3 days? Fallback for email, Teams, authentication?

| Level | Description |
|-------|-------------|
| 1 | No idea about recovery times; no policy |
| 2 | Intuitive ("back up ASAP") but not quantified |
| 3 | Per critical system: RTO and RPO determined and documented; backup strategy aligned |
| 4 | BIA conducted; continuity policy established by management; vendor SLAs verified |
| 5 | Automated failover; real-time RTO monitoring |

**5.2a: Recovery plan**
Question: "Is there a documented continuity and recovery plan? When was it last tested?"
Probe: Can you rebuild a laptop within 4 hours? Can you restore files if the NAS is encrypted? Do restores also work for SaaS data (SharePoint, Teams files)?

| Level | Description |
|-------|-------------|
| 1 | No plan |
| 2 | Plan exists but never tested, or test >2 years old |
| 3 | Annual test (tabletop or technical recovery); results documented |
| 4 | Periodic recovery test; "all IT down" scenario exercised |
| 5 | Automatic failover tests; continuous BCP validation |

**5.2b: Backup organisation**
Question: "How are backups organised? Offline or offsite? When was restore last tested?"
Probe: **Microsoft 365 has NO adequate built-in backup.** Version history is NOT a backup. Recommend Veeam for M365, Acronis, or Dropsuite.

| Level | Description |
|-------|-------------|
| 1 | "Everything is in the cloud, Microsoft makes backups" — no own backup, no test |
| 2 | Backup present but restore never tested, or no offline/offsite copy |
| 3 | 3-2-1 backup; monthly restore test; retention minimum 30 days |
| 4 | Immutable backups; automatic restore test; RPO < 4 hours |
| 5 | Real-time replication; automated restore validation |

**5.3: Crisis management**
Question: "Is there a crisis plan for major cyber incidents? Does management know what to do when all systems are down — outside the IR retainer?"
Probe: With IR retainer you do the technical response. But the client must decide on communication, business operations, notification obligations themselves. Minimum for SME+: a laminated emergency card with MDR/IR contacts, NCSC number, insurer contact, communication responsible — realisable in 1 day.

| Level | Description |
|-------|-------------|
| 1 | "Then we call you and hope for the best" — no understanding of own role |
| 2 | People broadly know what to do but own crisis role not described |
| 3 | Simple crisis plan: internal decision-maker assigned, escalation to provider described, communication plan, notification handled |
| 4 | Crisis plan tested in tabletop with MDR/IR team |
| 5 | Annual crisis exercise; lessons learned systematically incorporated |

#### BLOCK 8 — Supply Chain / Controls 6.1 & 6.2 (Art. 21(2)(d))

**6.1a: Supplier security policy**
Question: "Do you have a policy on the security of suppliers who have access to your systems or data?"
Probe: Typical SME+ problems — MSP has domain admin without MFA; accountant accesses via unmanaged laptop; ex-vendor still has login credentials.

| Level | Description |
|-------|-------------|
| 1 | No policy — vendors get access "because they need it for their work" |
| 2 | Know vendors are a risk but no formal policy or register |
| 3 | Policy describes how vendors are assessed, what requirements apply, how access is granted/revoked |
| 4 | Vendor classification (critical/non-critical); risk-based requirements per category |
| 5 | Supply chain fully mapped; fourth-party risks managed |

**6.1b: Security clauses in contracts**
Question: "Are security requirements included in vendor contracts? Processor agreements, SLAs with security requirements?"
Probe: GDPR processor agreement is a start but Cbw asks broader — also technical measures. Does your own MDR/IR contract contain the right SLAs?

| Level | Description |
|-------|-------------|
| 1 | No security requirements in contracts |
| 2 | GDPR processor agreement present but no broader security requirements |
| 3 | Standard clauses: incident notification, encryption, access rights |
| 4 | Risk-proportionate: for critical vendors, audit rights, ISO/SOC2 certification required |
| 5 | Security requirements standardised; automatically updated for legal changes |

**6.2: Vendor testing**
Question: "Do you periodically verify whether critical suppliers meet your security requirements?"
Probe: Simple first step — ask your top-5 vendors for their ISO27001 certificate or SOC2 report.

| Level | Description |
|-------|-------------|
| 1 | Never tested — "we trust our vendors" |
| 2 | One-time at contract signing; nothing after |
| 3 | Annual review: questionnaire; certifications requested (ISO27001, SOC2 Type II) |
| 4 | Risk-based: critical vendors annually, others biennially |
| 5 | Continuous vendor monitoring; real-time compliance dashboards |

#### BLOCK 9 — Systems: Acquire, Develop & Maintain / Controls 7.1-7.3 (Art. 21(2)(e))

**7.1: Acquiring systems (shadow IT)**
Question: "How are security requirements considered when purchasing new software, hardware or cloud services?"
Probe: Shadow IT detection technique — ask IT how many SaaS apps are in use. Ask a random employee the same question. **The difference is shadow IT.**

| Level | Description |
|-------|-------------|
| 1 | Everyone buys what they need — dozens of unknown SaaS apps |
| 2 | IT knows about it but only approves after purchase, or not at all |
| 3 | Procurement procedure: IT/security assesses before go-live; checklist with security criteria |
| 4 | Formal process; security by design; PIA when personal data involved |
| 5 | Centralised SaaS governance; automated shadow IT detection |

**7.2: Software development** (if applicable)
Question: "Do you develop software internally? If so, how are security requirements embedded?"
Probe: If no custom development, note N/A explicitly and skip. For external development: are security requirements in the assignment? Who owns source code?

| Level | Description |
|-------|-------------|
| 1 | Own development without security requirements |
| 2 | Some attention (no hardcoded passwords) but not systematic |
| 3 | SAST tooling; code reviews; OWASP top-10 as guideline; pentest before go-live |
| 4 | DevSecOps: security in CI/CD pipeline; DAST; threat modelling |
| 5 | Fully automated security pipeline; externally certified SDLC |

**7.3a: Patch management**
Question: "How is patch management arranged? Are security updates rolled out timely, including on network equipment?"
Probe: "When was your firewall firmware last updated?" — catches the SME+ pattern of patching endpoints but not network devices.

| Level | Description |
|-------|-------------|
| 1 | Patches rolled out "when we think of it" — no structure |
| 2 | Windows Updates automatic but firewall, NAS, routers, printers forgotten |
| 3 | Patch policy: critical patches within 72 hours; others monthly; includes all endpoints and network devices |
| 4 | Vulnerability management: CVE feeds; CVSS prioritisation; patch compliance measured |
| 5 | Automated vulnerability scanning; zero-day response within 24 hours |

SME+ forgotten devices: firewall firmware (Fortinet, Sophos), NAS (Synology, QNAP), printers, VoIP, IP cameras.

**7.3b: Configuration management**
Question: "Are changes to systems registered and authorised? Is there a change log?"
Probe: SaaS pitfall — who manages the M365 tenant? Are changes in Entra ID (conditional access, MFA settings) registered?

| Level | Description |
|-------|-------------|
| 1 | Changes directly implemented — no registration, no approval |
| 2 | Major changes discussed but minor ones not registered |
| 3 | Change log maintained; changes authorised; rollback procedure present |
| 4 | Formal change advisory board; automated compliance check on configurations |
| 5 | Infrastructure as Code; automatic drift detection; configs in version control |

#### BLOCK 10 — Cyber Hygiene & Training / Controls 8.1 & 8.2 (Art. 21(2)(g))

**8.1a: Technical baseline (MFA, passwords, screen lock)**
Question: "What baseline measures are standard for all employees? MFA, password policy, screen lock?"
Probe: MFA is the most impactful measure. Check conditional access. "Are there users who have disabled MFA or have an exception?" One admin without MFA = failure of the entire control.

| Level | Description |
|-------|-------------|
| 1 | No MFA; simple passwords; password reuse |
| 2 | MFA on M365 but not other SaaS apps; no password manager |
| 3 | MFA on all critical systems; password manager; screen lock enforced |
| 4 | Phishing-resistant MFA (FIDO2); conditional access; annual hygiene training |
| 5 | Zero trust posture; passwordless; continuous automated hygiene checks |

MFA checklist: M365, VPN, financial system, HR system, admin accounts, DNS registrar, GitHub/GitLab.

**8.1b: Security awareness training**
Question: "How are employees made aware of cyber threats? Is there awareness training and how often?"
Probe: "What is your phishing click-through rate?" If they don't know, there's no measurement. Demonstrable = score 3. "We mention it sometimes" = score 1-2.

| Level | Description |
|-------|-------------|
| 1 | No training |
| 2 | One-time training at onboarding; nothing after |
| 3 | Annual e-learning (KnowBe4, Proofpoint, Awarego); phishing simulations; results monitored |
| 4 | Continuous: monthly micro-learnings; advanced phishing simulations |
| 5 | Behavioural analysis integrated in security operations; security champions per department |

**8.2: Specialist security training**
Question: "Are employees with security-sensitive roles designated and do they receive additional training?"
Probe: Risk groups beyond IT that are often overlooked — Finance (CEO fraud), HR (identity fraud), Management (spear-phishing), Reception/helpdesk (social engineering).

| Level | Description |
|-------|-------------|
| 1 | No designation — the IT person handles it anyway |
| 2 | IT person designated but no structured security training |
| 3 | Designated personnel; annual relevant training |
| 4 | Certified professionals (CISSP, CISM, CompTIA Security+); training plan per person |
| 5 | Internal knowledge centre; external speakers; community contribution |

#### BLOCK 11 — Cryptography / Control 9.1 (Art. 21(2)(h))

**9.1a: Encryption policy**
Question: "Do you have an encryption policy? Are laptops and sensitive data encrypted?"
Probe: Disk encryption is an absolute baseline. Checklist: BitLocker (Windows), FileVault (Mac), USB forbidden or encrypted, TLS on all web apps. SaaS check: who manages the encryption key?

| Level | Description |
|-------|-------------|
| 1 | No encryption policy; laptops not encrypted |
| 2 | BitLocker present but inconsistently rolled out; no policy |
| 3 | Mandatory encryption policy; demonstrably implemented on all laptops and removable media |
| 4 | Encryption for data-at-rest and in-transit for all critical systems; key management formalised |
| 5 | End-to-end encryption for all communication; customer-managed keys in cloud |

**9.1b: Key management**
Question: "How are encryption keys and certificates managed? Who has access and how are they renewed?"
Probe: Key management is often forgotten. SSL certificates that expire. BitLocker recovery keys only in the IT person's head = single point of failure.

| Level | Description |
|-------|-------------|
| 1 | Keys stored in email or text file on desktop |
| 2 | Password manager but no formal rotation policy |
| 3 | Central password vault (1Password Teams, Bitwarden Business); key rotation policy; max 2-3 managers |
| 4 | Key Management Service (Azure Key Vault); audit trail on key usage; automated certificate renewal |
| 5 | HSM for high-risk processes; automated key lifecycle management |

#### BLOCK 12 — Personnel & Access / Controls 10.1 & 11.1 (Art. 21(2)(i),(j))

**10.1a: Personnel screening**
Question: "How are security roles assigned to personnel? Is there screening for sensitive positions?"
Probe: Often forgotten — vendors and interns sometimes get the same rights as employees without screening.

| Level | Description |
|-------|-------------|
| 1 | No screening; no NDA; security roles implicit |
| 2 | VOG only for "sensitive roles" but criteria unclear |
| 3 | VOG policy documented; NDA standard in employment contract; security roles described |
| 4 | Risk-proportionate screening per role; periodic re-screening for critical roles |
| 5 | Continuous insider risk monitoring; automated onboarding/offboarding checks |

**10.1b: Offboarding**
Question: "What happens when someone leaves? Is access revoked timely and completely?"
Probe: Direct test — export active Entra ID accounts, compare with current personnel roster. Active accounts of ex-employees = immediate finding.

| Level | Description |
|-------|-------------|
| 1 | Access revoked "if someone remembers" — ex-employees with active accounts |
| 2 | Main account blocked but SaaS apps forgotten |
| 3 | Offboarding checklist for all systems; account blocked day 1; IT assets returned |
| 4 | Automated via HR integration with Entra ID; direct disable on departure |
| 5 | Zero-trust: access expires automatically without active contract |

**11.1a: Least privilege and admin separation**
Question: "Do you apply least privilege? Are admin accounts separated from daily accounts?"
Probe: Everyone admin = major gap. M365 checks — Global Admin with separate MFA? Min 2, max 4 Global Admins? Privileged Identity Management active?

| Level | Description |
|-------|-------------|
| 1 | All employees admin on laptop; IT person uses admin account for daily work |
| 2 | Limited admins but admin accounts also used for daily work |
| 3 | Separated admin accounts; least privilege applied; periodic review of rights |
| 4 | Azure PIM active; just-in-time admin access; all admin actions logged |
| 5 | Full zero-trust model; continuous access verification |

**11.1b: MFA on critical systems**
Question: "Is MFA configured on all critical systems? Including remote access and admin portals?"
Probe: Conditional access minimum — block legacy authentication, require MFA all users, require compliant device. Basic MFA without conditional access = gap.

| Level | Description |
|-------|-------------|
| 1 | No MFA, or only on one system |
| 2 | MFA on M365 but not VPN, other SaaS, or admin portals |
| 3 | MFA on all critical systems; conditional access active; exceptions limited and documented |
| 4 | Phishing-resistant MFA (FIDO2/passkeys); risk-based conditional access |
| 5 | Fully passwordless; device compliance required; real-time risk scoring |

#### BLOCK 13 — Asset Management / Controls 12.1 & 12.2 (Art. 21(2)(i))

**12.1: Asset management policy**
Question: "Do you have a policy for managing IT assets? Is it clear who is responsible for which assets?"
Probe: Forgotten assets — SaaS subscriptions, cloud storage of ex-employees, API keys, domain registrations, SSL certificates, BYOD devices.

| Level | Description |
|-------|-------------|
| 1 | No asset policy — IT person broadly knows what exists, nothing documented |
| 2 | Hardware inventory present but software, SaaS, data assets missing |
| 3 | Policy describes lifecycle (acquisition → use → disposal); ownership per asset |
| 4 | Automated asset discovery; classification by criticality |
| 5 | Real-time asset management; automatic decommissioning triggers |

**12.2: Asset inventory**
Question: "Do you have a current overview of all IT assets, including SaaS applications and cloud services?"
Probe: Approach for SME+ — hardware via Intune export, software via Endpoint Manager, SaaS via credit card expenses + employee survey, data: where is sensitive data stored?

| Level | Description |
|-------|-------------|
| 1 | No inventory |
| 2 | Outdated hardware list; no software/SaaS; never updated |
| 3 | Current inventory: hardware + software + SaaS; owner per asset; updated on changes |
| 4 | Automated via MDM (Intune); MCAS/Defender for Cloud Apps |
| 5 | Continuous asset intelligence; automatic risk scoring per asset |

#### BLOCK 14 — Threat Intelligence / Control 13.1 (Art. 21(2)(b))

**13.1a: Threat monitoring**
Question: "How do you keep sight of current cyber threats and vulnerabilities? What do you do with information from NCSC or your MDR provider?"
Probe: "What have you done with the last security warning we sent you?" Tests whether they actively act on threat intelligence.

| Level | Description |
|-------|-------------|
| 1 | No process — reactive; learn through media |
| 2 | Receive NCSC newsletter but nobody reads or translates to actions |
| 3 | Registered with NCSC and relevant ISAC; MDR reports discussed; structured follow-up |
| 4 | Threat intelligence in management meetings; actions recorded |
| 5 | Active contribution to sector threat pictures; own threat hunting capacity |

**13.1b: Vulnerability response process**
Question: "When you receive a vulnerability warning for software you use — what is the internal process?"
Probe: "We sometimes send urgent patch advice. Who receives it and what do you do?" Tests effectiveness of service delivery.

| Level | Description |
|-------|-------------|
| 1 | Nobody acts — vulnerability found only when damage occurs |
| 2 | IT person follows up but no formal process or escalation |
| 3 | Process: receipt → impact assessment → decision → execution → verification. Contact person assigned |
| 4 | SLA on response (critical: patch within 24h); demonstrable follow-up |
| 5 | Automated triage and patch deployment |

---

### Session 3 — ISMS Management System (~1 hour, optional)

> The Cbw requires a management system for information security. The choice of methodology is free, but for government organisations ISO27001 is mandatory (via BIO2). For SME+ with ISMS-light: it's not about certification — it's about whether there is a management cycle that works without depending on an individual.

#### PLAN phase

**P.1: Context and scope**
Question: "Do you have insight into internal and external factors affecting information security? Is there a stakeholder analysis?"
Probe: "For which systems, processes and locations does your security policy apply?" If unclear = scope gap.

| Level | Description |
|-------|-------------|
| 1 | No insight in context, no stakeholder analysis, scope unknown |
| 2 | Know the environment but not documented |
| 3 | Context analysis documented (internal and external), stakeholders mapped, ISMS scope formally established |
| 4 | Context analysis reviewed annually, linked to strategic plan |
| 5 | Dynamic context analysis, integrated in enterprise risk management |

**P.2: Leadership**
Question: "Does the board show active leadership in information security? Are responsibilities described and has the board approved the policy?"
Probe: Difference with 14.1: leadership is about structural involvement in the ISMS system, not just training.

| Level | Description |
|-------|-------------|
| 1 | Board delegated to IT, no active involvement |
| 2 | Policy signed by board but no further active role |
| 3 | Board established policy, reporting structure in place, security as agenda item |
| 4 | Board establishes risk appetite, security KPIs monitored at board level |
| 5 | Board as security ambassador, active participation in sector consultations |

**P.3: Planning**
Question: "Are organisational goals, risks and compliance requirements translated into an information security plan?"
Probe: "Do you have a security annual plan for this year? What are the top-3 priorities?" If they can't name them = score 1-2.

| Level | Description |
|-------|-------------|
| 1 | No security plan, no link to strategy |
| 2 | One-time plan, not maintained |
| 3 | Annual plan linked to risk analysis, approved by board |
| 4 | SMART plan: objectives, measurement points, owners, timelines, budget |
| 5 | Dynamic plan, real-time adjusted based on threat intelligence |

**P.4: Resources**
Question: "Are sufficient resources (budget, people, tools) available? Are required competencies established?"
Probe: "What percentage of the IT budget goes to security?" Industry norm: 10-15%. In SME+ often 0-3% consciously allocated.

| Level | Description |
|-------|-------------|
| 1 | No security budget, no designated people, security is a side job |
| 2 | Limited budget (tools only) but no structural staffing plan |
| 3 | Security budget established, required competencies described, gap between desired and current mapped |
| 4 | Multi-year security budget, training plan per employee |
| 5 | Security investment linked to risk appetite, externally benchmarked |

#### DO phase

**D.1: Policy operationalisation**
Question: "Is the security policy operationally translated into procedures and work instructions? Do employees know what to concretely do?"
Probe: Cross-reference with control 1.1 — if policy scored 3 but this scores 1-2 = **policy is paper but not practice. Critical finding.**

| Level | Description |
|-------|-------------|
| 1 | Policy exists but not translated into practical procedures |
| 2 | Some procedures but not linked to policy, inconsistent |
| 3 | Policy translated into brief procedures per domain (incident, access, backup), employees know them |
| 4 | Procedures integrated in work processes, demonstrably followed, annual review |
| 5 | Automated compliance checks on procedure adherence |

**D.2: Execution**
Question: "Are measures actually executed as planned? Are there owners per measure?"
Probe: "Can you demonstrate that your patch policy is actually followed?" Report from Intune/MDM = good score. "We always do it" without evidence = score 1-2.

| Level | Description |
|-------|-------------|
| 1 | Plan exists but execution ad hoc or dependent on one person |
| 2 | Measures partly executed but not systematically monitored |
| 3 | Measures systematically executed, owners assigned, progress reported |
| 4 | Execution integrated in regular operations, demonstrable via logging and reports |
| 5 | Automated execution and verification, continuous compliance monitoring |

#### CHECK phase

**C.1: Performance evaluation**
Question: "Does the organisation periodically evaluate ISMS effectiveness? Is what needs to be measured being measured?"
Probe: Difference with 3.1: there it's about whether security measures work. Here it's about whether the ISMS system itself functions well.

| Level | Description |
|-------|-------------|
| 1 | No systematic ISMS evaluation |
| 2 | Reactive evaluation after incidents or external pressure |
| 3 | Planned internal audit, management review, KPIs defined and measured |
| 4 | Mix internal and external, trending visible, results to board |
| 5 | Continuous controls monitoring, real-time ISMS dashboard, externally certified |

#### ACT phase

**A.1: Improvement process**
Question: "Does the organisation continuously improve ISMS effectiveness? How are lessons from evaluations and incidents structurally processed?"
Probe: "What was the biggest security incident last year, and what did you concretely change afterwards?" Shows whether the improvement process actually works.

| Level | Description |
|-------|-------------|
| 1 | No structural improvement process |
| 2 | Improvements ad hoc after incidents, not systematically embedded |
| 3 | Lessons learned after incidents and audits, improvement actions with owner and deadline |
| 4 | PDCA cycle demonstrably working: improvements visible over multiple cycles |
| 5 | Proactive improvement based on threat intelligence and benchmarks |

**A.2: Corrective actions**
Question: "Does the organisation respond to deviations and take measures to address root causes?"
Probe: If no deviation register exists but incidents have occurred = score 1. Major gap in PDCA cycle.

| Level | Description |
|-------|-------------|
| 1 | Deviations resolved but root cause not addressed |
| 2 | Sometimes root cause analysis but not systematic, no registration |
| 3 | Deviation register, root cause analysis standard, corrective measures documented |
| 4 | Trend analysis on deviations, proactive measures, effectiveness measured |
| 5 | Automated deviation detection, structural root cause analysis |

---

## 5. Gap report output format

After completing the questionnaire, produce a gap report:

```json
{
  "entity_type": "essential | important",
  "assessment_date": "ISO 8601",
  "maturity_target": 3,
  "sessions": {
    "session_1_governance": {
      "controls": ["1.1", "2.1", "3.1", "14.1", "14.2", "15.1", "16.1", "17.1"],
      "avg_score": 2.3,
      "gaps_below_target": 5
    },
    "session_2_technical": {
      "controls": ["4.1", "4.2", "5.1", "5.2", "5.3", "6.1", "6.2", "7.1", "7.2", "7.3", "8.1", "8.2", "9.1", "10.1", "11.1", "12.1", "12.2", "13.1"],
      "avg_score": 2.1,
      "gaps_below_target": 12
    },
    "session_3_isms": {
      "controls": ["P.1", "P.2", "P.3", "P.4", "D.1", "D.2", "C.1", "A.1", "A.2"],
      "avg_score": 1.8,
      "gaps_below_target": 7
    }
  },
  "isms_reliability": "FRAGILE | ROBUST | DEVELOPING",
  "priority_gaps": [
    {"control": "14.1/14.2", "score": 1, "priority": "HIGH", "reason": "Hard Cbw requirement with 2-year deadline", "action": "Organise certified board training", "timeline": "< 3 months"},
    {"control": "5.2b", "score": 1, "priority": "HIGH", "reason": "No M365 backup", "action": "Deploy Veeam/Acronis for M365", "timeline": "< 1 month"}
  ],
  "overall_readiness": "LOW | MEDIUM | HIGH"
}
```

### Roadmap priority levels

| Priority | Meaning | Timeline |
|----------|---------|----------|
| **HIGH** | Direct compliance gap or high risk | < 3 months |
| **MID** | Improvement needed | 3-12 months |
| **LOW** | Nice-to-have | 12+ months |

---

## 6. Incident reporting quick reference

| Step | Deadline | What to report | To whom |
|------|----------|---------------|---------|
| Early warning | 24 hours after awareness | Suspected significant incident, cross-border impact indicator | CSIRT / competent authority |
| Incident notification | 72 hours after awareness | Severity, impact, initial assessment | CSIRT / competent authority |
| Intermediate report | On request | Updated assessment | CSIRT / competent authority |
| Final report | 1 month after notification | Root cause, mitigation, cross-border impact | CSIRT / competent authority |

**Significant incident criteria** (Art. 23(3)): serious operational disruption or financial loss, OR affected other persons with considerable material/non-material damage.

---

## 7. Supervision & enforcement

| Entity type | Supervision | Max fine |
|-------------|-------------|---------|
| Essential | Ex-ante (proactive) | EUR 10M or 2% worldwide annual turnover |
| Important | Ex-post (reactive) | EUR 7M or 1.4% worldwide annual turnover |

---

## Agent instructions

1. Always run the applicability pre-screen first. If out of scope, stop.
2. Work through sessions in order (Session 1 → 2 → optionally 3).
3. For each question, present the question and probe. Try to assess autonomously first (inspect code, config, docs). If answering autonomously, create an ADR via audit-logging.
4. If you cannot determine the answer, ask the user. Present the 5 maturity levels and let them self-place.
5. Score immediately after each block. Briefly validate scores with the user.
6. Use the three-layer assessment (design/adoption/effectiveness) when reviewing documents — final score = lowest layer.
7. After scoring ISMS, apply the reliability principle to interpret Session 1 & 2 scores.
8. Produce the gap report JSON with prioritised roadmap.
9. Never give legal advice — frame everything as "assessment" and recommend consulting legal counsel.
10. Apply MDR/IR context: when the organisation has MDR/IR, weight controls 4.1, 4.2, 5.3 on contractual safeguarding and scope awareness, not self-execution capability.
