---
name: eu-compliance-directives
description: >
  Curated index of official EU and national (member state) compliance sources,
  including directives, transposition laws, and regulatory guidance. ACTIVATE
  when answering questions about EU regulations or national implementations
  (NIS2, GDPR, DORA, AI Act, Cyberbeveiligingswet, etc.) — especially
  differences between EU directives and local laws, applicability, enforcement,
  timelines, or legal obligations. Also activate for conceptual or comparative
  questions ("what changed", "how does NL differ from the EU directive").
  Always verify current legal status and ground answers in authoritative sources
  instead of relying on general knowledge.
---

# EU Compliance Directives & National Transpositions

> Don't hardcode compliance facts that change. Look them up. EU directives become national law differently in each member state — always check both levels.

## Key concept: directives vs regulations

| Type | What it means | Example |
|---|---|---|
| **Regulation** | Directly applicable in all member states. No transposition needed. | GDPR, DORA, AI Act |
| **Directive** | Must be transposed into national law. Each country may implement differently. | NIS2 → Cyberbeveiligingswet (NL), NIS2UmsuCG (DE), etc. |

When a user asks about a directive, always consider both the EU-level text AND the national transposition. They can differ on scope, penalties, and sector definitions.

## Source index

### EU-level sources

#### ECSO NIS2 Transposition Tracker

- **URL**: https://ecs-org.eu/activities/nis2-transposition-tracker/
- **Maintainer**: European Cyber Security Organisation
- **Reliability**: HIGH
- **Use for**: Per-country transposition status, timeline, national legislation links
- **Limitations**: May lag behind official notifications by days

#### EC Digital Strategy

- **URL**: https://digital-strategy.ec.europa.eu/en/policies/nis-transposition
- **Maintainer**: European Commission
- **Reliability**: HIGH
- **Use for**: Official notification status per member state
- **Limitations**: Less detail than ECSO tracker

#### EUR-Lex

- **URL**: https://eur-lex.europa.eu
- **Maintainer**: Publications Office of the EU
- **Reliability**: HIGH (authoritative)
- **Key URLs**:
  - NIS2: https://eur-lex.europa.eu/eli/dir/2022/2555
  - GDPR: https://eur-lex.europa.eu/eli/reg/2016/679
  - DORA: https://eur-lex.europa.eu/eli/reg/2022/2554
  - AI Act: https://eur-lex.europa.eu/eli/reg/2024/1689
- **Use for**: Full legislative text, recitals, annexes, transposition notices

#### ENISA Technical Guidance

- **URL**: https://www.enisa.europa.eu/publications
- **Maintainer**: EU Agency for Cybersecurity
- **Reliability**: HIGH
- **Use for**: Practical implementation guidance for NIS2 Art. 21, risk management, incident reporting
- **Limitations**: Guidance, not binding

#### ENISA NIS2 Technical Implementation Guidance (June 2025, v1.0)

- **URL**: https://www.enisa.europa.eu/publications/nis2-technical-implementation-guidance
- **PDF**: https://www.enisa.europa.eu/sites/default/files/2025-06/ENISA_Technical_implementation_guidance_on_cybersecurity_risk_management_measures_version_1.0.pdf
- **Reliability**: HIGH
- **Use for**: Per-requirement guidance and auditor-accepted evidence examples for all 13 NIS2 Art. 21(2) domains
- **Scope**: Legally binds ICT-type entities only (DNS, TLDs, cloud, data centres, CDN, MSPs/MSSPs, online platforms, trust services). Useful reference for all NIS2 entities

#### EU ICT Supply Chain Security Toolbox (NIS Cooperation Group, Jan 2026)

- **URL**: https://digital-strategy.ec.europa.eu/en/library/toolbox-improve-ict-supply-chain-security
- **Maintainer**: NIS Cooperation Group (Member States + Commission + ENISA)
- **Reliability**: HIGH
- **Use for**: 11 ICT supply chain risk scenarios + 7 recommendations (R01-R07) supporting NIS2 Art. 21(2)(d)

#### EDPB Guidelines (GDPR)

- **URL**: https://edpb.europa.eu/our-work-tools/general-guidance/guidelines-recommendations-best-practices_en
- **Maintainer**: European Data Protection Board
- **Reliability**: HIGH
- **Use for**: GDPR interpretation, cross-border enforcement, binding decisions
- **Supervisory authorities**: https://edpb.europa.eu/about-edpb/about-edpb/members_en

#### EU AI Office

- **URL**: https://digital-strategy.ec.europa.eu/en/policies/ai-office
- **Maintainer**: European Commission
- **Reliability**: HIGH
- **Use for**: AI Act implementation timeline, codes of practice, high-risk classification
- **Phased entry**: Feb 2025 (prohibited) → Aug 2025 (GPAI) → Aug 2026 (high-risk Annex III) → Aug 2027 (Annex I)

#### ESA Guidance (DORA)

- **Maintainer**: EBA, EIOPA, ESMA (jointly)
- **Use for**: DORA regulatory technical standards (RTS), implementing technical standards (ITS)
- **In force**: January 2025

### National sources

#### Netherlands

| Source | URL | Use for |
|---|---|---|
| **Cyberbeveiligingswet (Cbw)** | wetten.overheid.nl | NIS2 transposition — Dutch national law |
| **NCSC-NL** | ncsc.nl | Guidance, self-assessment, incident reporting |
| **Autoriteit Persoonsgegevens** | autoriteitpersoonsgegevens.nl | GDPR supervision, breach reporting |

#### Germany

| Source | URL | Use for |
|---|---|---|
| **NIS2UmsuCG** | bsi.bund.de | NIS2 transposition — German national law |
| **BSI IT-Grundschutz** | bsi.bund.de | Baseline protection catalogue, KRITIS |
| **OpenKRITIS** | openkritis.de | Community resource for KRITIS implementation |

#### Belgium

| Source | URL | Use for |
|---|---|---|
| **CCB CyFun** | ccb.belgium.be | Belgian Cybersecurity Framework, NIS2 mapping |
| **Centre for Cybersecurity Belgium** | ccb.belgium.be | National authority, guidance |

#### Bird & Bird NIS2 Tracker (multi-country)

- **URL**: https://www.twobirds.com/en/insights/2023/global/nis2-tracker
- **Reliability**: MEDIUM (commercial, law firm)
- **Use for**: Quick visual overview of transposition status across all EU countries

### EU_compliance_MCP — pre-indexed regulation database

- **Install**: `npx @ansvar/eu-regulations-mcp` or add as MCP server
- **Source**: https://github.com/Ansvar-Systems/EU_compliance_MCP
- **Reliability**: HIGH (sourced from EUR-Lex)
- **Coverage**: 49 EU regulations, 2,500+ articles, 1,200+ definitions, full-text search
- **Use for**: Instant article/recital retrieval, cross-regulation comparison, control mappings
- **When available**: Prefer over web lookups for article text — faster and offline-capable

## Agent lookup workflow

### For EU-level questions (regulations, general obligations)

1. **EUR-Lex** — authoritative legislative text
2. **ENISA / EDPB / ESA** — practical guidance per regulation
3. **EU_compliance_MCP** — if available, use for instant article lookup and cross-regulation comparison
4. **Always include a freshness warning** — compliance status changes

### For national implementation questions (transposition, local differences)

1. **ECSO tracker** — which countries have transposed, links to national laws
2. **National source** — check the specific country's authority (NCSC-NL, BSI, CCB, etc.)
3. **Cross-reference EUR-Lex** — compare directive text with national implementation
4. **Flag differences** — explicitly tell the user where national law adds to or differs from the EU directive

### For comparative questions ("how does X differ from Y")

1. Identify both sources (EU directive + national law, or two national laws)
2. Use EUR-Lex for the EU baseline
3. Use national sources for local specifics
4. Present a clear comparison: what's the same, what differs, what's stricter

## Agent instructions

1. Never state transposition status or legal facts from memory — always direct the user to check the source.
2. Use the lookup workflow above to guide which source to check first.
3. Include the source URL and a freshness warning in every response.
4. If a user needs country-specific detail, check the ECSO tracker and the relevant national authority.
5. For practical "how to comply" questions, point to ENISA guidance (NIS2), EDPB guidelines (GDPR), or ESA standards (DORA).
6. For legal text, point to EUR-Lex.
7. When comparing EU directive vs national law, always flag where the national implementation is stricter or broader than the directive minimum.
8. If the user's org profile includes a jurisdiction, prioritise sources for that country.
