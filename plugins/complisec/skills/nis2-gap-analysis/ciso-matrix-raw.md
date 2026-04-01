# NIS2 Gap Analysis Matrix — Raw Conversion

> Converted from CISO's PDF export (March 2026). Original 4-column format: Question | Answer | Gap | Guidance.
> Each question has 3 maturity levels.

---

## Q1: Are you aware of all the systems, websites, and domain names you use?

**A: No. We have don't have an inventory.**
Gap: There is no formal asset inventory, meaning the organization lacks visibility into its systems, websites, and domain names. This increases the risk of unmanaged, unknown, or vulnerable assets being exposed.
Guidance: Establish a basic asset inventory using a centrally stored Excel or spreadsheet. Include key details such as system names, domain names, owners, and purpose. Update it at least annually. If possible, use automated tools such as domain scanners to help identify and track external-facing assets.

**B: Yes. Some assets documented (e.g., through pentests).**
Gap: Asset information is partially documented but incomplete and not actively maintained. There is no continuous monitoring of external-facing assets, which may lead to outdated data and overlooked risks.
Guidance: Move beyond basic documentation and adopt an Attack Surface Management (ASM) tool or automated asset discovery solution. Use it alongside your inventory (Excel or asset management system) to continuously monitor, validate, and update both internal and external assets. Define ownership and implement regular review cycles (e.g., quarterly).

**C: Yes. We have a comprehensive inventory of all assets, including systems and websites.**
Gap: No gap.
Guidance: No guidance needed — this meets best practice. If possible, ensure the inventory is continuously monitored, automatically updated, and linked to risk assessments and vulnerability management for enhanced maturity.

---

## Q2: Do you have established procedures and policy documents for risk management?

**A: Little to no procedures and policies in place.**
Gap: There are no formalized risk management procedures or documented policies. The organization lacks clear guidance on security expectations, which increases inconsistencies and unmanaged risks.
Guidance: Start by documenting basic policies and procedures that reflect how you want to organize key security practices. Prioritize essential documents such as a Password Policy, Cyber Incident Response Plan, and Acceptable Use Policy. These do not need to be perfect — starting simple is better than having nothing. You can use public policy templates for inspiration from sources like Policy templates | CCB Safeonweb.

**B: Yes. Policies exist, but they mainly address critical security issues.**
Gap: There is partial coverage of policies, but key security domains (e.g., governance, risk management, access control, vendor management) are not fully addressed. Policies may exist but are not yet comprehensive or aligned with a formal framework.
Guidance: Full ISO 27001 certification is not always necessary. Many organizations benefit from adopting only the relevant parts. Consider templates to help companies quickly build a more complete and structured set of policies. Another good reference is the Cyfun model (CCB, Belgium), which provides practical guidance on policy requirements without being overly complex. Policy templates | CCB Safeonweb.

**C: Yes. We have comprehensive policy frameworks, such as ISO27K1, effectively implemented for risk management.**
Gap: No gap.
Guidance: No guidance needed — this meets best practice. For continuous improvement, ensure policies are reviewed annually, aligned with current risks, and supported by governance oversight.

---

## Q3: Have you identified and taken additional measures to safeguard your company's 'crown jewels' (systems and data), both internally and externally?

**A: There are little to no identification or protection measures in place.**
Gap: Critical business assets ('crown jewels') have not been formally identified. As a result, there is no prioritization of protection measures for the most valuable systems, data, or people that are essential to business continuity.
Guidance: Start by identifying your crown jewels — ask yourself: What systems, data, or people are essential for this company to operate? What would cause major disruption if lost or compromised? Do not limit this to just servers or machines — also consider critical data, key personnel, business processes, and third-party dependencies. Document these assets clearly and assign ownership.

**B: Crown jewels are identified.**
Gap: The most critical assets have been identified, but there is no structured assessment of the risks, vulnerabilities, or required protective measures. The current protection level may not be adequate.
Guidance: Once crown jewels are identified, organize a simple risk workshop with key stakeholders. Discuss potential threats (internal and external), current security measures, and whether these are sufficient. Based on this, decide which additional controls are needed (e.g., segmentation, enhanced monitoring, encryption, MFA, or backups). This doesn't have to be complex — start simple and expand over time.

**C: Yes, security measures are in effect to protect the 'crown jewels', addressing both internal and external threats.**
Gap: No gap.
Guidance: No guidance needed — this meets best practice. For continuous improvement, ensure regular reviews, testing, and validation of these protections (e.g., red teaming, tabletop exercises, or threat modeling).

---

## Q4: Are advanced access controls, like Multi-Factor Authentication (MFA) and Single Sign-On (SSO), implemented for email, core applications such as databases and other critical applications?

**A: No, they are limited or absent.**
Gap: Critical systems and applications are not protected with strong access controls. This increases the risk of credential theft, unauthorized access, and data breaches.
Guidance: MFA is a key security layer that should be implemented on all critical applications such as email, VPN, databases, and cloud services. It significantly reduces the risk of account takeover. Start by enabling MFA for Microsoft 365, Google Workspace, and other key systems.

**B: Yes, MFA is enforced for all users.**
Gap: MFA is in place, but there is no centralized access management, and users may still experience friction or use weaker authentication methods. SSO is not yet implemented.
Guidance: MFA alone is an important start but not always enough. Consider implementing stronger authentication methods such as FIDO2 hardware tokens. To improve user experience and reduce password fatigue, explore using Single Sign-On (SSO) for core applications. This enhances both usability and security.

**C: Yes, MFA is enforced for all users, and SSO is configured for core applications.**
Gap: No gap.
Guidance: No guidance needed — this aligns with best practices. For improvement, consider adaptive access controls, conditional access policies, and regular access reviews.

---

## Q5: Are all employees regularly trained in cyber security, including spam and phishing recognition?

**A: Hardly or not at all.**
Gap: There is no structured cybersecurity awareness training in place. Employees are not equipped to recognize phishing, spam, or other cyber threats, increasing the risk of human error and security incidents.
Guidance: A quick and effective starting point is to organize at least four training sessions per year, led by internal experts or board members, covering core cybersecurity topics such as Privacy Awareness, Secure Remote Work, Incident Response, and Company Policies. Use these sessions to share key lessons and update employees on new threats and procedures.

**B: They are, but it's haphazard.**
Gap: Training happens occasionally but is not consistent, mandatory, or measurable. Employees receive incomplete or irregular awareness sessions, and effectiveness is hard to assess.
Guidance: Consider implementing a structured e-learning program that includes cybersecurity awareness topics such as phishing, password hygiene, social engineering, and safe remote work. Choose a platform that can track progress, send periodic reminders, and run simulated phishing tests to measure awareness and improve engagement.

**C: Yes, we have a regular, obligatory program for all employees.**
Gap: No gap.
Guidance: No guidance needed — this meets good practice. For continuous improvement, consider hiring an external party to give a session on cyber security.

---

## Q6: Is data protection aligned with an established risk policy to ensure confidentiality, integrity and availability?

**A: No formal risk policy in place.**
Gap: There is no structured risk policy defining how confidentiality, integrity, and availability (CIA) of data should be protected. Responsibilities, risk acceptance, and documentation processes are unclear, leading to inconsistent decision-making.
Guidance: Begin by documenting a basic risk management policy. Include key elements such as: What is considered a risk? How is risk assessed? Who can accept or approve risks? Who is responsible for monitoring and documenting them? Ask guiding questions like: What data is most important to the business? What would happen if it became unavailable, altered, or leaked? Start small — simple written rules are better than none.

**B: A policy exists but it isn't consistently applied.**
Gap: There is a documented risk policy, but it is not actively used for decision-making. Data protection may not be prioritized based on business impact, leading to inconsistent safeguards.
Guidance: First, use your crown jewels as a starting point. Create a priority list of critical data, systems, and processes — rank them from most to least critical. Apply the risk policy to these assets first to ensure confidentiality, integrity, and availability are properly protected. Ensure documentation such as risk registers, data classification, and treatment plans are kept up-to-date and actually followed.

**C: We actively follow a formal policy.**
Gap: No gap.
Guidance: No guidance needed — this aligns with good practice. For further maturity, consider implementing continuous risk monitoring, automated data classification, and linking risk treatment to governance KPIs.

---

## Q7: Are there clear roles and responsibilities defined for protecting information?

**A: Lack of defined roles and responsibilities.**
Gap: There is no clear assignment of responsibilities for information protection. This leads to uncertainty about who owns key processes, which increases the risk of gaps, misunderstandings, or conflicting responsibilities.
Guidance: Compile a clear list of cyber and information security responsibilities (e.g., data protection, access control, incident response, risk management). Assign each responsibility to a specific role or person. Check if there are gaps (unassigned tasks) or overlaps (conflicting or duplicate responsibilities). Adjust roles where needed and ensure accountability is documented.

**B: Roles and responsibilities exist but lack consistent implementation.**
Gap: Responsibilities are documented but not consistently followed or enforced. Roles may be unclear in practice, not understood by stakeholders, or not integrated into daily operations.
Guidance: If this is not your highest-priority gap, address other critical issues first. To improve maturity in this area, make the roles more operational by documenting responsibilities in job descriptions, policies, and procedures. Communicate them across the organization, and ensure responsibilities are actively monitored, reviewed, and updated when roles change.

**C: Clearly defined roles and responsibilities in place.**
Gap: No gap.
Guidance: No guidance needed — this meets best practice. For further maturity, consider creating a development plan to help these employees enhance their skills and knowledge.

---

## Q8: Is there a designated individual responsible for timely updates, with established SLAs?

**A: No clear responsibilities or SLAs for updates.**
Gap: There is no designated owner for system updates, and no process or timelines for managing updates. This may lead to inconsistent patching, unmanaged risks, and potential security exposure.
Guidance: Maintenance without clear ownership can be risky, as quick fixes may compromise security. Define clear responsibilities for update and patch management. Assign ownership to internal staff or teams, and document expectations to ensure updates are performed securely, consistently, and with oversight.

**B: Responsibilities defined for some systems, but no SLAs.**
Gap: Some systems have responsible individuals, but there are no agreed service levels or timelines (SLAs) to ensure timely updates. As a result, critical updates may be delayed or inconsistently applied.
Guidance: For both internal teams and external vendors, define SLAs that specify timelines and requirements for updates, including security patches, critical fixes, and maintenance expectations. Define deliverables, security standards, and escalation paths if SLA timelines are not met.

**C: Responsibilities and SLAs defined for all systems.**
Gap: No gap.
Guidance: No guidance needed — this meets best practice. For further maturity, consider tracking SLA compliance, reporting on patch timelines, and using automated systems to monitor update status and security impact.

---

## Q9: To what extent have technical solutions been implemented to protect and defend systems and assets?

**A: Limited or no technical solutions in use.**
Gap: Critical systems and assets lack basic protective technologies, leaving the organization highly vulnerable to attacks, unauthorized access, and data loss.
Guidance: Start by implementing essential security technologies such as antivirus/anti-malware, firewall, email security, MFA, and encrypted backups. These foundational tools significantly improve baseline protection and should be centrally managed and monitored.

**B: Basic security features of existing products are activated.**
Gap: Some protections are enabled, but they are limited to default or basic settings. Advanced threat prevention, monitoring, and response capabilities are not used.
Guidance: Enable and configure more advanced features available within existing tools (e.g., endpoint detection, logging, MFA, vulnerability scanning). As threats become more sophisticated, consider implementing solutions like EDR, or security monitoring services to improve detection and response.

**C: Specific, advanced products are acquired and fully implemented.**
Gap: No gap.
Guidance: No guidance needed — this meets best practice. For continued maturity, consider integrating monitoring, automated response capabilities, and ensuring solutions remain up to date with evolving threats.

---

## Q10: Is your network equipped to promptly detect and respond to malicious activities?

**A: Not equipped.**
Gap: There are no tools or capabilities to detect or respond to malicious activities. This leaves the organization highly vulnerable to undetected attacks or ongoing compromise.
Guidance: Deploy basic protection tools across all systems, starting with a centrally managed antivirus/anti-malware solution. Ensure all endpoints are protected and regularly updated. This is a fundamental first step in improving detection capabilities.

**B: Basic antivirus in place.**
Gap: Basic protection exists but is limited to signature-based detection. No behavioral analysis, threat hunting, or active response capabilities are in place.
Guidance: Signature-based antivirus is no longer sufficient. Consider implementing an Endpoint Detection & Response (EDR) solution that also analyzes system behavior, detects abnormal activity, and provides alerts, automated containment, and response capabilities. This significantly improves threat detection and reaction time.

**C: Advanced endpoint detection and response (EDR) systems deployed.**
Gap: No gap.
Guidance: No guidance needed — this meets best practice. For further maturity, consider integrating EDR with centralized SIEM/SOC monitoring, automated response playbooks, and regular threat hunting exercises.

---

## Q11: How are security alerts from different systems handled?

**A: Infrequently or not at all.**
Gap: Security alerts are not actively monitored or reviewed. This creates a high risk that real threats go unnoticed, leading to delayed or missed incident response.
Guidance: Make alert handling a structured and regular process. Assign clear responsibility for monitoring and reviewing alerts (daily or weekly at minimum). Alerts are valuable only if someone actively looks at them and acts on them. Many organizations have security tools in place, but when alerts are ignored, it reduces protection and leaves the organization exposed.

**B: Managed by the IT department.**
Gap: Alerts are being monitored, but mainly by IT staff whose focus is infrastructure availability, not cyber threat detection. This may lead to missed or misinterpreted security signals due to lack of specialized expertise.
Guidance: Cybersecurity alert monitoring requires specialized skills in threat detection, event correlation, and attack analysis. Consider upskilling IT staff, assigning dedicated security responsibilities, or using external managed detection services (MDR/SOC) to improve effectiveness.

**C: Managed by the Security Operations Centre (SOC) monitoring team.**
Gap: No gap.
Guidance: No guidance needed — this meets best practice. For further maturity, ensure alerts are correlated across systems (EDR, firewall, identity, email, cloud), and that incident response playbooks are well-defined and regularly tested.

---

## Q12: In case of a cybersecurity incident outside regular office hours, do you have confidence that it will be handled appropriately?

**A: Hardly or not at all.**
Gap: There is no documented incident response plan, and responsibilities during off-hours are unclear. As a result, incidents that occur outside working hours may go unnoticed or unmanaged, leading to delayed recovery and increased impact.
Guidance: Create an Incident Response Plan (IRP) outlining the procedures, roles, and escalation paths during a cybersecurity incident — especially outside normal working hours. Define who is responsible, how incidents should be reported, and what communication channels should be used. Even a basic plan is better than no plan.

**B: An incident response plan is in place.**
Gap: A documented plan exists, but its effectiveness during off-hours is uncertain because it has not been tested or validated. Staff may not be fully familiar with their roles and escalation responsibilities.
Guidance: If an IRP is in place, it also needs to be tested. Conduct tabletop exercises where a realistic incident scenario is simulated, and the team discusses how they would respond. This helps validate roles, responsibilities, decision-making, and off-hours readiness. Update the plan based on lessons learned.

**C: An incident response plan is in place, and annual tests are conducted.**
Gap: No gap.
Guidance: No guidance needed — this meets best practice. For further maturity, consider 24/7 monitoring, managed detection and response (MDR), and including external stakeholders (legal, communications, management) in incident simulations.

---

## Q13: Do you have a clear understanding of past incidents and the actions taken to prevent their recurrence?

**A: I lack a current overview of past incidents.**
Gap: There is no structured overview or documentation of past incidents, and no process to analyze causes or monitor improvements, leading to repeated risks.
Guidance: Start by documenting all incidents in a simple Word or Excel log. Capture key details such as date, description, root cause, impact, and lessons learned. Use this to ensure that the organization evolves and learns from incidents instead of repeating the same mistakes.

**B: I occasionally hear about incidents.**
Gap: Incident information is shared informally, but inconsistent reporting and lack of awareness prevent proper analysis, learning, and improvement.
Guidance: Improve awareness and educate employees on the importance of reporting incidents through the proper channels. This helps the organization collect insights, track trends, and apply improvements based on real incidents.

**C: We frequently experience incidents, and I or our designated personnel are well-informed about most of them.**
Gap: No gap.
Guidance: No guidance needed — this meets best practice. For further maturity, consider doing structured post-incident reviews and tracking improvements over time.

---

## Q14: Do the individuals responsible for evaluating security alerts have the necessary knowledge and experience to do so effectively?

**A: I have low expectations regarding their expertise.**
Gap: There is a lack of necessary skills and knowledge to properly evaluate security alerts. This may result in missed threats, false assessments, or delayed responses.
Guidance: If expertise is limited internally, ensure that individuals handling alerts receive proper training in threat detection, incident analysis, and cybersecurity fundamentals. If internal capabilities cannot be developed sufficiently, consider outsourcing this responsibility to an external specialist.

**B: Alerts are reviewed, but automatic resolutions are common without further investigation.**
Gap: Alerts are being processed, but often dismissed or auto-resolved without proper investigation. Potential threats may remain undetected, allowing attackers to persist or escalate.
Guidance: Effective alert handling requires thorough investigation. Encourage analysts to look beyond automated recommendations and examine context such as source, behavior, and potential impact. Without proper investigation, threats may remain hidden and cause significant damage. If this cannot be handled adequately in-house, consider involving an external expert or managed security provider to support this function.

**C: Our specialists typically conduct thorough investigations when handling alerts.**
Gap: No gap.
Guidance: No guidance needed — this meets best practice. For further maturity, consider regular training, threat hunting exercises, and documenting alert investigation procedures.

---

## Q15: How confident are you that your business would recover quickly in the event of an incident right now?

**A: I have little to no confidence.**
Gap: There is no clear recovery plan or tested procedures. In a real incident, recovery would likely be slow, uncoordinated, and potentially incomplete.
Guidance: Develop a recovery plan based on your identified crown jewels (critical systems, data, and processes). Define recovery procedures, responsibilities, and priorities. In a high-stress situation, you don't want to figure things out — have clear, documented steps ready.

**B: Theoretically, it should be fine.**
Gap: There is a basic recovery plan, but it is not tested. Actual recovery capability is uncertain, and assumptions may be incorrect.
Guidance: Validate your recovery confidence by testing your backups and recovery procedures. Perform practical exercises or simulations to verify that recovery works as expected and that data, systems, and access can be restored within acceptable time frames.

**C: We regularly practice incidents, and our recovery time is known.**
Gap: No gap.
Guidance: No guidance needed — this meets best practice. For further maturity, consider measuring recovery performance, conducting realistic simulations (including off-hours), and improving recovery time objectives (RTO).
