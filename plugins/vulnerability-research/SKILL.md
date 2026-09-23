---
name: kitten-process
description: >
  ACTIVATE when the user asks to run the kitten process, or to analyse, assess,
  reverse engineer, or security-test a piece of software for vulnerabilities —
  an installer, binary, container image, appliance, firmware, or application.
  Drives a repeatable 12-step vulnerability research workflow from obtaining the
  target through mapping attack surface, reverse engineering, finding high-impact
  vulnerabilities, building a proof-of-concept, and writing a vendor advisory.
  Every step is documented to a KITTEN_<n>.md file so the assessment is auditable.
  For authorized security research and responsible disclosure only.
---

# The kitten process

> A repeatable method for taking an unknown piece of software and ending with a
> documented, high-impact vulnerability, a working proof-of-concept, and a vendor
> advisory — with every step written down as you go.

## Scope of use

This process is for authorized security research: software you own, software you have
written permission to test, or research aimed at responsible disclosure to the vendor.
If the intended target and authorization are unclear, ask the user to state them before
confirming a live attack surface (step 5) or exploiting a host (step 11) — those two
steps touch live systems and must stay inside an agreed scope.

## How to run it

Follow the steps in order. If a later step reveals information that would change the
findings of an earlier step, loop back to that step, update the corresponding
KITTEN_\<step number\>.md, and continue forward again from where you left off. Do not
skip a step silently — if a step does not apply (for example, no target host was provided
for step 5), record that and why.

## Documentation convention

For each step, document your findings in a KITTEN_\<step number\>.md file. These files
are the audit trail of the assessment — they let the user or a reviewer follow your
reasoning, reproduce your steps, and hand the result to the vendor. Keep entries factual
and specific (exact versions, file paths, offsets, endpoints), not narrative.

## The steps

When asked to use the kitten process to analyse a piece of software, follow these steps:

1. **Obtain the software**: Determine if you already have access to the software. If not, try to download it in the form of an installer, virtual machine or docker image. If you are unable to obtain the software, ask the user for help and pause and await user input. Document the version of the target software you have.
2. **Extract**: Extract the relevant parts of the program from the installer. This can include extracting executables, libraries, script files etc. If you are unable to extract the code, ask the user for help and pause and await user input. If the user has performed this step for you, you can skip it. Record software version, build date, target OS/arch, and any version strings found in binaries to your findings.
3. **Analyse architecture**: Determine what software stack is used. If software (like a common web server) is bundled, analyse the configuration of that component, not the component itself.
4. **Map the attack surface**: Analyse the external attack surface of the software. Focus on parts that are accessible via the network, unless the user has told you to focus on other attack vectors. We are interested in parts that are accessible to an attacker that has no previous access to secrets or credentials (unless hardcoded in the application).
5. **Confirm the attack surface**: If the user has provided an IP address of a target host, you may confirm the external attack surface with tools like nmap or curl. If not, you may skip this step. Only touch hosts that are in the authorized scope (see Scope of use).
6. **Reverse engineer**: Prepare to analyse the software by reverse engineering it. Only reverse engineer parts of software that are directly or indirectly exposed via the attack surface. If you can decompile the software, do it.
7. **Analyse authentication**: Analyse which parts of the software require authentication and how the mechanisms involved work.
8. **Improve analysis of the attack surface**: Using the reverse engineered code and knowledge of the authentication process, improve your knowledge of the attack surface and which parts are accessible without authentication.
9. **Find vulnerabilities**: Analyse the software for vulnerabilities. Focus on high impact vulnerabilities in unauthenticated components that can lead to remote code execution, arbitrary file read/write, injection vulnerabilities etc. Also try to find vulnerabilities that can bypass authentication or authorization. Also consider: memory corruption (if native code), deserialization, SSRF, path traversal, logic flaws in multi-step workflows, and hardcoded credentials/keys. If no high-impact vulnerabilities are found after thorough analysis, document findings with a summary of reviewed components and rationale for low risk assessment.
10. **Create proof-of-concept code**: Create a python script that can exploit the vulnerabilities. PoC should be self-contained, include error handling, and demonstrate impact clearly (e.g. print file contents, show command output).
11. **Confirm exploitation potential**: If the user provided you with an IP address of a target host and you have a PoC, use the proof-of-concept code to compromise the machine. Confirm you have privileged access to the application or remote code execution. Only run against hosts that are in the authorized scope.
12. **Create an advisory**: Per critical vulnerability, create an advisory with enough detail to supply to the vendor of the software. Include the affected component and version, a technical description, the proof-of-concept, the impact, and remediation guidance. The goal is responsible disclosure — helping the vendor fix the flaw.
