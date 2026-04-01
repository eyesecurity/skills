# Data Sensitivity — Pattern Index & Scanner Reference

## Classification tiers

| Tier | Examples | Handling | Regulatory basis |
|------|----------|----------|-----------------|
| **PUBLIC** | Published company info, open-source code | No special controls | — |
| **INTERNAL** | Project names, department names, business data | Basic access control | ISO 27001 A.5.12 |
| **CONFIDENTIAL** | Customer names, emails, IPs, DOB, financial personal data | Encryption, access control, audit logging | GDPR Art. 4, ISO 27001 A.5.13 |
| **RESTRICTED** | National IDs (BSN, SSN), health data, biometrics, credentials | DPIA required, encryption mandatory, strict access, breach notification | GDPR Art. 9, Art. 87, ISO 27001 A.5.34 |

## Regex pattern index

### RESTRICTED — always block on plaintext exposure

| Pattern | Category | GDPR | NIS2 | ISO 27001 |
|---------|----------|------|------|-----------|
| `bsn`, `ssn`, `national_id`, `rijksregisternummer`, `sozialversicherungsnummer`, `nino`, `codice_fiscale`, `nie`, `nif` | National identifier (multilingual EU) | Art. 87 | — | A.5.34 |
| `diagnosis`, `patient`, `medical_record`, `icd_code`, `anamnese`, `clinical`, `pathology`, `prescription`, `symptom` | Health data | Art. 9(1) | — | A.5.34 |
| `fingerprint`, `retina`, `biometric`, `facial_recognition`, `voice_print`, `iris_scan` | Biometric data | Art. 9(1) | — | A.5.34 |
| `genetic`, `dna`, `genome` | Genetic data | Art. 9(1) | — | A.5.34 |
| `ethnicity`, `religion`, `political_opinion`, `sexual_orientation`, `trade_union`, `vakbond` | Special category | Art. 9(1) | — | A.5.34 |
| `criminal`, `conviction`, `strafblad`, `vog`, `police_record` | Criminal data | Art. 10 | — | A.5.34 |
| `password`, `api_key`, `private_key`, `secret`, `token`, `client_secret`, `access_token`, `refresh_token` | Credentials | — | Art. 21(2)(h) | A.5.33, A.8.5 |
| `credit_card`, `pan`, `cvv`, `payment_card` | Payment card | — | — | A.5.34 (PCI DSS) |

### CONFIDENTIAL — encrypt, control access, log

Includes multilingual variants (NL/DE/FR) for EU-wide coverage.

| Pattern | Category | GDPR | ISO 27001 |
|---------|----------|------|-----------|
| `email`, `e_mail`, `phone`, `mobile`, `telefoon`, `telefon`, `gsm` | Contact data | Art. 4(1) | A.5.13 |
| `first_name`, `last_name`, `full_name`, `voornaam`, `achternaam`, `naam`, `vorname`, `nachname` | Identity | Art. 4(1) | A.5.13 |
| `address`, `street`, `postcode`, `city`, `adres`, `straat`, `woonplaats` | Location | Art. 4(1) | A.5.13 |
| `date_of_birth`, `dob`, `age`, `geboortedatum`, `geburtsdatum`, `leeftijd` | Demographics | Art. 4(1) | A.5.13 |
| `ip_address`, `mac_address`, `client_ip`, `remote_addr`, `user_agent` | Network identifiers | Art. 4(1), Recital 30 | A.5.13 |
| `iban`, `bank_account`, `salary`, `salaris`, `gehalt`, `income` | Financial personal | Art. 4(1) | A.5.13 |
| `cookie_id`, `device_id`, `session_id` | Online identifiers | Art. 4(1), Recital 30 | A.5.13 |
| `employee_id`, `staff_id`, `personeelsnummer` | Personnel identifiers | Art. 4(1) | A.5.13 |

### INTERNAL — basic access control

| Pattern | Category | ISO 27001 |
|---------|----------|-----------|
| `project_name`, `department`, `team` | Business data | A.5.12 |
| `internal_id`, `employee_id` | Internal references | A.5.12 |

## Scanner categories

| Category | Patterns | Default tier |
|----------|----------|-------------|
| `pii` | email, phone (EU), IPv4, date of birth | CONFIDENTIAL |
| `national_id` | BSN, IBAN, passport number | RESTRICTED |
| `credentials` | hardcoded password, API key, private key block, AWS key, connection string | RESTRICTED |
| `health` | medical terminology, ICD codes, patient references | RESTRICTED |
| `financial` | credit card numbers | CONFIDENTIAL–RESTRICTED |

## Scanned file types

**Source code**: `.py`, `.js`, `.ts`, `.java`, `.go`, `.rs`, `.rb`, `.php`, `.cs`
**Config**: `.json`, `.yaml`, `.yml`, `.toml`, `.ini`, `.env`, `.conf`, `.cfg`
**Docs**: `.md`, `.txt`, `.csv`, `.xml`
**Logs**: `.log`
**Infrastructure**: `Dockerfile`, `docker-compose.*`, `.tf`, `.hcl`

**Excluded**: Binary files, `node_modules/`, `.git/`, `vendor/`, `__pycache__/`, files > 10 MB.

## Prompt secret patterns

| Pattern | Severity | Example |
|---------|----------|---------|
| Passwords / passphrases | CRITICAL | `password = "hunter2"` |
| API keys / tokens | CRITICAL | `api_key = "sk-abc123..."` |
| Private key blocks | CRITICAL | `-----BEGIN RSA PRIVATE KEY-----` |
| AWS access keys | CRITICAL | `AKIA...` + secret key |
| Connection strings | CRITICAL | `postgres://user:pass@host/db` |
| GitHub / Slack tokens | CRITICAL | `ghp_...`, `xoxb-...` |
| Bearer / auth tokens | CRITICAL | `Authorization: Bearer eyJ...` |
| JWT tokens | HIGH | Full `eyJhbGciOi...` token |
| Generic secret assignments | HIGH | `secret = "long-value"` |
| National IDs (BSN, SSN) | CRITICAL | `bsn: 123456789` |
| Credit card numbers | CRITICAL | `4111 1111 1111 1111` |

## Remediation quick reference

| Finding | Action |
|---------|--------|
| Hardcoded credential | Move to secrets manager / env var |
| National ID in source | Remove, use tokenized reference |
| PII in logs | Mask/redact before logging |
| Health data in config | Encrypt at rest, restrict access |
| Password in prompt | Replace with `<PASSWORD>` placeholder |
| API key in prompt | Replace with `<API_KEY>`, rotate if sent externally |
| Private key in prompt | Never include, describe key type/issue instead |
| Connection string in prompt | Replace creds: `postgres://<USER>:<PASSWORD>@host/db` |
