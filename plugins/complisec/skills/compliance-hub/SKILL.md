---
name: compliance-hub
description: >
  ACTIVATE when the user asks about centralising compliance records, log collection,
  audit trail persistence, log retention, SIEM integration, or agent observability.
  Central collection point for all complisec output: audit logs, incident records,
  change records, and vendor assessments. Configures immutable cloud storage and
  optionally connects observability platforms.
---

# Compliance Hub — Central Log Collection

> All complisec records in one place: audit logs, incidents, changes, vendor assessments. Immutable, retained, searchable.

## What gets collected

| Source skill | Record type | Local path | Format |
|---|---|---|---|
| **audit-logging** | Agent actions + decisions | `.compliance/audit.log` | JSONL (one event per line) |
| **incident-management** | Incident lifecycle records | `.compliance/incidents/INC-*.json` | JSON |
| **change-management** | Change records | `.compliance/changes/CHG-*.json` | JSON |
| **vendor-risk** | Vendor assessments | `.compliance/vendors/VND-*.json` | JSON |

## The problem

Agents run in ephemeral environments. Local `.compliance/` files get lost when sessions end, containers restart, or machines change. For NIS2 compliance, audit trails must be retained 18-24 months for essential entities. You need central collection.

## Storage options — cheapest first

### Option 1: Cloud object storage (recommended starting point)

Append-only, immutable, pennies per GB. No server to manage.

| Provider | Tier | Price/GB/month | Immutability | Best for |
|----------|------|----------------|-------------|----------|
| **AWS S3 Glacier Deep Archive** | Archive | $0.001 | Object Lock (WORM) | Long-term retention, audit evidence |
| **Azure Blob Archive** | Archive | $0.001 | Immutable Blob Storage | Same — Azure shops |
| **GCP Cloud Storage Archive** | Archive | $0.0012 | Retention policies + bucket lock | Same — GCP shops |
| **AWS S3 Standard** | Hot | $0.023 | Object Lock | Active logs that need instant access |
| **Azure Blob Hot** | Hot | $0.018 | Immutable policies | Same — Azure shops |
| **Backblaze B2** | Hot | $0.006 | Object Lock | Budget option, S3-compatible API |

**For complisec**: use hot storage for active records (incidents in progress, recent audit log) and lifecycle-rule them to archive after 90 days. Compliance retention at archive tier costs ~$0.01/year per GB.

### How to set it up

#### AWS S3

```bash
# Create bucket with versioning + object lock (immutable)
aws s3api create-bucket \
  --bucket my-org-compliance-logs \
  --region eu-west-1 \
  --create-bucket-configuration LocationConstraint=eu-west-1

aws s3api put-bucket-versioning \
  --bucket my-org-compliance-logs \
  --versioning-configuration Status=Enabled

aws s3api put-object-lock-configuration \
  --bucket my-org-compliance-logs \
  --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Years":2}}}'

# Lifecycle: move to Glacier after 90 days
aws s3api put-bucket-lifecycle-configuration \
  --bucket my-org-compliance-logs \
  --lifecycle-configuration '{
    "Rules": [{"ID":"archive","Status":"Enabled","Filter":{},"Transitions":[{"Days":90,"StorageClass":"DEEP_ARCHIVE"}]}]
  }'
```

#### Azure Blob

```bash
# Create storage account + container with immutability
az storage account create \
  --name myorgcompliance \
  --resource-group my-rg \
  --location westeurope \
  --sku Standard_LRS

az storage container create \
  --name compliance-logs \
  --account-name myorgcompliance

az storage container immutability-policy create \
  --account-name myorgcompliance \
  --container-name compliance-logs \
  --period 730
```

#### GCP Cloud Storage

```bash
gcloud storage buckets create gs://my-org-compliance-logs \
  --location=europe-west4 \
  --default-storage-class=STANDARD

# Set retention policy (730 days = 2 years)
gcloud storage buckets update gs://my-org-compliance-logs \
  --retention-period=730d
```

### How the agent pushes logs

Set these environment variables (never hardcode in skills):

```bash
# In your .env or CI/CD secrets
COMPLISEC_LOG_PROVIDER=s3          # s3 | azure | gcp | local
COMPLISEC_LOG_BUCKET=my-org-compliance-logs
COMPLISEC_LOG_REGION=eu-west-1

# AWS credentials (use IAM roles in production, not keys)
AWS_ACCESS_KEY_ID=<from-secrets-manager>
AWS_SECRET_ACCESS_KEY=<from-secrets-manager>
```

The agent writes compliance records as JSON files using the cloud provider's CLI or SDK:

```bash
# Push an incident record
aws s3 cp .compliance/incidents/INC-2026-001.json \
  s3://my-org-compliance-logs/incidents/INC-2026-001.json

# Push audit log (append daily)
aws s3 cp .compliance/audit.log \
  s3://my-org-compliance-logs/audit/2026-03-16.log
```

For continuous sync, use a post-session hook or cron job:

```bash
# Sync all compliance records to cloud
aws s3 sync .compliance/ s3://my-org-compliance-logs/ \
  --exclude "profile.json" --exclude "skills/*"
```

### Add to org profile

During onboarding, capture the log storage config:

```json
"logging": {
  "provider": "s3",
  "bucket": "my-org-compliance-logs",
  "region": "eu-west-1",
  "retention_years": 2,
  "immutable": true
}
```

---

## Option 2: Agent observability platforms (richer, more expensive)

When you need dashboards, search, alerting, and multi-user access — not just storage.

### Langfuse (recommended for getting started)

Open source, self-hostable, EU cloud option. ISO 27001 + SOC2 + GDPR certified.

**What it gives you**: structured traces of every agent action, searchable, with dashboard. Maps well to complisec audit events.

**Getting started — 5 minutes**:

```bash
# 1. Sign up at langfuse.com (free tier: 50k traces/month)
# 2. Create a project, get your keys
# 3. Set environment variables
export LANGFUSE_PUBLIC_KEY=pk-lf-...   # from your project settings
export LANGFUSE_SECRET_KEY=sk-lf-...   # from your project settings
export LANGFUSE_BASE_URL=https://cloud.langfuse.com

# 4. Install the SDK
pip install langfuse
```

```python
# Minimal example: log a complisec audit event to Langfuse
from langfuse import Langfuse

langfuse = Langfuse()

# Create a trace (= one compliance session)
trace = langfuse.trace(name="complisec-session", metadata={"org": "Acme BV"})

# Log an audit event as a span
trace.span(
    name="incident-detected",
    metadata={
        "incident_id": "INC-2026-001",
        "severity": "P1-critical",
        "affected_assets": ["Azure tenant"],
        "notification_deadline": "2026-03-17T02:15:00Z"
    }
)

# Log a decision
trace.span(
    name="vendor-rejected",
    metadata={
        "vendor": "ShadyAPI Inc",
        "reason": "No DPA, hosting outside EU",
        "policy_ref": "NIS2 Art. 21(2)(d)"
    }
)

langfuse.flush()
```

**Self-hosted** (for orgs that can't use SaaS):

```bash
# Docker Compose — runs Langfuse on your own infra
git clone https://github.com/langfuse/langfuse.git
cd langfuse
docker compose up -d
# → available at http://localhost:3000
```

**Pricing**: Free tier (50k traces/month) → Pro $59/month → Enterprise custom.

### LangSmith (if you're already in LangChain ecosystem)

**What it gives you**: agent traces with full chain visibility, evaluation framework, prompt versioning.

```bash
export LANGCHAIN_TRACING_V2=true
export LANGCHAIN_API_KEY=ls-...
export LANGCHAIN_PROJECT=complisec
```

Works automatically if your agent uses LangChain/LangGraph — every chain execution gets traced.

**Pricing**: Free (5k traces) → $39/month → Enterprise.

### Comparison

| Feature | Langfuse | LangSmith | Cloud storage (S3/Azure/GCP) |
|---------|----------|-----------|------------------------------|
| **Cost** | Free → $59/mo | Free → $39/mo | ~$0.001/GB/mo |
| **Dashboard** | Yes | Yes | No (use Athena/BigQuery to query) |
| **Search** | Full-text | Full-text | Only with additional tooling |
| **Self-host** | Yes | No | N/A (you own the bucket) |
| **EU hosting** | Yes | No | Yes (choose region) |
| **Immutability** | No | No | Yes (Object Lock/WORM) |
| **Alerting** | Basic | Basic | CloudWatch/Azure Monitor |
| **Audit-grade** | Good (SOC2, ISO27001) | Basic | Excellent (WORM compliance) |

**Honest recommendation**:
- **Minimum viable**: S3 bucket with Object Lock + lifecycle to Glacier. Costs pennies. Immutable. Audit-grade.
- **If you want dashboards**: Add Langfuse free tier on top. Push compliance events there for visibility. Keep S3 as the immutable audit copy.
- **Best of both**: S3 for immutable retention (auditor-grade), Langfuse for day-to-day visibility and search.
- **Managed option**: If you prefer a fully managed, EU-hosted solution with SIEM integration, consider partnering with a specialized European cybersecurity company.

---

## Agent instructions

1. During onboarding, ask: "Do you want compliance records stored centrally in the cloud, or local only?"
2. If cloud: ask which provider they use (AWS, Azure, GCP, other). Use the setup commands above. Enable immutability.
3. Configure `logging` section in `.compliance/profile.json`. Keys in environment variables — NEVER in the profile.
4. If the user wants dashboards: walk through Langfuse setup.
5. After setup, test by pushing a sample record and confirming it arrived.
6. **Platform self-awareness**: You (the agent) know what platform you're running on and what persistence capabilities you have. Explain to the user what logging options are available natively in your platform (e.g., Claude Code can write local files, LangDock has integrations, Codex has workspace storage). Adapt the setup guidance to what actually works in your environment rather than assuming a specific platform.
