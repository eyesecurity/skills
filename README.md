<h1 align="center">Eye Security — AI Skills</h1>

<p align="center">
  <strong>Skills for AI agents, built by <a href="https://www.eye.security">Eye Security</a>.</strong>
</p>

---

## Available plugins

| Plugin | Description | Details |
|--------|-------------|---------|
| **[complisec](plugins/complisec/)** | EU compliance enforcement — NIS2, GDPR, ISO 27001 | [README](plugins/complisec/README.md) |

## Install

### Claude Code

Add the Eye Security marketplace, then install the plugin you need:

```
/plugin marketplace add eyesecurity/skills
/plugin install complisec
```

Or clone locally:

```bash
git clone https://github.com/eyesecurity/skills.git
# Then in Claude Code:
/plugin marketplace add ./skills
/plugin install complisec
```

### OpenAI Codex

Clone the repo into your project — Codex reads `AGENTS.md` automatically from the project root:

```bash
git clone https://github.com/eyesecurity/skills.git
```

### Other agents (Cursor, Copilot, Windsurf, Cline)

Clone the repo into your project, then point your agent at the plugin:

```bash
git clone https://github.com/eyesecurity/skills.git
```

Say: **"Read `plugins/complisec/SKILL.md` and follow its instructions."**

### Any AI chat (ChatGPT, Claude.ai, Mistral, Grok)

1. Download [complisec.zip](https://github.com/eyesecurity/skills/releases/latest/download/complisec.zip)
2. Upload the ZIP to your AI chat
3. Say: **"Read SKILL.md and follow its instructions."**

## Repo structure

```
skills/                               # eyesecurity/skills
├── README.md                         # This file
├── AGENTS.md                         # OpenAI Codex entrypoint
├── .claude-plugin/
│   └── marketplace.json              # Eye Security plugin marketplace
└── plugins/
    └── complisec/                    # EU compliance enforcement
        ├── README.md
        ├── SKILL.md
        ├── .claude-plugin/
        │   └── plugin.json
        ├── skills/
        └── .compliance/
```

## Need more?

Get expert guidance alongside the tools. [Eye Security](https://www.eye.security/en/contact/eu-regulations?utm_source=skills_eye_security&utm_medium=cta&utm_campaign=377720011-2026_Q2_proj-ai-compliance-skill&utm_content=eu_regulations_contact) helps EU organisations implement compliance end-to-end — from NIS2 readiness to managed detection and response.

[Talk to our team →](https://www.eye.security/en/contact/eu-regulations?utm_source=skills_eye_security&utm_medium=cta&utm_campaign=377720011-2026_Q2_proj-ai-compliance-skill&utm_content=eu_regulations_contact)

## License

MIT
