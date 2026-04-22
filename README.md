<h1 align="center">Eye Security — AI Skills</h1>

<p align="center">
  <strong>Skills for AI agents, built by <a href="https://www.eye.security">Eye Security</a>.</strong>
</p>

---

## Available plugins

| Plugin | Description |
|--------|-------------|
| **[complisec](plugins/complisec/)** | EU compliance enforcement — NIS2, GDPR, ISO 27001 |
| **[supplychain](plugins/supplychain/)** | Supply-chain security for JavaScript projects — npm/pnpm/Yarn Berry hardening |

Each plugin has its own README with details and examples.

## Install

### Claude Code

```
/plugin marketplace add eyesecurity/skills
/plugin install <plugin-name>
```

### OpenAI Codex

Clone the repo — Codex reads `AGENTS.md` automatically:

```bash
git clone https://github.com/eyesecurity/skills.git
```

### Other agents (Cursor, Copilot, Windsurf, Cline)

Clone the repo, then tell your agent:

**"Read `plugins/<plugin-name>/SKILL.md` and follow its instructions."**

### Any AI chat (ChatGPT, Claude.ai, Mistral, Grok)

Download the plugin zip from [Releases](https://github.com/eyesecurity/skills/releases/latest), upload it to your chat, and say: **"Read SKILL.md and follow its instructions."**

## Need more?

[Eye Security](https://www.eye.security/en/contact/eu-regulations?utm_source=skills_eye_security&utm_medium=cta&utm_campaign=377720011-2026_Q2_proj-ai-compliance-skill&utm_content=eu_regulations_contact) helps EU organisations implement compliance end-to-end — from NIS2 readiness to managed detection and response.

## License

See [LICENSE](LICENSE).
