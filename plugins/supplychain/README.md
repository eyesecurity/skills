<p align="center">
  <img src="https://img.shields.io/badge/npm-hardened-green?style=flat-square" alt="npm" />
  <img src="https://img.shields.io/badge/pnpm-hardened-green?style=flat-square" alt="pnpm" />
  <img src="https://img.shields.io/badge/Yarn%20v2%2B-hardened-green?style=flat-square" alt="Yarn v2+" />
</p>

<h1 align="center">supplychain</h1>

<p align="center">
  <strong>Supply-chain security for JavaScript projects.</strong><br>
  Hardens npm, pnpm, and Yarn v2+ against 2025-2026 attack patterns (Shai-Hulud, chalk/debug, Axios).
</p>

---

## What is supplychain?

A growing set of skills that audit and harden JavaScript projects against dependency-chain attacks — package manager config, version pinning, lockfile hygiene, lifecycle scripts, and GitHub Actions CI pipeline surface.

## What to expect

| You say | supplychain does |
|---------|------------------|
| `/npm-harden` | Audits the current project's package manager config and outputs a prioritised fix list (CRITICAL → HARDENING → PASSING) |
| `/npm-harden ./apps/web` | Same, against a specific project root |
| `/npm-ci-audit` | Audits how npm/pnpm/Yarn is invoked in `.github/workflows/**` — install flags, registry override, manager version drift, OIDC publish, `npx` surface, plus generic Actions hardening |
| `/npm-ci-audit ./repo` | Same, against a specific repo root |

## Install

See the [eyesecurity/skills README](../../README.md) for installation instructions across all platforms.

## Skills

| Skill | Trigger | Scope | Status |
|-------|---------|-------|--------|
| **npm-harden** | `/npm-harden [path]` | Local project config — npm, pnpm, Yarn v2+ | shipped |
| **npm-ci-audit** | `/npm-ci-audit [path]` | npm/pnpm/Yarn supply chain **in GitHub Actions** — install flags, registry integrity, manager version consistency, OIDC + provenance, uncontrolled surface (`npx` / global installs), Dependabot npm. Plus generic Actions hardening (external action SHA pinning, permissions, `pull_request_target`). | shipped |
| *postinstall-scan* | `/postinstall-scan` | `package.json.scripts` + transitive lifecycle hooks (curl\|sh, eval, base64) | planned |
| *npmrc-secrets* | `/npmrc-secrets` | Committed auth tokens in `.npmrc` | planned |
| *aliases-overrides* | `/aliases-overrides` | npm aliases, `overrides` / `resolutions` / `pnpm.overrides` | planned |

Planned skills are documented to signal roadmap. No empty directories, no broken slash commands.

## Output grammar (for contributors)

All skills in this plugin share one output format so multi-skill reports read the same:

- 🚨 CRITICAL — unpatched CVE in installed tooling, scripts-on-by-default, lockfile gitignored, release-age gate inactive, credentials committed
- 🔶 FAIL — real gap needing a code or process fix
- ⚡ WARN — hardening opportunity, not immediately exploitable
- ✅ PASS — clean, shown last
- ➖ N/A — procedural notes

Fix lines use `└─ <file>: <exact value>` (no backticks, renders everywhere). Output **hard-stops after `✅ PASSING`** — never emit patch files, YAML blocks, or "want me to apply?" prompts.

## Plugin structure

```
supplychain/
├── README.md                     # This file
├── .claude-plugin/
│   └── plugin.json               # Claude Code plugin manifest
└── skills/
    ├── npm-harden/
    │   └── SKILL.md              # Local project hardening
    └── npm-ci-audit/
        └── SKILL.md              # GitHub Actions CI hardening
```

## License

See [LICENSE](../../LICENSE).
