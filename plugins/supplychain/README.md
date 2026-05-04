<p align="center">
  <img src="https://img.shields.io/badge/npm-hardened-green?style=flat-square" alt="npm" />
  <img src="https://img.shields.io/badge/pnpm-hardened-green?style=flat-square" alt="pnpm" />
  <img src="https://img.shields.io/badge/Yarn%20v2%2B-hardened-green?style=flat-square" alt="Yarn v2+" />
  <img src="https://img.shields.io/badge/PyPI-hardened-blue?style=flat-square" alt="PyPI" />
  <img src="https://img.shields.io/badge/uv-hardened-blue?style=flat-square" alt="uv" />
  <img src="https://img.shields.io/badge/Poetry-hardened-blue?style=flat-square" alt="Poetry" />
</p>

<h1 align="center">supplychain</h1>

<p align="center">
  <strong>Supply-chain security for JavaScript and Python projects.</strong><br>
  Protects the npm supply chain (npm, pnpm, Yarn v2+) and the PyPI supply chain (uv, pip, Poetry, pdm) — at the project level and in GitHub Actions CI.
</p>

---

## What is supplychain?

A growing set of skills that audit and harden JavaScript and Python projects against dependency-chain attacks — package manager config, version pinning, lockfile hygiene, install-time code execution, release-age cooldown, and GitHub Actions CI pipeline surface.

## What to expect

| You say | supplychain does |
|---------|------------------|
| `/supplychain:npm-harden` | Audits the current project's npm/pnpm/Yarn config and outputs a prioritised fix list (CRITICAL → HARDENING → PASSING) |
| `/supplychain:npm-harden ./apps/web` | Same, against a specific project root |
| `/supplychain:pypi-harden` | Audits the current project's uv/pip/Poetry/pdm config — release-age gate, lockfile + hash hygiene, sdist policy, index integrity, exotic sources |
| `/supplychain:pypi-harden ./services/api` | Same, against a specific project root |
| `/supplychain:ci-audit` | Audits how npm and Python package managers are invoked in `.github/workflows/**` — install flags, registry override, manager version drift, OIDC publish + provenance / PEP 740 attestations, `npx` / `pipx` / `curl\|sh` surface, plus generic Actions hardening |
| `/supplychain:ci-audit ./repo` | Same, against a specific repo root |

## Install

See the [eyesecurity/skills README](../../README.md) for installation instructions across all platforms.

## Skills

| Skill | Trigger | Scope | Status |
|-------|---------|-------|--------|
| **npm-harden** | `/supplychain:npm-harden [path]` | Local project config — npm, pnpm, Yarn v2+ | shipped |
| **pypi-harden** | `/supplychain:pypi-harden [path]` | Local project config — uv, pip / pip-tools, Poetry, pdm. Release-age gate (uv `exclude-newer`, pip 26.1 `--uploaded-prior-to=P7D`), lockfile + hash hygiene (PEP 751 `pylock.toml`, `--require-hashes`), sdist policy, dependency-confusion mitigations, exotic sources. | shipped |
| **ci-audit** | `/supplychain:ci-audit [path]` | npm and PyPI supply chain **in GitHub Actions** — install flags, registry integrity, manager version consistency, OIDC + provenance / PEP 740 attestations, uncontrolled surface (`npx` / `pipx` / `uvx` / `curl\|sh` / global installs), Dependabot npm + pip. Plus generic Actions hardening (external action SHA pinning, permissions, `pull_request_target`). | shipped |
| *postinstall-scan* | `/postinstall-scan` | `package.json.scripts` + transitive lifecycle hooks; Python `__init__.py` import-time exec patterns (curl\|sh, eval, base64) | planned |
| *npmrc-secrets* | `/npmrc-secrets` | Committed auth tokens in `.npmrc`, `.netrc`, `pip.conf`, `poetry.toml` | planned |
| *aliases-overrides* | `/aliases-overrides` | npm aliases / `overrides` / `resolutions` / `pnpm.overrides`; Python `[tool.uv.sources]` / Poetry `source = ` overrides | planned |

Planned skills are documented to signal roadmap. No empty directories, no broken slash commands.

## Output grammar (for contributors)

All skills in this plugin share one output format so multi-skill reports read the same:

- 🚨 CRITICAL — unpatched CVE in installed tooling, scripts-on-by-default, lockfile gitignored, release-age gate inactive, credentials committed
- 🔶 FAIL — real gap needing a code or process fix
- ⚠️ WARN — hardening opportunity, not immediately exploitable
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
    │   └── SKILL.md              # Local project hardening — npm/pnpm/Yarn
    ├── pypi-harden/
    │   └── SKILL.md              # Local project hardening — uv/pip/Poetry/pdm
    └── ci-audit/
        └── SKILL.md              # GitHub Actions CI hardening — npm + PyPI
```

## License

See [LICENSE](../../LICENSE).
