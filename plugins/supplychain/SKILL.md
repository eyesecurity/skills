---
name: supplychain
argument-hint: "[path]"
description: >
  Supply-chain security for JavaScript and Python projects — npm, pnpm, Yarn v2+, Bun,
  uv, pip, Poetry, pdm, and GitHub Actions CI. Router skill: detects which
  ecosystems a project uses and dispatches to the matching sub-skill under skills/.
  Read this first, then read only the sub-skill(s) the project actually needs.
---

# supplychain — router

## Important: installation vs usage

If you were asked to **install, clone, or set up** this plugin — finish the installation, confirm to the user, and stop. Do NOT run an audit during installation.

Audits run only when the user asks for one, either explicitly or by naming a sub-skill trigger.

## What this file is

A dispatcher. It contains no checks of its own. Its job is to send you to the sub-skill matching the ecosystem in front of you, so you load the right checks instead of defaulting to npm.

**On Claude Code**, `plugin.json` registers the sub-skills from `skills/` as slash commands. Invoke them directly and ignore this file:

- `/supplychain:npm-harden [path]`
- `/supplychain:bun-harden [path]`
- `/supplychain:pypi-harden [path]`
- `/supplychain:ci-audit [path]`

**On every other agent** — Codex, Cursor, Copilot, Windsurf, Cline, or any chat with the plugin zip uploaded — there are no slash commands. Run Step 1, then read the selected sub-skill's `SKILL.md` and follow it as written.

## Step 1 — detect ecosystems

Treat any argument as the project root; otherwise use cwd. Run as a single bash call. All checks are read-only.

```sh
echo "NPM=$([ -f package.json ] && echo PRESENT || echo ABSENT)"
echo "BUN=$(ls bun.lock bun.lockb 2>/dev/null | head -1 | grep -q . && echo PRESENT || echo ABSENT)"
echo "PYTHON=$(ls pyproject.toml requirements*.txt setup.py Pipfile 2>/dev/null | head -1 | grep -q . && echo PRESENT || echo ABSENT)"
echo "CI=$([ -d .github/workflows ] && echo PRESENT || echo ABSENT)"
```

## Step 2 — route

| Signal | Read | Scope |
|--------|------|-------|
| `NPM=PRESENT`, `BUN=ABSENT` | `skills/npm-harden/SKILL.md` | Local project config — npm, pnpm, Yarn v2+ |
| `BUN=PRESENT` | `skills/bun-harden/SKILL.md` | Local project config — Bun |
| `PYTHON=PRESENT` | `skills/pypi-harden/SKILL.md` | Local project config — uv, pip / pip-tools, Poetry, pdm |
| `CI=PRESENT` | `skills/ci-audit/SKILL.md` | How either manager is invoked in GitHub Actions, plus generic Actions hardening |

Routing rules:

- **`BUN=PRESENT`** — read `bun-harden`, not `npm-harden`. Both ecosystems sit behind a `package.json`, but the managers differ in every checked detail: Bun counts its release age in seconds, gates lifecycle scripts through a trusted-dependency allowlist rather than a flag, and may carry a binary lockfile. `npm-harden` has no Bun branch and would report a hardened Bun project as unconfigured.
- **One ecosystem** — read that one sub-skill. Do not read the others; their checks do not apply and their findings would be noise.
- **`CI=PRESENT`** — `ci-audit` applies *in addition to* any local audit, never instead of it. It covers CI invocation surface; the harden skills cover committed project config. It detects npm and Python independently, so it needs no ecosystem hint.
- **Both `NPM` and `PYTHON` present** (monorepo) — run the JavaScript skill (`npm-harden` or `bun-harden`, per the rule above), then `pypi-harden`, then `ci-audit` if applicable. Emit each as its own report under its own heading. Do not merge or de-duplicate findings across sub-skills; each ladder stands alone.
- **All `ABSENT`** — report that no JavaScript or Python project was found at the given path and stop. Do not guess at findings or audit a directory that has neither.

## Output grammar

Every sub-skill in this plugin shares one format, so multi-skill reports read the same:

- 🚨 CRITICAL — unpatched CVE in installed tooling, scripts-on-by-default, lockfile gitignored, release-age gate inactive, credentials committed
- 🔶 FAIL — real gap needing a code or process fix
- ⚠️ WARN — hardening opportunity, not immediately exploitable
- ✅ PASS — clean, shown last
- ➖ N/A — procedural notes

Fix lines use `└─ <file>: <exact value>` with no backticks — backticks render literally in some output panes and add noise.

The sub-skill you read is authoritative for finding wording. Copy its finding text verbatim; do not paraphrase, shorten, or recombine incident examples from this file.

**Hard stop:** output ends at the last ✅ or ➖ line. Never append patch files, YAML blocks, config summaries, or "want me to apply?" prompts.

## Not implemented

`postinstall-scan`, `npmrc-secrets`, and `aliases-overrides` appear in `README.md` as roadmap only — there is no SKILL.md for them. If a user asks for one, say it is planned and stop. Do not improvise its checks under this plugin's name.
