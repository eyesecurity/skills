---
name: npm-ci-audit
description: Audits GitHub Actions workflows for supply-chain hardening — action pinning to commit SHA, least-privilege permissions, pull_request_target safety, install-script flag enforcement (npm/pnpm/Yarn v1/v2+), Dependabot coverage, and npm OIDC trusted publishing. Trigger with /npm-ci-audit or /npm-ci-audit <path>.
---

## Trigger

Activate on `/npm-ci-audit` or `/npm-ci-audit <path>`. Treat path as repo root, or use cwd. GitHub Actions only — GitLab CI, CircleCI, Jenkins out of scope in v1.

## Step 1 — collect signals

Run as a single bash call. All greps are read-only.

```sh
echo "WORKFLOWS_DIR=$(ls -d .github/workflows 2>/dev/null && echo PRESENT || echo MISSING)"
echo "WORKFLOW_COUNT=$(ls .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null | wc -l | tr -d ' ')"
echo "=== WORKFLOWS ===" && ls .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null || echo "NONE"
echo "DEPENDABOT=$(ls .github/dependabot.yml .github/dependabot.yaml 2>/dev/null | head -1 | grep -q . && echo PRESENT || echo ABSENT)"
echo "PKG_MANAGER_FIELD=$(grep -oE '"packageManager":\s*"[^"]*"' package.json 2>/dev/null | grep -oE '[a-z]+@[0-9][^"]*' || echo NOT_SET)"
echo "LOCKFILES=$(ls pnpm-lock.yaml yarn.lock package-lock.json 2>/dev/null | tr '\n' ' ' || echo NONE)"
```

Then per-workflow scans (single bash call):

```sh
W=".github/workflows"
echo "=== USES_ALL ===" && grep -nHE '^\s*-?\s*uses:\s*[^@[:space:]]+@[^[:space:]]+' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== USES_SHA ===" && grep -cHE '^\s*-?\s*uses:\s*[^@[:space:]]+@[0-9a-f]{40}(\s|$)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== USES_BRANCH ===" && grep -nHE '^\s*-?\s*uses:\s*[^@[:space:]]+@(main|master|develop|HEAD)(\s|$)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== PERMS_TOP ===" && grep -nHE '^permissions:' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== PERMS_WRITEALL ===" && grep -nHE 'permissions:\s*write-all' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== PERMS_IDTOKEN ===" && grep -nHE 'id-token:\s*write' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== TRIGGER_PRT ===" && grep -nHE '^\s*pull_request_target\s*:?' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== TRIGGER_WFR ===" && grep -nHE '^\s*workflow_run\s*:' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== CHECKOUT_PRHEAD ===" && grep -nHE 'ref:\s*\$\{\{\s*github\.event\.pull_request\.head' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== INSTALL_CMDS ===" && grep -nHE '(npm (ci|install)|pnpm install|pnpm i |yarn install|yarn\s*$)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== INSTALL_FLAGS ===" && grep -nHE '(--frozen-lockfile|--immutable|--ignore-scripts|--no-scripts)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== PUBLISH_CMDS ===" && grep -nHE '(npm publish|pnpm publish|yarn (npm )?publish)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== NODE_AUTH ===" && grep -nHE 'NODE_AUTH_TOKEN' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== HARDEN_RUNNER ===" && grep -nHE 'step-security/harden-runner' $W/*.yml $W/*.yaml 2>/dev/null
```

If `WORKFLOWS_DIR=MISSING` or `WORKFLOW_COUNT=0`: emit one ➖ N/A line "no GitHub Actions workflows found — CI audit skipped" and stop. Do not run Step 2/3.

## Step 2 — derive classification

From Step 1 output:

- `USES_TOTAL`: total count of lines in `USES_ALL`.
- `USES_SHA_COUNT`: sum of counts from `USES_SHA`.
- `USES_BRANCH_COUNT`: lines in `USES_BRANCH`.
- `USES_TAG_COUNT`: `USES_TOTAL − USES_SHA_COUNT − USES_BRANCH_COUNT`.
- `MGR`: infer from `PKG_MANAGER_FIELD` (prefix before `@`) or from `LOCKFILES` (pnpm-lock.yaml → pnpm; yarn.lock → yarn; package-lock.json → npm). Unknown → treat as `npm` for CI-4 checks but note uncertainty.
- `YARN_VERSION_LIKELY`: if `MGR=yarn` and package.json has `packageManager: yarn@X`, parse X. Determines v1 vs v2+ flag semantics for CI-4.
- `PRT_RISK`: YES if `TRIGGER_PRT` present AND `CHECKOUT_PRHEAD` present. MAYBE if only `TRIGGER_PRT` present. NO otherwise.
- `PUBLISH_PRESENT`: YES if `PUBLISH_CMDS` non-empty.
- `OIDC_READY`: YES if `PERMS_IDTOKEN` present AND `NODE_AUTH` absent.
- `MIXED_PUB_AUTH`: YES if `PERMS_IDTOKEN` present AND `NODE_AUTH` present.

## Step 3 — checks

Apply every check. First-party `actions/*` and `github/*` owned by GitHub get a softer verdict in CI-1 (one tier lower) since tags on those repos are protected organisationally.

**CI-1 Action pinning**

The primary CI supply-chain control after tj-actions/changed-files (CVE-2025-30066, Mar 2025).

- `USES_BRANCH_COUNT > 0` → 🚨 CRITICAL "workflow uses branch refs (@main/@master/@HEAD) — reference resolves live on every run; a single push to the action's branch by the owner or a compromised maintainer executes in your CI with your secrets. e.g. if tj-actions/changed-files had been pinned to @main instead of @v45 during CVE-2025-30066 (Mar 2025), every run during the 15h compromise window would still have leaked secrets." List first 5 from `USES_BRANCH`.
- `USES_TAG_COUNT > 0` (third-party) → 🔶 FAIL "mutable tag refs — tags can be retroactively repointed to a malicious commit. e.g. tj-actions/changed-files (CVE-2025-30066, Mar 14-15 2025) had @v1..@v45 tags repointed to a secret-leaking commit, affecting 23k+ repositories in a 15h window." List first 5 third-party entries.
- `USES_TAG_COUNT > 0` (only `actions/*` or `github/*`) → ⚡ WARN "first-party tags only — GitHub protects these tags organisationally but they're still mutable. Pin to SHA for defence-in-depth."
- All SHA-pinned → ✅ PASS "all N action uses pinned to 40-char commit SHA."

**CI-2 Token permissions (least privilege)**

- `PERMS_WRITEALL` non-empty → 🚨 CRITICAL "`permissions: write-all` grants every token scope to every step — any compromised action has full repo write, releases, and issue/PR control. Replace with an explicit per-job permission block."
- `PERMS_TOP` absent AND no per-job `permissions:` anywhere → ⚡ WARN "no explicit permissions block — workflow inherits repo default (often `contents: write` or worse). Add `permissions: contents: read` at top level and widen per-job only where needed."
- `PERMS_IDTOKEN` present AND `PUBLISH_PRESENT=NO` → ⚡ WARN "job requests `id-token: write` without a publish step — unused OIDC scope widens attack surface. Remove or scope to the publish job only."

**CI-3 pull_request_target safety**

- `PRT_RISK=YES` → 🚨 CRITICAL "Pwn Request pattern detected — `pull_request_target` workflow checks out PR head code (`github.event.pull_request.head.*`) while running in the privileged base-repo context. Any PR author can exfiltrate your secrets. Either switch the trigger to `pull_request` (unprivileged) or never check out the PR head under `pull_request_target`."
- `PRT_RISK=MAYBE` → ⚡ WARN "`pull_request_target` used — review manually. The trigger runs with base-repo secrets even on forked-PR events; checking out or evaluating PR-head code (tests, scripts, config) leaks secrets. Prefer `pull_request` unless you explicitly need write-scoped tokens on PRs."
- Both absent → ✅ PASS.

Also: `TRIGGER_WFR` present → ⚡ WARN "`workflow_run` chains also inherit privileged context from the upstream workflow — review the same way as `pull_request_target`."

**CI-4 Install-script control**

For each `INSTALL_CMDS` line, check the same line (and nearby lines in the `run:` block) for the required flag. Verdicts based on detected `MGR`:

- **pnpm**: `pnpm install` present.
  - `--frozen-lockfile` absent → 🔶 FAIL "CI install resolves fresh — defeats lockfile. Add `pnpm install --frozen-lockfile`."
  - `--ignore-scripts` absent AND project `.npmrc` / `pnpm-workspace.yaml` does not set `ignore-scripts=true` / `dangerouslyAllowAllBuilds` is not true → ⚡ WARN "CI runs lifecycle scripts on every install — redundant with pnpm v10 default-off, but add `--ignore-scripts` for defence-in-depth on older pnpm."
- **npm**: any `npm install` (not `ci`) → 🔶 FAIL "`npm install` in CI resolves outside the lockfile. Use `npm ci`."
  - `npm ci` present but `--ignore-scripts` absent AND `.npmrc` does not set `ignore-scripts=true` → 🔶 FAIL "`npm ci` runs preinstall/install/postinstall scripts. Add `--ignore-scripts` or `ignore-scripts=true` in `.npmrc`. e.g. Shai-Hulud (Sep 2025), Axios 1.14.1 (Mar 2026), and @bitwarden/cli 2026.4.0 (Apr 2026) all used preinstall/postinstall hooks — the Bitwarden compromise specifically targeted CI secrets (GitHub Actions tokens, AWS/GCP/Azure credentials, AI tooling configs) and exfiltrated to audit.checkmarx.cx."
- **yarn v1**: `yarn install` without `--frozen-lockfile` → 🔶 FAIL.
- **yarn v2+**: `yarn install` without `--immutable` → 🔶 FAIL "v2+ uses `--immutable` (not `--frozen-lockfile`)."

If `INSTALL_CMDS` empty → ➖ N/A "no install step found in workflows — CI likely uses a separate mechanism (reusable workflow, container, etc.); check manually."

**CI-5 Dependabot**

- `DEPENDABOT=PRESENT` → ✅ PASS "`.github/dependabot.yml` present — security patches routed through review."
- `DEPENDABOT=ABSENT` → ⚡ WARN "no Dependabot config — dependency updates happen manually or not at all, and security advisories don't auto-open PRs. Add `.github/dependabot.yml` with `package-ecosystem: npm` weekly."

**CI-6 npm trusted publishing** (only if `PUBLISH_PRESENT=YES`)

- `OIDC_READY=YES` (id-token: write present, NODE_AUTH_TOKEN absent) → ✅ PASS "workflow publishes via OIDC trusted publishing — provenance attestations auto-generated, no long-lived npm token."
- `MIXED_PUB_AUTH=YES` → 🔶 FAIL "workflow has both `id-token: write` and `NODE_AUTH_TOKEN` — classic token overrides OIDC, provenance may be missing. Remove `NODE_AUTH_TOKEN` and its secret."
- `PERMS_IDTOKEN` absent AND `NODE_AUTH_TOKEN` present → ⚡ WARN "classic token auth — migrate to OIDC trusted publishing. Requires npm CLI ≥11.5.1, Node ≥22.14.0, `id-token: write` permission, and a trust-relationship configured on npmjs.com. Classic tokens are being deprecated."
- Neither → ⚡ WARN "publish step without visible auth — token likely injected via env elsewhere; verify OIDC path."

**CI-7 Runtime hardening**

- `HARDEN_RUNNER` present in any workflow → ✅ PASS "step-security/harden-runner detected — runtime egress monitoring in place."
- Absent → ⚡ WARN "no runtime egress monitoring — consider `step-security/harden-runner` as the first step of each job. Would have caught the tj-actions/changed-files exfiltration to an attacker-controlled endpoint (CVE-2025-30066, Mar 2025) and the @bitwarden/cli 2026.4.0 exfil to audit.checkmarx.cx (Apr 2026)."

## Step 4 — output format

**HARD STOP: output ends after ✅ PASSING. No patch files, no workflow YAML blocks, no "Want me to apply?". Fixes are specified inline per check.**

Icons: same as `npm-harden` — 🚨 CRITICAL, 🔶 FAIL, ⚡ WARN, ✅ PASS, ➖ N/A.

Apply the highest-severity finding's icon to the section header.

**Structure:**

```
/npm-ci-audit · [repo name] (GitHub Actions · [MGR])
🚨 N critical  🔶 N failing  ⚡ N hardening  ✅ N passing
→ [top fix]
📖 Hardening guide: https://docs.github.com/en/actions/reference/security/secure-use

[sections...]
```

Omit zero-count categories from line 2. If nothing to audit: `➖ no workflows found`. If everything passes: `✅ all passing`.

Line 2 counts *checks* (CI-1 through CI-7), not sections.

**Fix-line format** — identical to `npm-harden`:

```
        └─ .github/workflows/release.yml:42: uses: actions/checkout@<40-char-sha>
        └─ .github/workflows/ci.yml: add `permissions: contents: read` at top level
        └─ .github/workflows/publish.yml: remove NODE_AUTH_TOKEN, add `permissions: id-token: write`
```

Name the workflow file and line number whenever available. No backticks around values in the fix line — they render literally.

**Incident examples in CRITICAL findings:**

Step 3 is the sole source for finding wording. Copy both the first clause and the `e.g.` line **verbatim** from the matching Step 3 definition. Do not paraphrase or combine incidents.

Layout (placeholders are structural only):

```
  🚨 CIx  <first clause, verbatim from Step 3>
          <full e.g. line, verbatim from Step 3>
          └─ <file>:<line>: <exact fix>
```

**Top-fix line** (line 3) — same pattern as npm-harden: `→ [verb] [what with exact values] — [impact]`. If both a CRITICAL and a FAIL exist, lead with CRITICAL. If a CVE is named, include it first.

Example top fixes:

```
→ Pin 12 third-party actions to 40-char SHAs across 4 workflows — closes the tj-actions/changed-files (CVE-2025-30066) attack class at its root.
→ Replace `permissions: write-all` with explicit per-job scopes in release.yml — one compromised step currently has full repo write.
→ Drop `NODE_AUTH_TOKEN` from publish.yml and enable OIDC trusted publishing — removes the long-lived npm token and adds provenance on every release.
```

**Never add after PASSING:** no patch blocks, no YAML, no offers to apply fixes. Output stops at the last ✅ or ➖ line.
