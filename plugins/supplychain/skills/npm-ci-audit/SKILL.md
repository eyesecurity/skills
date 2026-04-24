---
name: npm-ci-audit
description: Audits npm/pnpm/Yarn supply-chain hardening in GitHub Actions workflows. Primary focus on how the project's package manager is invoked in CI — install commands, registry integrity, manager version pinning, publish flow (OIDC + provenance), and uncontrolled install surface (npx, global installs). Secondary focus on generic GitHub Actions hardening (external action SHA pinning, token permissions, pull_request_target). Trigger with /supplychain:npm-ci-audit or /supplychain:npm-ci-audit <path>.
---

## Trigger

Activate on `/supplychain:npm-ci-audit` or `/supplychain:npm-ci-audit <path>`. Treat path as repo root, or use cwd. GitHub Actions only — GitLab CI, CircleCI, Jenkins out of scope in v1.

## Step 1 — collect signals

Run as a single bash call. All greps are read-only.

```sh
echo "WORKFLOWS_DIR=$(ls -d .github/workflows 2>/dev/null && echo PRESENT || echo MISSING)"
echo "WORKFLOW_COUNT=$(ls .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null | wc -l | tr -d ' ')"
echo "=== WORKFLOWS ===" && ls .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null || echo "NONE"
echo "DEPENDABOT=$(ls .github/dependabot.yml .github/dependabot.yaml 2>/dev/null | head -1 | grep -q . && echo PRESENT || echo ABSENT)"
echo "=== DEPENDABOT_ECOSYSTEMS ===" && grep -E "package-ecosystem" .github/dependabot.yml .github/dependabot.yaml 2>/dev/null || echo "NONE"
echo "PKG_MANAGER_FIELD=$(grep -oE '"packageManager":\s*"[^"]*"' package.json 2>/dev/null | grep -oE '[a-z]+@[0-9][^"]*' || echo NOT_SET)"
echo "LOCKFILES=$(ls pnpm-lock.yaml yarn.lock package-lock.json 2>/dev/null | tr '\n' ' ' || echo NONE)"
echo "REPO_ORG=$(git config --get remote.origin.url 2>/dev/null | sed -E 's|.*[:/]([^/]+)/[^/]+(\.git)?$|\1|' | head -1 || echo NONE)"
```

Then per-workflow scans (single bash call):

```sh
W=".github/workflows"

# Generic action pinning
echo "=== USES_ALL ===" && grep -nHE '^\s*-?\s*uses:\s*[^@[:space:]]+@[^[:space:]]+' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== USES_SHA ===" && grep -cHE '^\s*-?\s*uses:\s*[^@[:space:]]+@[0-9a-f]{40}(\s|$)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== USES_BRANCH ===" && grep -nHE '^\s*-?\s*uses:\s*[^@[:space:]]+@(main|master|develop|HEAD)(\s|$)' $W/*.yml $W/*.yaml 2>/dev/null

# Permissions + triggers
echo "=== PERMS_TOP ===" && grep -nHE '^permissions:' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== PERMS_WRITEALL ===" && grep -nHE 'permissions:\s*write-all' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== PERMS_IDTOKEN ===" && grep -nHE 'id-token:\s*write' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== TRIGGER_PRT ===" && grep -nHE '^\s*pull_request_target\s*:?' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== TRIGGER_WFR ===" && grep -nHE '^\s*workflow_run\s*:' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== CHECKOUT_PRHEAD ===" && grep -nHE 'ref:\s*\$\{\{\s*github\.event\.pull_request\.head' $W/*.yml $W/*.yaml 2>/dev/null

# NPM install flow
echo "=== INSTALL_CMDS ===" && grep -nHE '(npm (ci|install|i)\b|pnpm install|pnpm i\b|yarn install|yarn\s*$)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== INSTALL_FLAGS ===" && grep -nHE '(--frozen-lockfile|--immutable|--ignore-scripts|--no-scripts)' $W/*.yml $W/*.yaml 2>/dev/null

# NPM uncontrolled surface
echo "=== NPX ===" && grep -nHE '(^|\s)npx\s+[^-]' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== GLOBAL_INSTALL ===" && grep -nHE '(npm (install|i) -g|npm (install|i) --global|pnpm add -g|yarn global add)' $W/*.yml $W/*.yaml 2>/dev/null

# NPM registry + .npmrc creation in CI
echo "=== REGISTRY_ENV ===" && grep -nHE 'NPM_CONFIG_REGISTRY|NPM_CONFIG_@[^=]+:REGISTRY|YARN_NPM_REGISTRY_SERVER|COREPACK_NPM_REGISTRY' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== NPMRC_WRITES ===" && grep -nHE '(>\s*\.npmrc|tee\s+\.npmrc|npm config set registry|setup-node.*registry-url)' $W/*.yml $W/*.yaml 2>/dev/null

# NPM manager setup + version
echo "=== SETUP_NODE ===" && grep -nHE 'uses:\s*actions/setup-node@' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== SETUP_NODE_VERSION ===" && grep -nHE '^\s*node-version\s*:\s*' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== SETUP_PNPM ===" && grep -nHE 'uses:\s*pnpm/action-setup@' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== SETUP_PNPM_VERSION ===" && grep -nHE '^\s*version\s*:\s*[0-9]' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== COREPACK_ENABLE ===" && grep -nHE 'corepack enable|corepack:\s*true' $W/*.yml $W/*.yaml 2>/dev/null

# NPM publish flow
echo "=== PUBLISH_CMDS ===" && grep -nHE '(npm publish|pnpm publish|yarn (npm )?publish)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== PROVENANCE ===" && grep -nHE '(--provenance|NPM_CONFIG_PROVENANCE)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== NODE_AUTH ===" && grep -nHE 'NODE_AUTH_TOKEN|NPM_TOKEN' $W/*.yml $W/*.yaml 2>/dev/null

```

If `WORKFLOWS_DIR=MISSING` or `WORKFLOW_COUNT=0`: emit `➖ no GitHub Actions workflows found — nothing to audit` and stop. Do not run Step 2/3.

## Step 2 — derive classification

From Step 1 output:

**Manager & version inference**
- `MGR`: infer from `PKG_MANAGER_FIELD` (prefix before `@`), else from `LOCKFILES` (pnpm-lock.yaml → pnpm; yarn.lock → yarn; package-lock.json → npm). Unknown → treat as `npm` for NPM-1 checks and note uncertainty.
- `YARN_VERSION_LIKELY`: if `MGR=yarn` and `PKG_MANAGER_FIELD` parses to `yarn@X`, use X. Determines v1 vs v2+ flag semantics.
- `PROJECT_MGR_VERSION`: semver from `PKG_MANAGER_FIELD` (e.g. `10.26.2`).
- `WORKFLOW_MGR_VERSION`: semver from `SETUP_PNPM_VERSION` / `SETUP_NODE_VERSION` matching the detected manager. If multiple workflows pin different versions, flag.
- `MGR_VERSION_DRIFT`: YES if `PROJECT_MGR_VERSION` and `WORKFLOW_MGR_VERSION` both parse and differ in major or minor. Patch-only drift → NO.

**Action pinning** — scope is external actions only. First-party and self-org are exempt.

For each line in `USES_ALL`, classify by owner prefix:
- **First-party**: `actions/*`, `github/*` — exempt; no verdict emitted.
- **Self-org**: `$REPO_ORG/*` (if `REPO_ORG` parsed from `git remote`) — exempt; no verdict emitted.
- **External**: everything else — subject to CI-1.

Derived counts over *external* lines only:
- `EXT_TOTAL`: external `uses:` lines.
- `EXT_SHA`: external lines where the ref matches `@[0-9a-f]{40}`.
- `EXT_BRANCH`: external lines where the ref matches `@(main|master|develop|HEAD)`.
- `EXT_TAG`: `EXT_TOTAL − EXT_SHA − EXT_BRANCH`.

**Trigger risk**
- `PRT_RISK`: YES if `TRIGGER_PRT` present AND `CHECKOUT_PRHEAD` present. MAYBE if only `TRIGGER_PRT`. NO otherwise.

**Publish posture**
- `PUBLISH_PRESENT`: YES if `PUBLISH_CMDS` non-empty.
- `OIDC_READY`: `PERMS_IDTOKEN` present AND `NODE_AUTH` absent.
- `MIXED_PUB_AUTH`: `PERMS_IDTOKEN` present AND `NODE_AUTH` present.
- `PROVENANCE_EXPLICIT`: YES if `PROVENANCE` present.

## Step 3 — checks

**Primary group: NPM supply chain in CI.** Secondary group: generic GitHub Actions hardening that compounds npm risk. Both groups render in the same output, primary group listed first.

---

### NPM group (primary)

**NPM-1 Install command + flags**

Per-manager expected form:

- **pnpm**: `pnpm install --frozen-lockfile` (optionally `--ignore-scripts`).
  - Any `pnpm install` line without `--frozen-lockfile` on the same run → 🔶 FAIL "CI install resolves outside the lockfile — defeats its purpose and lets a fresh registry resolution land a malicious version. Add `pnpm install --frozen-lockfile`."
  - `--ignore-scripts` absent AND project config does not set `ignore-scripts=true` / `dangerouslyAllowAllBuilds: false` → ⚡ WARN "CI runs lifecycle scripts on every install — redundant with pnpm v10 default-off, but explicit `--ignore-scripts` hardens against older pnpm binaries injected via setup action version drift."
- **npm**: `npm ci --ignore-scripts`.
  - Any `npm install` / `npm i ` (not `npm ci`) in CI → 🔶 FAIL "`npm install` in CI ignores the lockfile for new entries. Use `npm ci`."
  - `npm ci` present but `--ignore-scripts` absent AND `.npmrc` does not set `ignore-scripts=true` → 🔶 FAIL "`npm ci` runs preinstall/install/postinstall scripts by default. Add `--ignore-scripts` or `ignore-scripts=true` in `.npmrc`. e.g. Shai-Hulud (Sep 2025), Axios 1.14.1 (Mar 2026), and @bitwarden/cli 2026.4.0 (Apr 2026) all used preinstall/postinstall hooks — the Bitwarden compromise specifically targeted CI secrets (GitHub Actions tokens, AWS/GCP/Azure credentials, AI tooling configs) and exfiltrated to audit.checkmarx.cx."
- **yarn v1**: `yarn install --frozen-lockfile`. Missing flag → 🔶 FAIL.
- **yarn v2+**: `yarn install --immutable`. Missing flag → 🔶 FAIL "v2+ uses `--immutable` (not `--frozen-lockfile`)."

If `INSTALL_CMDS` empty → ➖ N/A "no install step found — CI likely uses a reusable workflow or container image; verify manually."

**NPM-2 Registry integrity**

Untrusted PR code or misconfigured workflow can redirect the manager at an attacker mirror. Checks that the effective registry is the public default unless an internal mirror is explicit and intentional.

- `REGISTRY_ENV` points to a non-registry.npmjs.org host not prefixed with an organisation's internal domain → 🚨 CRITICAL "workflow env overrides registry to `{host}` — every dependency resolves through it. An attacker who controls that host (or an attacker who managed to inject the env via PR input) can serve poisoned tarballs. Unset or restrict to a named internal mirror."
- `NPMRC_WRITES` present (workflow creates `.npmrc` on the fly) → ⚡ WARN "workflow writes `.npmrc` at run time — verify the registry value is not templated from untrusted input (`github.event.*`) and is pinned to a trusted host. `setup-node` with `registry-url:` is the safer equivalent."
- `REGISTRY_ENV` absent AND `NPMRC_WRITES` absent → ✅ PASS "no CI registry override — resolves via project `.npmrc` or the public registry default."

**NPM-3 Manager setup + version consistency**

The manager that runs in CI must match the project's pinned version, and Node/pnpm/Yarn setup actions themselves must be reproducible.

- `SETUP_NODE_VERSION` matching a floating label (`lts/*`, `20`, `20.x`) → ⚡ WARN "floating Node version — CI rolls forward silently. Pin to exact (e.g. `20.14.0`) or anchor to the project's `.nvmrc` / `engines.node`."
- `MGR_VERSION_DRIFT=YES` → 🔶 FAIL "CI runs a different major/minor of `{MGR}` than the project pins in `packageManager`. pnpm 9→10 changed the lifecycle-script default; Yarn 3→4 flipped scripts-off default in v4.14. Align workflow version to `{PROJECT_MGR_VERSION}`."
- `SETUP_PNPM` present with unpinned `version:` (tag range) → ⚡ WARN.
- `MGR=pnpm` or `yarn` AND `COREPACK_ENABLE` absent AND `SETUP_PNPM` / setup-yarn also absent → ⚡ WARN "no corepack or setup action — `{MGR}` resolves from whatever the runner happens to have pre-installed. Add `run: corepack enable` (requires `packageManager` in package.json) or the manager's setup action with a pinned version."
- All in order → ✅ PASS.

**NPM-4 Publish flow (OIDC + provenance)**

Only runs if `PUBLISH_PRESENT=YES`.

- `OIDC_READY=YES` (id-token: write present, no NODE_AUTH_TOKEN/NPM_TOKEN) → ✅ PASS "OIDC trusted publishing active — npm auto-generates provenance attestations; no long-lived token to rotate or steal. Axios 1.14.1 (Mar 2026) was published using a stolen long-lived npm token; projects on OIDC had no token to lose."
- `MIXED_PUB_AUTH=YES` → 🔶 FAIL "workflow has both `id-token: write` and `NODE_AUTH_TOKEN` — the classic token wins and OIDC provenance is not emitted. Remove `NODE_AUTH_TOKEN`/`NPM_TOKEN` and the underlying repo secret."
- `PERMS_IDTOKEN` absent AND `NODE_AUTH` present → ⚡ WARN "classic token auth — migrate to OIDC trusted publishing. Classic tokens are deprecated; stolen tokens were the vector for Axios 1.14.1 (Mar 2026). Requires npm CLI ≥11.5.1, Node ≥22.14.0, a trust relationship configured on npmjs.com, and `permissions: id-token: write` on the publish job."
- `OIDC_READY=YES` but `PROVENANCE_EXPLICIT=NO` → ✅ note only "provenance auto-emitted by trusted publishing — no flag needed. If you ever leave OIDC, re-add `--provenance` or `NPM_CONFIG_PROVENANCE=true` to preserve attestations."
- Neither auth visible → ⚡ WARN "publish step without visible auth — token likely injected elsewhere; verify OIDC path is actually used."

**NPM-5 Uncontrolled install surface**

Paths that bypass the project's lockfile and release-age gate.

- `NPX` non-empty → ⚡ WARN "`npx {tool}` in workflow resolves `{tool}` fresh from the registry every run — no lockfile, no release-age control, no pinning. A compromised tool landed via npx runs with the CI job's full environment (secrets, tokens, cloud credentials). List first 5 invocations. Prefer `npm ci` installing the tool as a devDependency pinned in the project lockfile, or `npx <pkg>@<exact-sha-or-version>` with known-good version."
- `GLOBAL_INSTALL` non-empty → 🔶 FAIL "`npm install -g` / `pnpm add -g` / `yarn global add` in workflow resolves outside the project lockfile and runs the target package's lifecycle scripts — same attack surface as installing an untrusted project dep, applied to CI tooling. Move the tool to `devDependencies` and install via the project's lockfile. e.g. `npx only-allow pnpm` as a `preinstall` is fine (pinned by npm's own cache); arbitrary `npm install -g some-release-cli` is not."
- Both empty → ✅ PASS.

**NPM-6 Dependabot npm coverage**

- `DEPENDABOT=PRESENT` AND `DEPENDABOT_ECOSYSTEMS` contains `npm` → ✅ PASS "Dependabot configured for npm — security advisories auto-open PRs."
- `DEPENDABOT=PRESENT` AND `DEPENDABOT_ECOSYSTEMS` does not include `npm` → ⚡ WARN "Dependabot configured but no `package-ecosystem: npm` entry — add one."
- `DEPENDABOT=ABSENT` → ⚡ WARN "no Dependabot config — security advisories don't auto-open PRs, dependency updates happen manually or not at all. Add `.github/dependabot.yml` with `package-ecosystem: npm` weekly."

---

### CI group (secondary — generic GitHub Actions hardening that compounds npm risk)

**CI-1 Action pinning (external actions only)**

Primary CI supply-chain control after tj-actions/changed-files (CVE-2025-30066, Mar 2025). Applies only to **external** actions — first-party (`actions/*`, `github/*`) and self-org (`$REPO_ORG/*`) are exempt because their tag and branch refs are controlled by a party the project already trusts for other purposes.

- `EXT_BRANCH > 0` → 🚨 CRITICAL "external action uses a branch ref (@main/@master/@HEAD) — reference resolves live on every run. A single push to the action's default branch by a compromised maintainer executes in your CI with your secrets and can steal your npm publish token. e.g. if tj-actions/changed-files had been pinned to @main instead of @v45 during CVE-2025-30066 (Mar 2025), every run during the 15h compromise window would still have leaked secrets." List first 5 from `USES_BRANCH` filtered to external.
- `EXT_TAG > 0` → 🔶 FAIL "external actions use mutable tag refs — tags can be retroactively repointed to a malicious commit. e.g. tj-actions/changed-files (CVE-2025-30066, Mar 14-15 2025) had @v1..@v45 tags repointed to a secret-leaking commit, affecting 23k+ repositories in a 15h window. The s1ngularity attack (Aug 2025) exploited the same class to steal npm publishing tokens from Nx build workflows. Pin each external action to a 40-char commit SHA." List first 5 external tag entries.
- `EXT_TOTAL > 0` AND all external pinned to SHA → ✅ PASS "all N external action uses pinned to 40-char commit SHA."
- `EXT_TOTAL = 0` → ✅ PASS "no external actions in use (first-party and self-org only) — no SHA-pin requirement applies."

**CI-2 Token permissions (least privilege)**

- `PERMS_WRITEALL` non-empty → 🚨 CRITICAL "`permissions: write-all` grants every token scope to every step — any compromised action has full repo write, release creation, and issue/PR control, enabling a `.npmrc` overwrite attack or malicious commit to the default branch that redirects future installs. Replace with an explicit per-job permission block."
- `PERMS_TOP` absent AND no per-job `permissions:` anywhere → ⚡ WARN "no explicit permissions block — workflow inherits the repo default (often `contents: write`). Add `permissions: contents: read` at top level and widen per-job only where needed."
- `PERMS_IDTOKEN` present AND `PUBLISH_PRESENT=NO` → ⚡ WARN "job requests `id-token: write` without a publish step — unused OIDC scope widens attack surface. Remove or scope to the publish job only."

**CI-3 pull_request_target — classic npm token theft vector**

The trigger runs with base-repo secrets on forked-PR events. The s1ngularity incident (Aug 2025, Nx build system) and many earlier compromises used this to steal npm publish tokens and trigger malicious releases.

- `PRT_RISK=YES` → 🚨 CRITICAL "Pwn Request pattern detected — `pull_request_target` workflow checks out PR head code (`github.event.pull_request.head.*`) while running in the privileged base-repo context. Any PR author can exfiltrate `NODE_AUTH_TOKEN` / `NPM_TOKEN` / OIDC-derived credentials. Either switch the trigger to `pull_request` (unprivileged) or never check out the PR head under `pull_request_target`."
- `PRT_RISK=MAYBE` → ⚡ WARN "`pull_request_target` used — review manually. Even without explicit PR-head checkout, evaluating PR-sourced config (eslint config, jest setup, scripts) is enough to leak base-repo secrets. Prefer `pull_request` unless you need write-scoped tokens on PRs."
- `TRIGGER_WFR` present → ⚡ WARN "`workflow_run` chains inherit the upstream workflow's privileged context — review the same way as `pull_request_target`."
- Both absent → ✅ PASS.

## Step 4 — output format

**HARD STOP: output ends after ✅ PASSING. No patch files, no workflow YAML blocks, no "Want me to apply?". Fixes are specified inline per check.**

Icons: same as `npm-harden` — 🚨 CRITICAL, 🔶 FAIL, ⚡ WARN, ✅ PASS, ➖ N/A.

Apply the highest-severity finding's icon to the section header. Render the NPM group first, then the CI group.

**Structure:**

```
/supplychain:npm-ci-audit · [repo name] (GitHub Actions · [MGR] [PROJECT_MGR_VERSION])
🚨 N critical  🔶 N failing  ⚡ N hardening  ✅ N passing
→ [top fix]
📖 Hardening guide: https://docs.github.com/en/actions/reference/security/secure-use

[NPM sections...]
[CI sections...]
```

Omit zero-count categories from line 2. If nothing to audit: `➖ no workflows found`. If everything passes: `✅ all passing`.

Line 2 counts *checks* — NPM-1..NPM-6 plus CI-1..CI-3.

**Fix-line format** — identical to `npm-harden`:

```
        └─ .github/workflows/release.yml:42: uses: actions/checkout@<40-char-sha>
        └─ .github/workflows/ci.yml: pnpm install --frozen-lockfile --ignore-scripts
        └─ .github/workflows/publish.yml: remove NODE_AUTH_TOKEN env; add `permissions: id-token: write` on the publish job
        └─ .github/dependabot.yml: add package-ecosystem: npm (interval: weekly)
```

Name the workflow file and line number whenever available. No backticks around values — they render literally.

**Incident examples in CRITICAL findings:**

Step 3 is the sole source for finding wording. Copy both the first clause and the `e.g.` line **verbatim** from the matching Step 3 definition. Do not paraphrase or combine incidents.

Layout (placeholders are structural only):

```
  🚨 NPM-x  <first clause, verbatim from Step 3>
            <full e.g. line, verbatim from Step 3>
            └─ <file>:<line>: <exact fix>
```

**Top-fix line** (line 3) — `→ [verb] [what with exact values] — [impact]`. Bias toward NPM-group findings over CI-group when both fire, since the skill's primary mandate is the npm supply chain in CI. If a CVE is named, include it first.

Example top fixes:

```
→ Add --frozen-lockfile + --ignore-scripts to pnpm install in ci.yml — closes the Axios/Bitwarden/Shai-Hulud preinstall-hook attack class and locks CI to the committed lockfile in one line each.
→ Drop NODE_AUTH_TOKEN from publish.yml and enable OIDC trusted publishing — removes the long-lived npm token stolen in Axios 1.14.1 (Mar 2026) and adds provenance on every release.
→ Pin 12 third-party actions to 40-char SHAs across 4 workflows — closes the tj-actions/changed-files (CVE-2025-30066) attack class that specifically targeted npm publishing workflows.
```

**Never add after PASSING:** no patch blocks, no YAML, no offers to apply fixes. Output stops at the last ✅ or ➖ line.
