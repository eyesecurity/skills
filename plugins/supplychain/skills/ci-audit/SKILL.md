---
name: ci-audit
description: Audits npm and PyPI supply-chain hardening in GitHub Actions workflows. Primary focus on how the project's package manager is invoked in CI — install commands, registry integrity, manager version pinning, publish flow (OIDC + provenance / attestations), and uncontrolled install surface (npx, pipx, global installs, curl|sh). Secondary focus on generic GitHub Actions hardening (external action SHA pinning, token permissions, pull_request_target). Trigger with /supplychain:ci-audit or /supplychain:ci-audit <path>.
---

## Trigger

Activate on `/supplychain:ci-audit` or `/supplychain:ci-audit <path>`. Treat path as repo root, or use cwd. GitHub Actions only — GitLab CI, CircleCI, Jenkins out of scope in v1.

The skill detects npm and Python ecosystems independently and runs both groups against the same workflow set. Monorepos with both ecosystems are explicitly supported.

## Step 1 — collect signals

Run as a single bash call. All greps are read-only.

```sh
echo "WORKFLOWS_DIR=$(ls -d .github/workflows 2>/dev/null && echo PRESENT || echo MISSING)"
echo "WORKFLOW_COUNT=$(ls .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null | wc -l | tr -d ' ')"
echo "=== WORKFLOWS ===" && ls .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null || echo "NONE"
echo "DEPENDABOT=$(ls .github/dependabot.yml .github/dependabot.yaml 2>/dev/null | head -1 | grep -q . && echo PRESENT || echo ABSENT)"
echo "=== DEPENDABOT_ECOSYSTEMS ===" && grep -E "package-ecosystem" .github/dependabot.yml .github/dependabot.yaml 2>/dev/null || echo "NONE"

# npm signals
echo "PKG_JSON=$(ls package.json 2>/dev/null && echo PRESENT || echo ABSENT)"
echo "PKG_MANAGER_FIELD=$(grep -oE '"packageManager":\s*"[^"]*"' package.json 2>/dev/null | grep -oE '[a-z]+@[0-9][^"]*' || echo NOT_SET)"
echo "NPM_LOCKFILES=$(ls pnpm-lock.yaml yarn.lock package-lock.json 2>/dev/null | tr '\n' ' ' || echo NONE)"

# Python signals
echo "PYPROJECT=$(ls pyproject.toml 2>/dev/null && echo PRESENT || echo ABSENT)"
echo "PY_LOCKFILES=$(ls uv.lock poetry.lock pdm.lock Pipfile.lock pylock.toml 2>/dev/null | tr '\n' ' ' || echo NONE)"
echo "REQS_FILES=$(ls requirements.txt requirements-*.txt 2>/dev/null | tr '\n' ' ' || echo NONE)"
echo "=== PY_TOOL_SECTIONS ===" && grep -nE '^\[tool\.(uv|poetry|pdm|hatch|pipenv)' pyproject.toml 2>/dev/null || echo "NONE"
echo "HASHED_REQS_IN_REPO=$(grep -lE '^\s*--hash=' requirements*.txt 2>/dev/null | head -1 | grep -q . && echo YES || echo NO)"

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
echo "=== NPM_INSTALL_CMDS ===" && grep -nHE '(npm (ci|install|i)\b|pnpm install|pnpm i\b|yarn install|yarn\s*$)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== NPM_INSTALL_FLAGS ===" && grep -nHE '(--frozen-lockfile|--immutable|--ignore-scripts|--no-scripts)' $W/*.yml $W/*.yaml 2>/dev/null

# NPM uncontrolled surface
echo "=== NPX ===" && grep -nHE '(^|\s)npx\s+[^-]' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== NPM_GLOBAL_INSTALL ===" && grep -nHE '(npm (install|i) -g|npm (install|i) --global|pnpm add -g|yarn global add)' $W/*.yml $W/*.yaml 2>/dev/null

# NPM registry + .npmrc creation in CI
echo "=== NPM_REGISTRY_ENV ===" && grep -nHE 'NPM_CONFIG_REGISTRY|NPM_CONFIG_@[^=]+:REGISTRY|YARN_NPM_REGISTRY_SERVER|COREPACK_NPM_REGISTRY' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== NPMRC_WRITES ===" && grep -nHE '(>\s*\.npmrc|tee\s+\.npmrc|npm config set registry|setup-node.*registry-url)' $W/*.yml $W/*.yaml 2>/dev/null

# NPM manager setup + version
echo "=== SETUP_NODE ===" && grep -nHE 'uses:\s*actions/setup-node@' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== SETUP_NODE_VERSION ===" && grep -nHE '^\s*node-version\s*:\s*' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== SETUP_PNPM ===" && grep -nHE 'uses:\s*pnpm/action-setup@' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== SETUP_PNPM_VERSION ===" && grep -nHE '^\s*version\s*:\s*[0-9]' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== COREPACK_ENABLE ===" && grep -nHE 'corepack enable|corepack:\s*true' $W/*.yml $W/*.yaml 2>/dev/null

# NPM publish flow
echo "=== NPM_PUBLISH_CMDS ===" && grep -nHE '(npm publish|pnpm publish|yarn (npm )?publish)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== NPM_PROVENANCE ===" && grep -nHE '(--provenance|NPM_CONFIG_PROVENANCE)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== NODE_AUTH ===" && grep -nHE 'NODE_AUTH_TOKEN|NPM_TOKEN' $W/*.yml $W/*.yaml 2>/dev/null

# Python install flow
echo "=== PY_INSTALL_CMDS ===" && grep -nHE '(\bpip install\b|\buv (sync|pip install|pip sync)\b|\bpoetry install\b|\bpdm (sync|install)\b|\bpipenv (sync|install)\b)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== PY_INSTALL_FLAGS ===" && grep -nHE '(--require-hashes|--no-deps|--frozen|--locked|--only-binary|--no-binary|--exclude-newer|--uploaded-prior-to|--no-build-isolation|--trusted-host|--extra-index-url|--sync|--check|--deploy)' $W/*.yml $W/*.yaml 2>/dev/null

# Python uncontrolled surface
echo "=== PIPX_RUN ===" && grep -nHE '(^|\s)(pipx run|pipx install|uvx)\s+[^-]' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== PY_PIPE_EXEC ===" && grep -nHE 'curl\s+[^|]*\|\s*(python|sh|bash)|wget\s+[^|]*\|\s*(python|sh|bash)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== PY_AD_HOC_PIP ===" && grep -nHE '(^|\s)(sudo\s+)?pip install\s+[^-]' $W/*.yml $W/*.yaml 2>/dev/null | grep -vE -- '-r\s|-c\s|--requirement|--constraint'

# Python index + auth
echo "=== PY_INDEX_ENV ===" && grep -nHE 'PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|PIP_TRUSTED_HOST|UV_INDEX_URL|UV_EXTRA_INDEX_URL|POETRY_HTTP_BASIC' $W/*.yml $W/*.yaml 2>/dev/null

# Python manager setup
echo "=== SETUP_PYTHON ===" && grep -nHE 'uses:\s*actions/setup-python@' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== SETUP_PYTHON_VERSION ===" && grep -nHE '^\s*python-version\s*:\s*' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== SETUP_UV ===" && grep -nHE 'uses:\s*astral-sh/setup-uv@' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== SETUP_POETRY ===" && grep -nHE 'uses:\s*(snok/install-poetry|abatilo/actions-poetry)@' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== SETUP_PDM ===" && grep -nHE 'uses:\s*pdm-project/setup-pdm@' $W/*.yml $W/*.yaml 2>/dev/null

# Python publish flow
echo "=== PY_PUBLISH_CMDS ===" && grep -nHE '(pypa/gh-action-pypi-publish|twine upload|poetry publish|uv publish|pdm publish|hatch publish)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== PY_PUBLISH_ATTESTATIONS ===" && grep -nHE '(attestations:\s*(true|false)|--attestations)' $W/*.yml $W/*.yaml 2>/dev/null
echo "=== TWINE_AUTH ===" && grep -nHE 'TWINE_(USERNAME|PASSWORD)|POETRY_PYPI_TOKEN|UV_PUBLISH_TOKEN' $W/*.yml $W/*.yaml 2>/dev/null
```

If `WORKFLOWS_DIR=MISSING` or `WORKFLOW_COUNT=0`: emit `➖ no GitHub Actions workflows found — nothing to audit` and stop.

If `PKG_JSON=ABSENT` AND `PYPROJECT=ABSENT` AND `REQS_FILES=NONE` AND `NPM_LOCKFILES=NONE` AND `PY_LOCKFILES=NONE`: emit `➖ no JavaScript or Python project detected — nothing to audit` and stop.

## Step 2 — derive classification

From Step 1 output:

**Ecosystem flags**
- `NPM_PRESENT`: YES if `PKG_JSON=PRESENT` or `NPM_LOCKFILES` non-empty.
- `PY_PRESENT`: YES if `PYPROJECT=PRESENT`, `PY_LOCKFILES` non-empty, or `REQS_FILES` non-empty.

**npm manager & version inference** (only if `NPM_PRESENT=YES`)
- `NPM_MGR`: infer from `PKG_MANAGER_FIELD` (prefix before `@`), else from `NPM_LOCKFILES` (pnpm-lock.yaml → pnpm; yarn.lock → yarn; package-lock.json → npm). Unknown → treat as `npm` and note uncertainty.
- `YARN_VERSION_LIKELY`: if `NPM_MGR=yarn` and `PKG_MANAGER_FIELD` parses to `yarn@X`, use X.
- `PROJECT_MGR_VERSION`: semver from `PKG_MANAGER_FIELD`.
- `WORKFLOW_MGR_VERSION`: semver from `SETUP_PNPM_VERSION` / `SETUP_NODE_VERSION` matching the detected manager.
- `MGR_VERSION_DRIFT`: YES if `PROJECT_MGR_VERSION` and `WORKFLOW_MGR_VERSION` both parse and differ in major or minor.

**Python manager inference** (only if `PY_PRESENT=YES`)
- `PY_MGR`: precedence uv > Poetry > pdm > pipenv > pip. Detection rule: uv if `uv.lock` or `[tool.uv]`; Poetry if `poetry.lock` or `[tool.poetry]`; pdm if `pdm.lock`; pipenv if `Pipfile.lock`; pip if `REQS_FILES` non-empty and no other lock claims the project. Multi-tool repos: pick the dominant one for the section header but run checks for any tool whose install command appears in `PY_INSTALL_CMDS`.
- `PY_INSTALL_TOOL_IN_CI`: list of installer commands actually invoked in workflows (pip, uv, poetry, pdm, pipenv).
- `PY_PUBLISH_PRESENT`: YES if `PY_PUBLISH_CMDS` non-empty.
- `PYPI_OIDC_READY`: YES if `PERMS_IDTOKEN` present, `TWINE_AUTH` absent, AND `PY_PUBLISH_CMDS` references `pypa/gh-action-pypi-publish` or `uv publish` / `poetry publish` / `pdm publish` / `hatch publish` without an API-token env.
- `PYPI_MIXED_PUB_AUTH`: `PERMS_IDTOKEN` present AND `TWINE_AUTH` present.

**Action pinning** — scope is external actions only. First-party and self-org are exempt.

For each line in `USES_ALL`, classify by owner prefix:
- **First-party**: `actions/*`, `github/*` — exempt; no verdict emitted.
- **Self-org**: `$REPO_ORG/*` (if `REPO_ORG` parsed from `git remote`) — exempt.
- **External**: everything else — subject to CI-1.

Derived counts over *external* lines only:
- `EXT_TOTAL`: external `uses:` lines.
- `EXT_SHA`: external lines where the ref matches `@[0-9a-f]{40}`.
- `EXT_BRANCH`: external lines where the ref matches `@(main|master|develop|HEAD)`.
- `EXT_TAG`: `EXT_TOTAL − EXT_SHA − EXT_BRANCH`.

**Trigger risk**
- `PRT_RISK`: YES if `TRIGGER_PRT` present AND `CHECKOUT_PRHEAD` present. MAYBE if only `TRIGGER_PRT`. NO otherwise.

**npm publish posture**
- `NPM_PUBLISH_PRESENT`: YES if `NPM_PUBLISH_CMDS` non-empty.
- `NPM_OIDC_READY`: `PERMS_IDTOKEN` present AND `NODE_AUTH` absent.
- `NPM_MIXED_PUB_AUTH`: `PERMS_IDTOKEN` present AND `NODE_AUTH` present.
- `NPM_PROVENANCE_EXPLICIT`: YES if `NPM_PROVENANCE` present.

## Step 3 — checks

Render section order: NPM group first if `NPM_PRESENT=YES`, then PyPI group if `PY_PRESENT=YES`, then CI group (always). Skip a group entirely if its ecosystem is absent.

---

### NPM group (only if NPM_PRESENT=YES)

**NPM-1 Install command + flags**

Per-manager expected form:

- **pnpm**: `pnpm install --frozen-lockfile` (optionally `--ignore-scripts`).
  - Any `pnpm install` line without `--frozen-lockfile` on the same run → 🔶 FAIL "CI install resolves outside the lockfile — defeats its purpose and lets a fresh registry resolution land a malicious version. Add `pnpm install --frozen-lockfile`."
  - `--ignore-scripts` absent AND project config does not set `ignore-scripts=true` / `dangerouslyAllowAllBuilds: false` → ⚠️ WARN "CI runs lifecycle scripts on every install — redundant with pnpm v10 default-off, but explicit `--ignore-scripts` hardens against older pnpm binaries injected via setup action version drift."
- **npm**: `npm ci --ignore-scripts`.
  - Any `npm install` / `npm i ` (not `npm ci`) in CI → 🔶 FAIL "`npm install` in CI ignores the lockfile for new entries. Use `npm ci`."
  - `npm ci` present but `--ignore-scripts` absent AND `.npmrc` does not set `ignore-scripts=true` → 🔶 FAIL "`npm ci` runs preinstall/install/postinstall scripts by default. Add `--ignore-scripts` or `ignore-scripts=true` in `.npmrc`. e.g. Shai-Hulud (Sep 2025), Axios 1.14.1 (Mar 2026), and @bitwarden/cli 2026.4.0 (Apr 2026) all used preinstall/postinstall hooks — the Bitwarden compromise specifically targeted CI secrets (GitHub Actions tokens, AWS/GCP/Azure credentials, AI tooling configs) and exfiltrated to audit.checkmarx.cx."
- **yarn v1**: `yarn install --frozen-lockfile`. Missing flag → 🔶 FAIL.
- **yarn v2+**: `yarn install --immutable`. Missing flag → 🔶 FAIL "v2+ uses `--immutable` (not `--frozen-lockfile`)."

If `NPM_INSTALL_CMDS` empty → ➖ N/A "no npm install step found — CI likely uses a reusable workflow or container image; verify manually."

**NPM-2 Registry integrity**

Untrusted PR code or misconfigured workflow can redirect the manager at an attacker mirror. Checks that the effective registry is the public default unless an internal mirror is explicit and intentional.

- `NPM_REGISTRY_ENV` points to a non-`registry.npmjs.org` host not prefixed with an organisation's internal domain → 🚨 CRITICAL "workflow env overrides registry to `{host}` — every dependency resolves through it. An attacker who controls that host (or an attacker who managed to inject the env via PR input) can serve poisoned tarballs. Unset or restrict to a named internal mirror."
- `NPMRC_WRITES` present → ⚠️ WARN "workflow writes `.npmrc` at run time — verify the registry value is not templated from untrusted input (`github.event.*`) and is pinned to a trusted host. `setup-node` with `registry-url:` is the safer equivalent."
- Both absent → ✅ PASS "no CI registry override — resolves via project `.npmrc` or the public registry default."

**NPM-3 Manager setup + version consistency**

- `SETUP_NODE_VERSION` matching a floating label (`lts/*`, `20`, `20.x`) → ⚠️ WARN "floating Node version — CI rolls forward silently. Pin to exact (e.g. `20.14.0`) or anchor to the project's `.nvmrc` / `engines.node`."
- `MGR_VERSION_DRIFT=YES` → 🔶 FAIL "CI runs a different major/minor of `{NPM_MGR}` than the project pins in `packageManager`. pnpm 9→10 changed the lifecycle-script default; Yarn 3→4 flipped scripts-off default in v4.14. Align workflow version to `{PROJECT_MGR_VERSION}`."
- `SETUP_PNPM` present with unpinned `version:` (tag range) → ⚠️ WARN.
- `NPM_MGR=pnpm` or `yarn` AND `COREPACK_ENABLE` absent AND `SETUP_PNPM` / setup-yarn also absent → ⚠️ WARN "no corepack or setup action — `{NPM_MGR}` resolves from whatever the runner happens to have pre-installed. Add `run: corepack enable` (requires `packageManager` in package.json) or the manager's setup action with a pinned version."
- All in order → ✅ PASS.

**NPM-4 Publish flow (OIDC + provenance)**

Only runs if `NPM_PUBLISH_PRESENT=YES`.

- `NPM_OIDC_READY=YES` → ✅ PASS "OIDC trusted publishing active — npm auto-generates provenance attestations; no long-lived token to rotate or steal. Axios 1.14.1 (Mar 2026) was published using a stolen long-lived npm token; projects on OIDC had no token to lose."
- `NPM_MIXED_PUB_AUTH=YES` → 🔶 FAIL "workflow has both `id-token: write` and `NODE_AUTH_TOKEN` — the classic token wins and OIDC provenance is not emitted. Remove `NODE_AUTH_TOKEN`/`NPM_TOKEN` and the underlying repo secret."
- `PERMS_IDTOKEN` absent AND `NODE_AUTH` present → ⚠️ WARN "classic token auth — migrate to OIDC trusted publishing. Classic tokens are deprecated; stolen tokens were the vector for Axios 1.14.1 (Mar 2026). Requires npm CLI ≥11.5.1, Node ≥22.14.0, a trust relationship configured on npmjs.com, and `permissions: id-token: write` on the publish job."
- `NPM_OIDC_READY=YES` but `NPM_PROVENANCE_EXPLICIT=NO` → ✅ note only "provenance auto-emitted by trusted publishing — no flag needed. If you ever leave OIDC, re-add `--provenance` or `NPM_CONFIG_PROVENANCE=true` to preserve attestations."
- Neither auth visible → ⚠️ WARN "publish step without visible auth — token likely injected elsewhere; verify OIDC path is actually used."

**NPM-5 Uncontrolled install surface**

- `NPX` non-empty → ⚠️ WARN "`npx {tool}` in workflow resolves `{tool}` fresh from the registry every run — no lockfile, no release-age control, no pinning. A compromised tool landed via npx runs with the CI job's full environment (secrets, tokens, cloud credentials). List first 5 invocations. Prefer `npm ci` installing the tool as a devDependency pinned in the project lockfile, or `npx <pkg>@<exact-sha-or-version>` with known-good version."
- `NPM_GLOBAL_INSTALL` non-empty → 🔶 FAIL "`npm install -g` / `pnpm add -g` / `yarn global add` in workflow resolves outside the project lockfile and runs the target package's lifecycle scripts — same attack surface as installing an untrusted project dep, applied to CI tooling. Move the tool to `devDependencies` and install via the project's lockfile."
- Both empty → ✅ PASS.

**NPM-6 Dependabot npm coverage**

- `DEPENDABOT=PRESENT` AND `DEPENDABOT_ECOSYSTEMS` contains `npm` → ✅ PASS "Dependabot configured for npm — security advisories auto-open PRs."
- `DEPENDABOT=PRESENT` AND `DEPENDABOT_ECOSYSTEMS` does not include `npm` → ⚠️ WARN "Dependabot configured but no `package-ecosystem: npm` entry — add one."
- `DEPENDABOT=ABSENT` → ⚠️ WARN "no Dependabot config — security advisories don't auto-open PRs, dependency updates happen manually or not at all. Add `.github/dependabot.yml` with `package-ecosystem: npm` weekly."

---

### PyPI group (only if PY_PRESENT=YES)

**PY-1 Install command + flags**

Per-manager expected form. Apply rules for whichever installer appears in `PY_INSTALL_TOOL_IN_CI`.

- **pip + requirements.txt + hashes** (`HASHED_REQS_IN_REPO=YES`): expect `pip install -r requirements.txt --require-hashes`. Missing `--require-hashes` flag in `PY_INSTALL_FLAGS` → 🔶 FAIL "pinned hashes are committed but CI does not enforce them — install silently falls back to no-verification mode if a hash line is absent for any transitive. Add `--require-hashes`."
- **pip + requirements.txt + no hashes** (`HASHED_REQS_IN_REPO=NO`): 🔶 FAIL "`pip install -r requirements.txt` without `--require-hashes` resolves a fresh artifact from the registry every run for any unpinned line. Regenerate the file with `pip-compile --generate-hashes` (pip-tools) or `uv pip compile --generate-hashes`, then install with `--require-hashes`."
- **pip without `-r`** (`PY_AD_HOC_PIP` non-empty): 🔶 FAIL "ad-hoc `pip install <pkg>` resolves live from PyPI — no lockfile, no release-age gate, no pinning. e.g. lightning 2.6.2/2.6.3 (Apr 2026) shipped a malicious wheel that ran `_runtime/start.py` on import and harvested GitHub/npm/cloud credentials; an unpinned `pip install lightning` during the live window would have executed the payload on the runner."
- **uv**: expect `uv sync --frozen` (or `--locked`). Plain `uv sync` → 🔶 FAIL "no `--frozen` / `--locked` — uv may re-resolve and update `uv.lock` in CI. Use `--frozen` to enforce the committed lock or `--locked` to fail on drift."
- **Poetry**: expect `poetry install --no-interaction --sync` (or `--no-root` for libraries). Missing `--sync` → ⚠️ WARN "Poetry has no native release-age gate (issue #10646, PR #10824 in review). Until that ships, the lockfile + `--sync` are the only line of defence; ensure both are present and the lockfile is committed."
- **pdm**: expect `pdm sync --check`. Plain `pdm install` → ⚠️ WARN "use `pdm sync --check` to fail when the lock and pyproject drift; pdm has no native release-age gate."
- **pipenv**: expect `pipenv sync --deploy`. `pipenv install` in CI → 🔶 FAIL.

If `PY_INSTALL_CMDS` empty AND `PY_PUBLISH_CMDS` empty → ➖ N/A "no Python install or publish step found in workflows — verify manually if a reusable workflow or container handles it."

**PY-2 Index integrity**

Dependency confusion is the dominant supply-chain risk for Python projects with internal mirrors. PyPI permits anyone to publish a package matching any unclaimed name; if CI consults PyPI alongside an internal index, an attacker can publish a higher-versioned typosquat under your internal package's name and the resolver will pick it.

- `PY_INDEX_ENV` contains `PIP_TRUSTED_HOST` → 🚨 CRITICAL "`PIP_TRUSTED_HOST` disables TLS verification for the listed host — any on-path attacker (corporate proxy, Wi-Fi MITM, malicious mirror) can swap wheels in flight. Replace with a properly-issued certificate or a CA the runner trusts."
- `PY_INDEX_ENV` contains `PIP_EXTRA_INDEX_URL` or `UV_EXTRA_INDEX_URL` → 🔶 FAIL "extra index URL configured in CI — pip and uv (in `unsafe-best-match` mode) consult **all** indexes and pick the highest version match, allowing a public PyPI package matching an internal package's name to shadow the internal one. Use a single `PIP_INDEX_URL` pointing at your internal mirror with PyPI proxied through it, or for uv set `index-strategy = \"first-index\"` (the default) and declare each index in `[[tool.uv.index]]`."
- `--extra-index-url` flag in `PY_INSTALL_FLAGS` → 🔶 FAIL same finding.
- `PY_INDEX_ENV` contains `PIP_INDEX_URL` set to a non-`pypi.org` host without an organisation's internal-domain prefix → ⚠️ WARN "verify the override points at a trusted internal mirror, not an attacker-controlled host injected via untrusted PR input."
- All clean → ✅ PASS.

**PY-3 Tool setup + version consistency**

- `SETUP_PYTHON_VERSION` matching a floating label (`3.x`, `3.12`, `3` without minor.patch) → ⚠️ WARN "floating Python version — CI rolls forward silently. Pin to exact (e.g. `3.12.5`) or anchor to `.python-version` / `requires-python`."
- `SETUP_PYTHON` absent AND any pip/uv/poetry install step present → ⚠️ WARN "no `actions/setup-python` step — Python resolves from whatever the runner image happens to ship. Add the action with a pinned version."
- `SETUP_UV` present with unpinned `version:` → ⚠️ WARN "uv version not pinned — `astral-sh/setup-uv` defaults to latest; add `version: x.y.z` matching `[tool.uv] required-version`."
- `SETUP_POETRY` / `SETUP_PDM` present without explicit version → ⚠️ WARN.
- All in order → ✅ PASS.

**PY-4 Publish flow (OIDC + PEP 740 attestations)**

Only runs if `PY_PUBLISH_PRESENT=YES`.

- `PYPI_OIDC_READY=YES` AND `pypa/gh-action-pypi-publish` referenced → ✅ PASS "PyPI OIDC trusted publishing active — no long-lived token, and `pypa/gh-action-pypi-publish@release/v1` emits PEP 740 attestations (Sigstore-backed) by default. e.g. ultralytics 8.3.41 (Dec 2024) was published using a long-lived PyPI token stolen via GitHub Actions cache poisoning; projects on OIDC had no token to lose."
- `PYPI_MIXED_PUB_AUTH=YES` → 🔶 FAIL "workflow has both `id-token: write` and `TWINE_PASSWORD` / `POETRY_PYPI_TOKEN` / `UV_PUBLISH_TOKEN` — the classic token path wins and PEP 740 attestations are not emitted. Remove the token env and the underlying repo secret."
- `PERMS_IDTOKEN` absent AND `TWINE_AUTH` present → ⚠️ WARN "classic token auth on PyPI — migrate to OIDC trusted publishing. Configure a Trusted Publisher on pypi.org under the project's `Manage > Publishing` page, then add `permissions: id-token: write` to the publish job and use `pypa/gh-action-pypi-publish@release/v1` (or `uv publish` / `poetry publish` with the OIDC token environment)."
- `pypa/gh-action-pypi-publish` referenced AND `PY_PUBLISH_ATTESTATIONS` shows `attestations: false` → ⚠️ WARN "PEP 740 attestations explicitly disabled — leave at default (`true`) so consumers can verify the Sigstore bundle on PyPI."
- Neither auth visible → ⚠️ WARN.

**PY-5 Uncontrolled install surface**

- `PIPX_RUN` non-empty → ⚠️ WARN "`pipx run` / `uvx` resolves the tool fresh from PyPI every run — no lockfile, no release-age gate, no pinning. A compromised tool runs with the CI job's environment. Pin via `pipx run --spec '<pkg>==<exact-version>'` / `uvx --from '<pkg>==<exact-version>'`, or move to a project devDependency installed via the lockfile."
- `PY_PIPE_EXEC` non-empty → 🚨 CRITICAL "`curl … | python` / `curl … | sh` in workflow — the remote endpoint can serve different code on every fetch and runs in the CI job's full context. Replace with a pinned download + checksum verification, or install via a managed action with a SHA pin."
- `PY_AD_HOC_PIP` non-empty (covered under PY-1 already if the tool is pip; suppress duplicate here when PY-1 already fired on the same line) → 🔶 FAIL "ad-hoc `pip install <pkg>` resolves outside the project lockfile and may execute `setup.py` on a source distribution. Move the tool into `requirements.txt` (with hashes) or a `[dependency-groups]` table consumed via `pip install -r`."
- All clean → ✅ PASS.

**PY-6 Dependabot pip coverage**

- `DEPENDABOT=PRESENT` AND `DEPENDABOT_ECOSYSTEMS` contains `pip` → ✅ PASS "Dependabot configured for pip (covers `requirements.txt`, `pyproject.toml`, Poetry, and pipenv)."
- `DEPENDABOT=PRESENT` AND `DEPENDABOT_ECOSYSTEMS` contains `uv` → ✅ PASS.
- `DEPENDABOT=PRESENT` AND no Python ecosystem listed → ⚠️ WARN "Dependabot configured but no `package-ecosystem: pip` (or `uv`) entry — add one."
- `DEPENDABOT=ABSENT` → ⚠️ WARN "no Dependabot config — Python security advisories don't auto-open PRs. Add `.github/dependabot.yml` with `package-ecosystem: pip` weekly. Pair with `pip-audit` or `osv-scanner` in CI for advisory enforcement on PR."

---

### CI group (always — generic GitHub Actions hardening that compounds package-manager risk)

**CI-1 Action pinning (external actions only)**

Primary CI supply-chain control after tj-actions/changed-files (CVE-2025-30066, Mar 2025). Applies only to **external** actions — first-party (`actions/*`, `github/*`) and self-org (`$REPO_ORG/*`) are exempt because their tag and branch refs are controlled by a party the project already trusts for other purposes.

- `EXT_BRANCH > 0` → 🚨 CRITICAL "external action uses a branch ref (@main/@master/@HEAD) — reference resolves live on every run. A single push to the action's default branch by a compromised maintainer executes in your CI with your secrets and can steal your npm or PyPI publish token. e.g. if tj-actions/changed-files had been pinned to @main instead of @v45 during CVE-2025-30066 (Mar 2025), every run during the 15h compromise window would still have leaked secrets." List first 5 from `USES_BRANCH` filtered to external.
- `EXT_TAG > 0` → 🔶 FAIL "external actions use mutable tag refs — tags can be retroactively repointed to a malicious commit. e.g. tj-actions/changed-files (CVE-2025-30066, Mar 14-15 2025) had @v1..@v45 tags repointed to a secret-leaking commit, affecting 23k+ repositories in a 15h window. The s1ngularity attack (Aug 2025) exploited the same class to steal npm publishing tokens from Nx build workflows; the ultralytics PyPI compromise (Dec 2024) used GitHub Actions cache poisoning to steal a PyPI token. Pin each external action to a 40-char commit SHA." List first 5 external tag entries.
- `EXT_TOTAL > 0` AND all external pinned to SHA → ✅ PASS "all N external action uses pinned to 40-char commit SHA."
- `EXT_TOTAL = 0` → ✅ PASS "no external actions in use (first-party and self-org only) — no SHA-pin requirement applies."

**CI-2 Token permissions (least privilege)**

- `PERMS_WRITEALL` non-empty → 🚨 CRITICAL "`permissions: write-all` grants every token scope to every step — any compromised action has full repo write, release creation, and issue/PR control, enabling a `.npmrc` / `pyproject.toml` overwrite attack or malicious commit to the default branch that redirects future installs. Replace with an explicit per-job permission block."
- `PERMS_TOP` absent AND no per-job `permissions:` anywhere → ⚠️ WARN "no explicit permissions block — workflow inherits the repo default (often `contents: write`). Add `permissions: contents: read` at top level and widen per-job only where needed."
- `PERMS_IDTOKEN` present AND `NPM_PUBLISH_PRESENT=NO` AND `PY_PUBLISH_PRESENT=NO` → ⚠️ WARN "job requests `id-token: write` without a publish step — unused OIDC scope widens attack surface. Remove or scope to the publish job only."

**CI-3 pull_request_target — token theft vector**

The trigger runs with base-repo secrets on forked-PR events. The s1ngularity incident (Aug 2025, Nx build system) used this to steal npm publish tokens; the same class threatens PyPI tokens.

- `PRT_RISK=YES` → 🚨 CRITICAL "Pwn Request pattern detected — `pull_request_target` workflow checks out PR head code (`github.event.pull_request.head.*`) while running in the privileged base-repo context. Any PR author can exfiltrate `NODE_AUTH_TOKEN` / `NPM_TOKEN` / `TWINE_PASSWORD` / `POETRY_PYPI_TOKEN` / OIDC-derived credentials. Either switch the trigger to `pull_request` (unprivileged) or never check out the PR head under `pull_request_target`."
- `PRT_RISK=MAYBE` → ⚠️ WARN "`pull_request_target` used — review manually. Even without explicit PR-head checkout, evaluating PR-sourced config (eslint config, jest setup, `pytest` plugins, `conftest.py`, `pyproject.toml [tool.*]`) is enough to leak base-repo secrets. Prefer `pull_request` unless you need write-scoped tokens on PRs."
- `TRIGGER_WFR` present → ⚠️ WARN "`workflow_run` chains inherit the upstream workflow's privileged context — review the same way as `pull_request_target`."
- All absent → ✅ PASS.

## Step 4 — output format

**HARD STOP: output ends after ✅ PASSING. No patch files, no workflow YAML blocks, no "Want me to apply?". Fixes are specified inline per check.**

Icons: same as `npm-harden` / `pypi-harden` — 🚨 CRITICAL, 🔶 FAIL, ⚠️ WARN, ✅ PASS, ➖ N/A.

Apply the highest-severity finding's icon to the section header. Render NPM group first (if present), then PyPI group (if present), then CI group.

**Structure:**

```
/supplychain:ci-audit · [repo name] (GitHub Actions · [ecosystems])
🚨 N critical  🔶 N failing  ⚠️ N hardening  ✅ N passing
→ [top fix]
📖 Hardening guide: https://docs.github.com/en/actions/reference/security/secure-use

[NPM sections, if NPM_PRESENT]
[PyPI sections, if PY_PRESENT]
[CI sections, always]
```

`[ecosystems]` reads as one of: `npm <NPM_MGR> <PROJECT_MGR_VERSION>`, `pypi <PY_MGR>`, or `npm <NPM_MGR> + pypi <PY_MGR>` when both ecosystems are present.

Omit zero-count categories from line 2. If everything passes: `✅ all passing`.

Line 2 counts *checks* — every NPM-N, PY-N, and CI-N finding that has a result.

**Fix-line format:**

```
        └─ .github/workflows/release.yml:42: uses: actions/checkout@<40-char-sha>
        └─ .github/workflows/ci.yml: pnpm install --frozen-lockfile --ignore-scripts
        └─ .github/workflows/ci.yml: uv sync --frozen
        └─ .github/workflows/ci.yml: pip install -r requirements.txt --require-hashes
        └─ .github/workflows/publish.yml: remove TWINE_PASSWORD env; add `permissions: id-token: write` on the publish job
        └─ .github/dependabot.yml: add package-ecosystem: pip (interval: weekly)
```

Name the workflow file and line number whenever available. No backticks around values — they render literally.

**Incident examples in CRITICAL findings:**

Step 3 is the sole source for finding wording. Copy both the first clause and the `e.g.` line **verbatim** from the matching Step 3 definition. Do not paraphrase or combine incidents.

Layout (placeholders are structural only):

```
  🚨 [CHECK-ID]  <first clause, verbatim from Step 3>
                <full e.g. line, verbatim from Step 3>
                └─ <file>:<line>: <exact fix>
```

**Top-fix line** (line 3) — `→ [verb] [what with exact values] — [impact]`. Bias toward primary-group findings (NPM or PyPI) over CI-group when both fire. If a CVE is named, include it first.

Example top fixes:

```
→ Add --frozen-lockfile + --ignore-scripts to pnpm install in ci.yml — closes the Axios/Bitwarden/Shai-Hulud preinstall-hook attack class and locks CI to the committed lockfile in one line each.
→ Add --require-hashes to pip install in ci.yml and regenerate requirements.txt with pip-compile --generate-hashes — closes the lightning 2.6.x (Apr 2026) wheel-poisoning attack class for any future install during a 0-day publish window.
→ Drop TWINE_PASSWORD from publish.yml and configure PyPI Trusted Publishing — removes the long-lived PyPI token stolen in ultralytics 8.3.41 (Dec 2024) and adds PEP 740 attestations on every release.
→ Pin 12 third-party actions to 40-char SHAs across 4 workflows — closes the tj-actions/changed-files (CVE-2025-30066) attack class that targeted both npm and PyPI publishing workflows.
```

**Never add after PASSING:** no patch blocks, no YAML, no offers to apply fixes. Output stops at the last ✅ or ➖ line.
