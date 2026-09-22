---
name: pypi-harden
description: Hardens Python projects against PyPI supply chain attacks. Audits installer configuration (uv, pip, Poetry, pdm), version pinning, lockfile + hash hygiene, release-age gate, sdist execution policy, and index integrity. Trigger with /supplychain:pypi-harden or /supplychain:pypi-harden <path>.
---

## Trigger

Activate on `/supplychain:pypi-harden` or `/supplychain:pypi-harden <path>`. Treat the path as project root, or use cwd.

## Background — why Python differs from npm

Python has no single `ignore-scripts` switch. Three install-time code paths exist:

1. **sdist build** — `setup.py` / `pyproject.toml` build hooks execute when pip resolves a source distribution. Mitigated by `--only-binary :all:`.
2. **Wheel `.pth` files** — execute on every Python startup if installed into site-packages. Not mitigated by `--only-binary`.
3. **`__init__.py` on import** — runs the first time the consumer imports the package. Lightning 2.6.2/2.6.3 (Apr 2026) used a hidden `_runtime/start.py` invoked from `__init__.py` to harvest GitHub/npm/cloud tokens and seed a worm. Wheels were poisoned, so an `--only-binary` policy alone would not have stopped it.

The primary defense available to consumers right now is the **release-age gate** (cooldown). Wheel-only and sdist controls are defense-in-depth.

## Step 1 — detect manager

```sh
echo "=== FILES ==="
ls pyproject.toml uv.lock poetry.lock pdm.lock Pipfile.lock pylock.toml requirements.txt requirements-*.txt 2>/dev/null || echo "NONE"
echo "PYPROJECT=$(ls pyproject.toml 2>/dev/null && echo PRESENT || echo ABSENT)"
echo "REQS_PRESENT=$(ls requirements.txt requirements-*.txt 2>/dev/null | tr '\n' ' ' || echo NONE)"
echo "UV_LOCK=$(ls uv.lock 2>/dev/null && echo PRESENT || echo ABSENT)"
echo "POETRY_LOCK=$(ls poetry.lock 2>/dev/null && echo PRESENT || echo ABSENT)"
echo "PDM_LOCK=$(ls pdm.lock 2>/dev/null && echo PRESENT || echo ABSENT)"
echo "PIPENV_LOCK=$(ls Pipfile.lock 2>/dev/null && echo PRESENT || echo ABSENT)"
echo "PYLOCK_TOML=$(ls pylock.toml 2>/dev/null && echo PRESENT || echo ABSENT)"
echo "=== TOOL_SECTIONS ===" && grep -nE '^\[tool\.(uv|poetry|pdm|hatch|setuptools|pipenv)' pyproject.toml 2>/dev/null || echo "NONE"
echo "=== BUILD_SYSTEM ===" && grep -A2 '^\[build-system\]' pyproject.toml 2>/dev/null || echo "NONE"
echo "=== REQUIRES_PYTHON ===" && grep -nE '(^requires-python|python\s*=\s*")' pyproject.toml 2>/dev/null || echo "NOT_SET"
echo "=== PYTHON_VERSION_FILE ===" && cat .python-version 2>/dev/null || echo "ABSENT"
```

Then per-manager probe (single bash call). Run all blocks whose lock/section was detected — multi-tool repos exist.

**uv:**
```sh
echo "=== UV ==="
echo "UV_VERSION=$(uv --version 2>/dev/null | awk '{print $2}')"
echo "=== UV_PYPROJECT ===" && grep -nE '^(exclude-newer|exclude-newer-package|no-build|no-binary|index-strategy|required-version|index-url|extra-index-url)' pyproject.toml 2>/dev/null
echo "=== UV_TOOL_SECTION ===" && awk '/^\[tool\.uv\]/,/^\[/' pyproject.toml 2>/dev/null | grep -vE '^\[' | head -40
echo "=== UV_TOML ===" && cat uv.toml .config/uv/uv.toml 2>/dev/null || echo "NONE"
echo "=== UV_SOURCES ===" && awk '/^\[tool\.uv\.sources\]/,/^\[/' pyproject.toml 2>/dev/null | grep -vE '^\[' | head -20
echo "=== UV_INDEXES ===" && awk '/^\[\[tool\.uv\.index\]\]/,/^\[\[/' pyproject.toml 2>/dev/null | head -40
```

**Poetry:**
```sh
echo "=== POETRY ==="
echo "POETRY_VERSION=$(poetry --version 2>/dev/null | awk '{print $3}' | tr -d ')')"
echo "=== POETRY_DEPS ===" && awk '/^\[tool\.poetry\.dependencies\]/,/^\[/' pyproject.toml 2>/dev/null | grep -vE '^\[' | head -30
echo "=== POETRY_SOURCES ===" && awk '/^\[\[tool\.poetry\.source\]\]/,/^\[\[/' pyproject.toml 2>/dev/null | head -30
echo "=== POETRY_REQUIRES ===" && grep -nE '(requires-poetry|poetry-core)' pyproject.toml 2>/dev/null || echo "NOT_SET"
```

**pip / pip-tools:**
```sh
echo "=== PIP ==="
echo "PIP_VERSION=$(pip --version 2>/dev/null | awk '{print $2}')"
echo "=== PIP_CONF ===" && cat pip.conf .pip/pip.conf 2>/dev/null || echo "NONE"
echo "=== REQS_HASH_MODE ===" && grep -lE '^\s*--hash=' requirements*.txt 2>/dev/null || echo "ABSENT"
echo "=== REQS_INDEX_URL ===" && grep -nE '^\s*(--index-url|--extra-index-url|--trusted-host)' requirements*.txt 2>/dev/null || echo "NONE"
echo "=== REQS_EXOTIC ===" && grep -nE '^\s*(git\+|https?://|file://|\./|\.\./)' requirements*.txt 2>/dev/null || echo "NONE"
echo "=== REQS_RANGES ===" && grep -nE '^[a-zA-Z][^=]*[><~!]=?[^=]' requirements*.txt 2>/dev/null | grep -vE '^\s*#' | head -20 || echo "NONE"
echo "=== REQS_EXACT_COUNT ===" && grep -cE '^[a-zA-Z][^=]*==' requirements*.txt 2>/dev/null
echo "=== PIP_COMPILE_HEADER ===" && head -5 requirements*.txt 2>/dev/null | grep -E 'pip-compile|uv pip compile|by uv' || echo "NONE"
echo "=== REQS_UNCONSTRAINED ===" && grep -nE '^[a-zA-Z][a-zA-Z0-9._-]*\s*$' requirements*.txt 2>/dev/null | grep -vE '^\s*#' | head -20 || echo "NONE"
echo "REQS_UNCONSTRAINED_COUNT=$(grep -cE '^[a-zA-Z][a-zA-Z0-9._-]*\s*$' requirements*.txt 2>/dev/null | awk '{s+=$1} END {print s+0}')"
```

**pdm:**
```sh
echo "=== PDM ==="
echo "PDM_VERSION=$(pdm --version 2>/dev/null | awk '{print $3}')"
echo "=== PDM_RESOLUTION ===" && awk '/^\[tool\.pdm\.resolution\]/,/^\[/' pyproject.toml 2>/dev/null | grep -vE '^\[' | head -20
echo "=== PDM_SOURCES ===" && awk '/^\[\[tool\.pdm\.source\]\]/,/^\[\[/' pyproject.toml 2>/dev/null | head -30
```

## Step 1.5 — derive flags

From Step 1 output, compute these once and reference downstream by name.

- `MANAGERS`: list. uv if `UV_LOCK=PRESENT` or `[tool.uv]` present. Poetry if `POETRY_LOCK=PRESENT` or `[tool.poetry]` present. pdm if `PDM_LOCK=PRESENT`. pipenv if `PIPENV_LOCK=PRESENT`. pip if `REQS_PRESENT` ≠ NONE and no other lockfile claims it. Multiple permitted.
- `PRIMARY_MGR`: precedence uv > Poetry > pdm > pipenv > pip. Section ordering only; checks still run for every detected manager.
- `RELEASE_AGE_AVAILABLE`: per-manager boolean.
  - uv: YES (any version).
  - pip: YES if `PIP_VERSION` ≥ `26.0` (absolute date) — uplift to "duration" if ≥ `26.1`. NO if `< 26.0`. UNKNOWN if unparseable.
  - Poetry: NO until PR #10824 ships. Flag as ecosystem gap.
  - pdm: NO native support. Flag as ecosystem gap.
- `LOCKFILE_KIND`: `uv.lock` | `poetry.lock` | `pdm.lock` | `Pipfile.lock` | `pylock.toml` | `requirements.txt+hashes` | `requirements.txt-no-hashes` | `none`.
- `LOCKFILE_GITIGNORED`: YES if `.gitignore` lists the detected lockfile.
- `HASHED_REQS`: YES if `REQS_HASH_MODE` non-empty. NO if requirements.txt present but no `--hash=` lines.
- `UNCONSTRAINED_PKGS`: names from `REQS_UNCONSTRAINED`. Count = `REQS_UNCONSTRAINED_COUNT`.
- `WHEEL_ONLY`: YES if `pip.conf` contains `only-binary = :all:` or `[tool.uv] no-build = true`. NO otherwise.
- `EXTRA_INDEX`: YES if any `extra-index-url` found in `pip.conf`, `requirements*.txt`, `pyproject.toml`, or `uv.toml`.
- `EXOTIC_DEPS`: list of direct-URL / VCS / local path entries from `REQS_EXOTIC` and equivalent pyproject scans.

## Step 2 — version rules

- **pip < 26.0**: `--uploaded-prior-to` not available. Primary recommendation: switch the install step to `uv pip sync` (available today, no pip upgrade needed; configure `[tool.uv] exclude-newer = "7 days"`). Secondary: upgrade pip ≥26.1 and use `[install] uploaded-prior-to = P7D` in `pip.conf`.
- **pip 26.0**: only absolute dates supported — flag durations as "requires pip ≥ 26.1".
- **Poetry (any version)**: native release-age gate not yet shipped (issue #10646, PR #10824 in review). Workarounds: maintain the lockfile via Renovate with `minimumReleaseAge`, or generate `requirements.txt` from `poetry export` then run `uv pip compile --exclude-newer` ahead of install.
- **pdm**: same gap. Same workarounds.

## Step 3 — checks

Apply only checks for detected managers. Order findings by manager (primary first), then by category.

**Release-age gate**

uv: read `UV_TOOL_SECTION` and `UV_TOML` for `exclude-newer`. Accepts ISO 8601 duration (`"7 days"`, `"P7D"`, `"1w"`) or absolute RFC 3339 timestamp.
- Absent → 🚨 CRITICAL "release age: 0d (uv) — every newly published version installs immediately. e.g. lightning 2.6.2/2.6.3 (Apr 2026) shipped a malicious wheel that runs `_runtime/start.py` on import, harvesting GitHub/npm/cloud credentials and worming through repos via planted `.claude/router_runtime.js` files. Socket detected and quarantined within hours; a 7-day exclude-newer window would have prevented installation entirely."
- `< P1D` → ⚠️ WARN.
- `P1D`–`P6D` → ✅ PASS + note "consider 7 days".
- `≥ P7D` → ✅ PASS.
- `exclude-newer-package` set without base `exclude-newer` → 🚨 CRITICAL "per-package overrides set but global gate inactive — false security posture. e.g. lightning 2.6.2 would have installed silently despite the apparent configuration."

pip: read `PIP_CONF` for `[install] uploaded-prior-to`.
- `PIP_VERSION < 26.0` → ⚠️ WARN "pip {version}: release-age gate unavailable. Switch install step to `uv pip sync` today (no upgrade needed) and add `[tool.uv] exclude-newer = \"7 days\"` to pyproject.toml — or upgrade pip ≥26.1 and set `[install] uploaded-prior-to = P7D` in `pip.conf`." Skip the rest.
- Absent (pip ≥26.0) → 🚨 CRITICAL "release age: 0d (pip) — every newly published version installs immediately. e.g. lightning 2.6.2/2.6.3 (Apr 2026) — see incident details above. Add `[install] uploaded-prior-to = P7D` to `pip.conf` (pip ≥26.1) or use `uv` for the install step."
- Present → parse value, apply same `< P1D` / 1-6 / ≥7 verdicts as uv.

Poetry: `RELEASE_AGE_AVAILABLE=NO` → 🔶 FAIL "Poetry has no native release-age gate (issue #10646, PR #10824 pending). Workarounds: (1) commit `poetry.lock` and use Renovate with `minimumReleaseAge: '7 days'`; or (2) use `poetry export -f requirements.txt --output requirements.txt` then install with `uv pip install -r requirements.txt --exclude-newer 7d` in CI."

pdm: same as Poetry — flag and suggest Renovate / uv-driven install.

**Lockfile + hash mode**

`LOCKFILE_KIND=none` → 🚨 CRITICAL "no lockfile — every install resolves versions fresh from the registry. e.g. running `pip install` during the lightning 2.6.x window (Apr 2026) would have pulled the malicious wheel with no version barrier."

`LOCKFILE_GITIGNORED=YES` → 🚨 CRITICAL "lockfile gitignored — frozen-install enforcement has no baseline; CI silently falls back to fresh resolution. Remove the lockfile entry from `.gitignore` and commit it."

`LOCKFILE_KIND=requirements.txt-no-hashes` → 🔶 FAIL "`requirements.txt` not compiled — no artifact hashes{, and `REQS_UNCONSTRAINED_COUNT` packages unconstrained: list up to 5 from `UNCONSTRAINED_PKGS`}. Pip cannot verify what it installs. Fix: `uv pip compile <source> --generate-hashes -o <output>`, then `uv pip sync --require-hashes <output>` (or `pip install --require-hashes -r <output>`)." Omit the unconstrained clause if `REQS_UNCONSTRAINED_COUNT=0`.

`LOCKFILE_KIND` is `uv.lock` / `poetry.lock` / `pdm.lock` / `Pipfile.lock` / `pylock.toml` / `requirements.txt+hashes` → ✅ PASS. If `pylock.toml` detected, add ✅ note "PEP 751 lockfile — interoperable across pip ≥26.1, uv, pdm."

**Install-time code execution policy**

Read `WHEEL_ONLY` and the package config for `no-build` (uv) / `only-binary = :all:` (pip).

- pip + `pip.conf` missing `only-binary = :all:` → ⚠️ WARN "no sdist policy — `setup.py` executes on install. e.g. ctx (May 2022) exfiltrated AWS env vars via `setup.py`. Add `[install] only-binary = :all:` to `pip.conf`; use `--no-binary <pkg>` for sdist-only deps. (Does not stop `__init__.py` import-time exec — lightning 2.6.x lived in a wheel. Release-age gate is the primary control.)"
- uv + `[tool.uv]` missing `no-build = true` → ⚠️ WARN "no sdist policy in uv config. Add `no-build = true` to `[tool.uv]`. (Does not stop import-time exec — pair with `exclude-newer`.)"
- Both absent but `WHEEL_ONLY=YES` → ✅ PASS.

**Index integrity (dependency confusion)**

`EXTRA_INDEX=YES` → 🔶 FAIL "`extra-index-url` configured — pip and uv consult **all** indexes and pick the highest version match. A public PyPI package matching an internal package name shadows the internal one. e.g. the 2021 dependency-confusion class affected dozens of large orgs; PyPI typosquats of internal package names ship monthly. Use a single `index-url` pointing at your internal mirror with PyPI proxied through it, or set `index-strategy = \"first-index\"` (uv) / `unsafe-package` overrides explicitly."

uv `index-strategy = "unsafe-best-match"` → 🔶 FAIL "uv index-strategy explicitly disables first-index priority — same dependency-confusion risk as `extra-index-url` on pip. Remove the override; uv defaults to `first-index`."

requirements.txt or env contains `--trusted-host` → 🚨 CRITICAL "`--trusted-host` disables TLS verification for the listed host — any on-path attacker (corporate proxy, Wi-Fi MITM, malicious mirror) can swap wheels. e.g. internal mirrors with self-signed certs are the typical excuse; replace with a properly-issued certificate or a CA the runner trusts."

All clean → ✅ PASS.

**Exotic sources** (direct URL, VCS, local path)

`EXOTIC_DEPS` non-empty → 🔶 FAIL "direct-URL / VCS / local-path dependencies bypass the release-age gate, the index-integrity controls, and (for `git+`) the lockfile hash. Pin to a published wheel on a trusted index, or vendor the dependency."

List up to 5; 6+ → count + first 5.

`EXOTIC_DEPS` empty → ✅ PASS.

**Tool version pinning** (analogue of `packageManager`)

- `REQUIRES_PYTHON=NOT_SET` → ⚠️ WARN "`requires-python` not declared — Python version floats between developer and CI environments. Add `requires-python = \">=3.11,<3.13\"` (or your supported range) to `[project]` in pyproject.toml."
- uv `[tool.uv] required-version` absent → ⚠️ WARN "no uv version constraint — CI and developer machines may run different uv versions with different default settings. Add `required-version = \">=0.5\"` (or your floor) to `[tool.uv]`."
- Poetry `requires-poetry` / `poetry-core` version range too broad → ⚠️ WARN.
- `.python-version` present and matches `requires-python` → ✅ note "pinned via `.python-version`".

**Version ranges**

requirements.txt path: ranges are subsumed by the Lockfile + hash mode check above. `HASHED_REQS=YES` → ✅ PASS (hashes anchor exact versions; range syntax in source `.in` files is fine). `HASHED_REQS=NO` → already reported as 🔶 FAIL under Lockfile — do not emit a duplicate finding here.

pyproject.toml path (lockfile-based tools): ranges in `[project] dependencies` or `[tool.poetry.dependencies]` are fine while the lockfile is the install source. Only flag if lockfile absent (already CRITICAL above) or if a developer could `pip install -e .` without the lockfile — emit at most one ⚠️ WARN.

## Step 4 — output format

**HARD STOP: output ends after ✅ PASSING. Do not generate patch files, config summaries, TOML blocks, or offers to apply fixes. Each fix is already specified inline in its section. Adding anything after PASSING is explicitly prohibited.**

**Brevity rule:** Each finding = one sentence (problem) + one `└─` fix line. Reserve the `e.g.` incident line for 🚨 CRITICAL findings only — omit it for 🔶 FAIL and ⚠️ WARN. Do not repeat the same fix command across multiple findings.

Each check appears exactly once inside its category. PASSING goes last.

**Icon system — same as `npm-harden`:**
- 🚨 CRITICAL — release age 0 with no global, exclude-newer-package without base, lockfile gitignored, `--trusted-host` set, no lockfile.
- 🔶 FAIL — real gap needing a fix (no hash mode in requirements, exotic deps, extra-index-url, Poetry/pdm release-age unavailable).
- ⚠️ WARN — hardening opportunity, not immediately exploitable.
- ✅ PASS — clean, shown last.
- ➖ N/A.

Apply the highest-severity finding's icon to the section header.

**Structure:**

```
/supplychain:pypi-harden · [project name] ([primary manager] [version])
🚨 N critical  🔶 N failing  ⚠️ N hardening  ✅ N passing
→ [top fix]
📖 Hardening guide: https://pip.pypa.io/en/stable/topics/secure-installs/

[sections...]
```

Omit any zero-count category from line 2. If everything passes: `✅ all passing`.

Line 2 counts *checks*, not sections.

**Hardening-guide link** (line 4, plain URL — no markdown link syntax, renders cleanly in monospace):

| `PRIMARY_MGR` | URL |
|---------------|-----|
| `uv` | `https://docs.astral.sh/uv/concepts/resolution/` |
| `poetry` | `https://python-poetry.org/docs/dependency-specification/` |
| `pip` / `pip-tools` | `https://pip.pypa.io/en/stable/topics/secure-installs/` |
| `pdm` | `https://pdm-project.org/latest/usage/lockfile/` |

Emit exactly one line. If `PRIMARY_MGR` undetermined, omit the 📖 line.

**Fix line format:**

```
        └─ [filename]: [exact config value]
```

Examples:
```
        └─ pyproject.toml: [tool.uv] exclude-newer = "7 days"
        └─ pip.conf: [install] uploaded-prior-to = P7D
        └─ pyproject.toml: requires-python = ">=3.11,<3.13"
        └─ requirements.txt: regenerate via `pip-compile --generate-hashes`
        └─ .gitignore: remove `uv.lock` line
```

**Incident examples in CRITICAL findings:**

Step 3 is the **sole source** for finding wording. Copy both the first clause and the full `e.g.` line **verbatim** from the matching Step 3 definition. Do not paraphrase, shorten, re-order incidents, or combine multiple incidents into a new sentence.

Layout template (placeholders are structural only — do not emit them literally):
```
  🚨 <Check name>  <first clause, verbatim from Step 3>
          <full e.g. line, verbatim from Step 3>
          └─ <file>: <exact config value>
```

Format: `→ [verb] [what with exact values] — [impact]`

**Never add after PASSING:** no patch blocks, no TOML, no "Want me to apply?" — output stops at the last ✅ or ➖ line. This is a hard rule.
