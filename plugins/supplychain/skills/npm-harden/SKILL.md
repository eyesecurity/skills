---
name: npm-harden
description: Hardens npm, pnpm, and Yarn v2+ projects against supply chain attacks. Audits package manager configuration, version pinning, and lockfile hygiene against 2025-2026 attack patterns. Trigger with /npm-harden or /npm-harden <path>.
---

## Trigger

Activate on `/npm-harden` or `/npm-harden <path>`. Treat the path as project root, or use cwd.

## Step 1 — detect manager

```sh
grep -oE '"packageManager":\s*"[^"@]*' package.json 2>/dev/null | grep -oE '[a-z]+$'
ls pnpm-lock.yaml yarn.lock package-lock.json 2>/dev/null || true
```

Detect from `packageManager` field, then from whichever lockfile is present. Run the matching block below as a single bash call.

**pnpm:**
```sh
echo "MGR=pnpm"
echo "PNPM_VERSION=$(pnpm --version 2>/dev/null)"
echo "GLOBAL_RELEASE_AGE=$(pnpm config get minimumReleaseAge 2>/dev/null)"
echo "LOCKFILE=$(ls pnpm-lock.yaml 2>/dev/null && echo PRESENT || echo ABSENT)"
echo "LOCKFILE_GITIGNORED=$(grep -qE 'pnpm-lock' .gitignore 2>/dev/null && echo YES || echo NO)"
echo "DANGEROUSLY=$(grep -qE '(dangerouslyAllowAllBuilds|dangerously-allow-all-builds)[:=]\s*true' pnpm-workspace.yaml .npmrc 2>/dev/null && echo YES || echo NO)"
echo "PKG_MANAGER_FIELD=$(grep -oE '"packageManager":\s*"[^"]*"' package.json 2>/dev/null | grep -oE '[a-z]+@[0-9][^"]*' || echo NOT_SET)"
echo "GLOBAL_IGNORE_SCRIPTS=$(pnpm config get ignore-scripts 2>/dev/null)"
echo "ONLY_ALLOW=$(grep -oE '"preinstall":\s*"[^"]*only-allow[^"]*"' package.json 2>/dev/null || echo NOT_SET)"
echo "=== RELEASE_AGE ===" && grep -E "minimumReleaseAge|minimum-release-age" pnpm-workspace.yaml .npmrc 2>/dev/null || echo "NOT_SET"
echo "=== NPMRC ===" && grep -E "ignore-scripts|ignoreScripts|minimum-release-age|minimumReleaseAge" .npmrc 2>/dev/null || echo "NOT_SET"
echo "=== BUILD_POLICY ===" && grep -E "dangerouslyAllowAllBuilds|allowBuilds|strictDepBuilds|onlyBuiltDependencies|ignoredBuiltDependencies" pnpm-workspace.yaml 2>/dev/null || echo "NOT_SET"
echo "=== HARDENING ===" && grep -E "blockExoticSubdeps|trustPolicy" pnpm-workspace.yaml 2>/dev/null || echo "NOT_SET"
echo "=== EXOTIC_DEPS ===" && grep -oE '"[^"]+": "(git\+?https?://[^"]+|github:[^"]+|bitbucket:[^"]+|gitlab:[^"]+|[^"]+\.tgz|file:\.\.)"' package.json 2>/dev/null || echo "NONE"
echo "RANGE_TOTAL=$(grep -cE '"[\^~]' package.json 2>/dev/null || echo 0)"
echo "=== PKG_NAME ===" && grep -oE '"name":\s*"[^"]*"' package.json 2>/dev/null | head -1
echo "=== RANGES ===" && grep -oE '"[^"]+": "[\^~][^"]*"' package.json 2>/dev/null | head -8
```

**npm:**
```sh
echo "MGR=npm"
echo "LOCKFILE=$(ls package-lock.json 2>/dev/null && echo PRESENT || echo ABSENT)"
echo "LOCKFILE_GITIGNORED=$(grep -qE 'package-lock' .gitignore 2>/dev/null && echo YES || echo NO)"
echo "PKG_MANAGER_FIELD=$(grep -oE '"packageManager":\s*"[^"]*"' package.json 2>/dev/null | grep -oE '[a-z]+@[0-9][^"]*' || echo NOT_SET)"
echo "=== NPMRC ===" && grep -E "ignore-scripts|min-release-age|minimum-release-age|minimumReleaseAge|save-exact" .npmrc 2>/dev/null || echo "NOT_SET"
echo "=== EXOTIC_DEPS ===" && grep -oE '"[^"]+": "(git\+?https?://[^"]+|github:[^"]+|bitbucket:[^"]+|gitlab:[^"]+|[^"]+\.tgz|file:\.\.)"' package.json 2>/dev/null || echo "NONE"
echo "RANGE_TOTAL=$(grep -cE '"[\^~]' package.json 2>/dev/null || echo 0)"
echo "=== PKG_NAME ===" && grep -oE '"name":\s*"[^"]*"' package.json 2>/dev/null | head -1
echo "=== RANGES ===" && grep -oE '"[^"]+": "[\^~][^"]*"' package.json 2>/dev/null | head -8
```

**Yarn:**
```sh
echo "MGR=yarn"
echo "YARN_VERSION=$(yarn --version 2>/dev/null)"
echo "LOCKFILE=$(ls yarn.lock 2>/dev/null && echo PRESENT || echo ABSENT)"
echo "LOCKFILE_GITIGNORED=$(grep -qE 'yarn\.lock' .gitignore 2>/dev/null && echo YES || echo NO)"
echo "PKG_MANAGER_FIELD=$(grep -oE '"packageManager":\s*"[^"]*"' package.json 2>/dev/null | grep -oE '[a-z]+@[0-9][^"]*' || echo NOT_SET)"
echo "=== YARNRC ===" && grep -E "enableScripts|npmMinimalAgeGate|defaultSemverRangePrefix" .yarnrc.yml 2>/dev/null || echo "NOT_SET"
echo "=== EXOTIC_DEPS ===" && grep -oE '"[^"]+": "(git\+?https?://[^"]+|github:[^"]+|bitbucket:[^"]+|gitlab:[^"]+|[^"]+\.tgz|file:\.\.)"' package.json 2>/dev/null || echo "NONE"
echo "RANGE_TOTAL=$(grep -cE '"[\^~]' package.json 2>/dev/null || echo 0)"
echo "=== PKG_NAME ===" && grep -oE '"name":\s*"[^"]*"' package.json 2>/dev/null | head -1
echo "=== RANGES ===" && grep -oE '"[^"]+": "[\^~][^"]*"' package.json 2>/dev/null | head -8
```

## Step 1.5 — derive version flags

From Step 1 output, compute the booleans below once and reference them by name in Step 3. Do not repeat version comparisons in prose downstream.

- `CVE_FLAG`: YES if `PNPM_VERSION` parses and is `< 10.26.2` (CVE-2025-69263/69264 unpatched). NO if parses and ≥. UNKNOWN if `PNPM_VERSION` empty/unparseable → emit ⚡ WARN "pnpm binary not found on PATH — CVE version check skipped; ensure installed version ≥10.26.2". N/A if `MGR` ≠ pnpm.
- `PKG_MGR_CVE`: YES if `PKG_MANAGER_FIELD` matches `pnpm@X.Y.Z` with X.Y.Z `< 10.26.2`. NO otherwise. Applies regardless of installed pnpm (project pin, not runtime).
- `YARN_SCRIPTS_OFF`: YES if `YARN_VERSION` parses and is `≥ 4.14.0` (scripts-off default landed). NO if parses and `<`. UNKNOWN if empty → ⚡ WARN "yarn binary not found — version check skipped". N/A if `MGR` ≠ yarn.

## Step 2 — version rules

**Yarn v1**: 🚨 CRITICAL for PM-1 — scripts run by default, no allowlist. Output: "Yarn Classic detected — lifecycle scripts enabled with no protection. Same exposure as npm without ignore-scripts. Migrate to pnpm or Yarn v4."
**Yarn v2/v3**: apply Yarn v2+ checks; scripts-off-by-default arrived in v4.14.
**pnpm < 10.0**: allowBuilds-as-default absent — flag.
**pnpm < 10.26.2**: CVE-2025-69263/69264 unpatched — git dep script bypass. Flag regardless.

## Step 3 — checks

Apply only checks for detected manager. Read signals from Step 1 output — do not re-read files.

**PM-1 Lifecycle script control**

pnpm: DANGEROUSLY=YES → 🚨 CRITICAL "dangerouslyAllowAllBuilds: true — all pnpm script protection disabled. e.g. Shai-Hulud (Sep 2025) used postinstall hooks to steal credentials from 796 packages; this setting would have let it run." DANGEROUSLY=NO → ✅ PASS (pnpm v10 default). Then read BUILD_POLICY extraction: if `allowBuilds` present, list packages and flag non-native entries (expected: esbuild, sharp, canvas, fsevents, node-gyp); if `onlyBuiltDependencies`/`ignoredBuiltDependencies` present, note migration to `allowBuilds`; if `strictDepBuilds: true` absent, add ⚡ WARN to HARDENING section. Global-config credit: if `GLOBAL_IGNORE_SCRIPTS=true` or `NPMRC` contains `ignore-scripts=true` / `ignoreScripts=true`, add ✅ note "lifecycle scripts globally disabled via pnpm config — defence-in-depth on top of the v10 default".

npm: Read NPMRC for `ignore-scripts`. Not found or `ignore-scripts=false` → 🚨 CRITICAL "lifecycle scripts enabled by default — preinstall/install/postinstall run on every npm install. e.g. Axios 1.14.1 (Mar 2026) used a postinstall hook to deploy a cross-platform RAT during a 3h window; @bitwarden/cli 2026.4.0 (Apr 2026) used the preinstall hook to harvest GitHub tokens, AWS/GCP/Azure secrets, shell history, and AI-tool configs from every machine that ran npm install." `ignore-scripts=true` → PASS (check PackageGate: if EXOTIC_DEPS ≠ NONE, downgrade to ⚡ WARN).

Yarn Classic (v1): 🚨 CRITICAL "Yarn Classic — scripts run by default with no allowlist. Same exposure as npm without ignore-scripts. e.g. Shai-Hulud's postinstall worm would have executed on every yarn install. Migrate to pnpm or Yarn v4."

Yarn v2+:
- `YARN_SCRIPTS_OFF=NO` (pre-v4.14): read YARNRC for `enableScripts`. Absent → ⚡ WARN "pre-v4.14 Yarn — scripts-off default arrived in v4.14; upgrade or set `enableScripts: false` explicitly."
- `YARN_SCRIPTS_OFF=YES` (v4.14+): `enableScripts` absent/false → ✅ PASS. `enableScripts: true` → 🚨 CRITICAL "explicitly re-enabled lifecycle scripts — Yarn v4.14 ships with scripts off; this reverses that. e.g. Shai-Hulud's postinstall payload would execute on every yarn install."

**PM-2 Release age gate**

Read RELEASE_AGE extraction (and GLOBAL_RELEASE_AGE for pnpm). Normalise to days for output.

Unit conversion: pnpm value ÷ 1440 = days (10080 = 7d; if >43800 → WARN wrong unit). Yarn: parse string ("7d"/"1w"/"168h" = 7d; raw int → WARN ambiguous unit). npm: value ÷ 86400 = days (seconds, since npm v11.10.0; 604800 = 7d). Key in `.npmrc` accepted as `min-release-age`, `minimum-release-age`, or camelCase `minimumReleaseAge`.

Effective value: project `RELEASE_AGE` takes precedence; if absent and `MGR=pnpm`, fall back to `GLOBAL_RELEASE_AGE`. Convert to days, then apply verdicts.

Verdicts:
- Project NOT_SET, no exclude list, AND (npm/yarn OR pnpm global also NOT_SET/0) → 🚨 CRITICAL "release age: 0d — every newly published version installs immediately. e.g. Axios 1.14.1 (Mar 2026) was live for 3h, Shai-Hulud 2.0 (Nov 2025) for 12h, chalk/debug (Sep 2025) for 2.5h — all would have landed."
- Project NOT_SET, pnpm `GLOBAL_RELEASE_AGE` ≥10080 (7d) → ✅ PASS + note "pnpm global config supplies minimumReleaseAge={N}d — consider committing to `pnpm-workspace.yaml` for team visibility and new-joiner parity."
- Project NOT_SET, pnpm `GLOBAL_RELEASE_AGE` 1-6d → ⚡ WARN "global config has release age <7d — raise to 10080 and commit to workspace file."
- Exclude present, base NOT_SET (and no global fallback) → 🚨 CRITICAL "exclude list set but gate inactive — team believes release-age protection is on; it is not. e.g. Axios 1.14.1 would have installed silently despite the apparent configuration."
- Exclude present, base set → ✅ note excluded packages, flag non-internal-scoped ones
- <1d → ⚡ WARN
- 1–6d → ✅ PASS + note "consider 7d"
- ≥7d → ✅ PASS

**PM-3 packageManager field**

Read PKG_MANAGER_FIELD signal.

- `NOT_SET` → ⚡ WARN "packageManager field absent — manager version floats between environments. Add `\"packageManager\": \"pnpm@x.y.z\"` to package.json."
- Present, fully pinned with patch (e.g. `pnpm@10.26.2`) → if `PKG_MGR_CVE=YES` → 🚨 CRITICAL "pinned to CVE-affected version — update to ≥10.26.2. e.g. pnpm <10.26.2 allows a git dependency to override the git binary via .npmrc and execute scripts even with dangerouslyAllowAllBuilds: false (CVE-2025-69263)." Else → ✅ PASS.
- Present, partially pinned (e.g. `pnpm@10` or `pnpm@10.26`) → ⚡ WARN "missing patch version — pin to exact (e.g. pnpm@10.26.2) to prevent silent patch updates."

**PM-4 Lockfile**

Read LOCKFILE signal. ABSENT → 🚨 CRITICAL "no lockfile — every install resolves versions fresh from the registry. e.g. running pnpm install during Axios's 3h attack window would have pulled 1.14.1 with no barrier." Read LOCKFILE_GITIGNORED. YES → 🚨 CRITICAL "lockfile gitignored — --frozen-lockfile has no baseline to enforce; teams fall back to unfrozen installs. e.g. Axios 1.14.1 would resolve on any CI run during the attack window." Both OK → ✅ PASS.

**PM-5 Exotic sources**

Read EXOTIC_DEPS. NONE → ✅ PASS for direct deps. Then read HARDENING for `blockExoticSubdeps`: present+true → ✅; absent → ⚡ WARN (pnpm only).
npm + EXOTIC_DEPS ≠ NONE → 🔶 FAIL (PackageGate unpatched bypass).
pnpm + EXOTIC_DEPS ≠ NONE + `CVE_FLAG=YES` → 🔶 FAIL (CVE-2025-69263/69264 — git dep can override git binary via .npmrc).
pnpm + EXOTIC_DEPS ≠ NONE + `CVE_FLAG=NO` → ⚡ WARN.
pnpm + EXOTIC_DEPS ≠ NONE + `CVE_FLAG=UNKNOWN` → ⚡ WARN "exotic deps present; pnpm version unverifiable — ensure ≥10.26.2 before install."

**PM-6 Trust policy** (pnpm only)

Read HARDENING for `trustPolicy`. `no-downgrade` present → ✅ PASS. Absent → ⚡ WARN.

**PM-7 Version ranges**

Read `RANGE_TOTAL`. `0` → ✅ PASS immediately, no further processing.

If `>0`: read `PKG_NAME` to determine internal scope (e.g. `@eyectrl-engineering`, `@eye`). Classify each entry in `RANGES` as internal (matches own scope) or external.

Verdicts — ranges are the belt-and-suspenders layer. Release-age + lockfile + CI frozen-install carry the primary weight; when those three hold, ranges are a reproducibility concern, not an acute supply-chain risk.

- All internal → ⚡ WARN "internal `^`/`~` ranges — tighten to exact for reproducibility; supply-chain risk already contained by lockfile + CI frozen install."
- Any external + `PM-4=PASS` (lockfile committed + not gitignored) → ⚡ WARN "external `^`/`~` ranges present. Committed lockfile contains the acute risk; remaining exposure is manual `npm/pnpm/yarn install` or `update` calls by developers that bypass the lockfile. Run `/npm-ci-audit` to verify CI enforces `--frozen-lockfile` / `--immutable`. Pin to exact versions for defence-in-depth." List up to 5 external from `RANGES`; 6+ → count + first 5.
- Any external + `PM-4=FAIL` (lockfile absent or gitignored) → 🔶 FAIL "external `^`/`~` ranges combined with the PM-4 lockfile gap — unfrozen install resolves fresh from registry and a malicious patch cleared of the release-age gate lands automatically." List up to 5 external.

Config tie-ins (print under the finding as additional `└─` lines if applicable):
- npm: `NPMRC` missing `save-exact=true` → add ⚡ WARN note and suggest `└─ .npmrc: save-exact=true`.
- Yarn: `YARNRC` missing `defaultSemverRangePrefix` → add ⚡ WARN note and suggest `└─ .yarnrc.yml: defaultSemverRangePrefix: ""`.
- pnpm: no equivalent config; suggest only exact-pin fixups in `package.json`.

Fix-line examples:
```
        └─ package.json: replace "^1.2.3" with "1.2.3" (exact pin)
        └─ .npmrc: save-exact=true
        └─ .yarnrc.yml: defaultSemverRangePrefix: ""
```

**PM-8 Manager enforcement** (pnpm only)

Read `ONLY_ALLOW`. Checks whether the project blocks teammates from accidentally running `npm install` / `yarn install` and bypassing pnpm's protections.

- Present (any `preinstall` matching `only-allow` or `only-allow pnpm`) → ✅ PASS "preinstall guard blocks non-pnpm installs".
- `NOT_SET` → ⚡ WARN "no preinstall guard — a teammate running `npm install` out of habit silently creates `package-lock.json`, installs without pnpm's release-age gate, and runs lifecycle scripts with npm defaults. Add `\"preinstall\": \"npx only-allow pnpm\"` to package.json scripts."

Fix line:
```
        └─ package.json: "scripts": { "preinstall": "npx only-allow pnpm" }
```

## Step 4 — output format

**HARD STOP: output ends after ✅ PASSING. Do not generate patch files, config summaries, YAML blocks, or offers to apply fixes. Each fix is already specified inline in its section. Adding anything after PASSING is explicitly prohibited.**

No separate check results block. Each check appears exactly once inside its category. PASSING goes last.

**Icon system — shape and color both carry meaning:**
- 🚨 CRITICAL — any of: unpatched CVE in installed tooling; dangerouslyAllowAllBuilds: true; npm ignore-scripts absent (scripts run by default — primary attack vector); release age not configured on any manager; minimumReleaseAgeExclude set without minimumReleaseAge (false security posture); lockfile gitignored. Do not use for optional hardening gaps.
- 🔶 FAIL — real gap needing a fix (Yarn Classic, lockfile absent, exotic deps with CVE exposure, external ranges + lockfile gap)
- ⚡ WARN — hardening opportunity, not immediately exploitable
- ✅ PASS — clean, shown last
- ➖ N/A

pnpm is safer by default (scripts off in v10, more security settings available) so pnpm projects have fewer CRITICAL findings than npm for the same security posture. This is correct and expected.

Apply the same icon to the section header as to its highest-severity item.

**Structure:**

```
/npm-harden · [project name] ([manager] [version])
🚨 N critical  🔶 N failing  ⚡ N hardening  ✅ N passing
→ [top fix]
📖 Hardening guide: [manager docs URL — see table below]

[sections...]
```

Omit any zero-count category from line 2. If everything passes: `✅ all passing`.

Line 2 is a count of *checks*, not sections. Count each PM finding that has a result.

**Hardening-guide link** (line 4, one line, plain URL — no markdown link syntax, renders cleanly in monospace):

| `MGR` | URL |
|-------|-----|
| `pnpm` | `https://pnpm.io/supply-chain-security` |
| `npm` | `https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/` |
| `yarn` (v1 or v2+) | `https://yarnpkg.com/features/security` |

Emit exactly one line. If `MGR` is unknown, omit the 📖 line entirely.

**Fix line format — every fix uses this pattern:**
```
        └─ [filename]: [exact config value]
```
The `└─` prefix visually separates the fix from the description above it without relying on markdown rendering. No backticks — they appear literally in Claude Code's output pane and add noise.

Examples:
```
        └─ pnpm-workspace.yaml: minimumReleaseAge: 10080  # 7 days in minutes
        └─ package.json: "packageManager": "pnpm@10.26.2"
        └─ .npmrc: ignore-scripts=true
        └─ pnpm-workspace.yaml: strictDepBuilds: true
```

**Incident examples in CRITICAL findings:**

Step 3 is the **sole source** for finding wording. Copy both the first clause and the full `e.g.` line **verbatim** from the matching Step 3 definition. Do not paraphrase, shorten, re-order incidents, or combine multiple incidents into a new sentence. If Step 3 lists three incidents, output all three.

Layout template (placeholders are structural only — do not emit them literally):
```
  🚨 PMx  <first clause, verbatim from Step 3>
          <full e.g. line, verbatim from Step 3>
          └─ <file>: <exact config value>
```
Name specific files and exact values. If CVE present, include it first. Do not repeat any finding line elsewhere in the output.

Format: `→ [verb] [what with exact values] — [impact]`

**Never add after PASSING:** no patch blocks, no config summaries, no YAML, no "Want me to apply?" — output stops at the last ✅ or ➖ line. This is a hard rule.
