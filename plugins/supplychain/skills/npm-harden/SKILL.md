---
name: npm-harden
description: Hardens npm, pnpm, and Yarn Berry projects against supply chain attacks. Audits package manager configuration, version pinning, and lockfile hygiene against 2025-2026 attack patterns. Trigger with /npm-harden or /npm-harden <path>.
---

## Trigger

Activate on `/npm-harden` or `/npm-harden <path>`. Treat the path as project root, or use cwd.

## Step 1 — detect manager

```sh
grep -oE '"packageManager":\s*"[^"@]*' package.json 2>/dev/null | grep -oE '[a-z]+$'
ls pnpm-lock.yaml yarn.lock package-lock.json bun.lock 2>/dev/null || true
```

Detect from `packageManager` field, then from whichever lockfile is present. Run the matching block below as a single bash call.

**pnpm:**
```sh
echo "MGR=pnpm"
echo "PNPM_VERSION=$(pnpm --version 2>/dev/null)"
echo "GLOBAL_RELEASE_AGE=$(pnpm config get minimumReleaseAge 2>/dev/null)"
echo "LOCKFILE=$(ls pnpm-lock.yaml 2>/dev/null && echo PRESENT || echo ABSENT)"
echo "LOCKFILE_GITIGNORED=$(grep -qE 'pnpm-lock' .gitignore 2>/dev/null && echo YES || echo NO)"
echo "DANGEROUSLY=$(grep -qE 'dangerouslyAllowAllBuilds:\s*true' pnpm-workspace.yaml 2>/dev/null && echo YES || echo NO)"
echo "PKG_MANAGER_FIELD=$(grep -oE '"packageManager":\s*"[^"]*"' package.json 2>/dev/null | grep -oE '[a-z]+@[0-9][^"]*' || echo NOT_SET)"
echo "=== RELEASE_AGE ===" && grep -E "minimumReleaseAge" pnpm-workspace.yaml .npmrc 2>/dev/null || echo "NOT_SET"
echo "=== BUILD_POLICY ===" && grep -E "dangerouslyAllowAllBuilds|allowBuilds|strictDepBuilds|onlyBuiltDependencies|ignoredBuiltDependencies" pnpm-workspace.yaml 2>/dev/null || echo "NOT_SET"
echo "=== HARDENING ===" && grep -E "blockExoticSubdeps|trustPolicy" pnpm-workspace.yaml 2>/dev/null || echo "NOT_SET"
echo "=== EXOTIC_DEPS ===" && grep -oE '"[^"]+": "(git\+?https?://[^"]+|github:[^"]+|bitbucket:[^"]+|gitlab:[^"]+|[^"]+\.tgz|file:\.\.)"' package.json 2>/dev/null || echo "NONE"
```

**npm:**
```sh
echo "MGR=npm"
echo "LOCKFILE=$(ls package-lock.json 2>/dev/null && echo PRESENT || echo ABSENT)"
echo "LOCKFILE_GITIGNORED=$(grep -qE 'package-lock' .gitignore 2>/dev/null && echo YES || echo NO)"
echo "PKG_MANAGER_FIELD=$(grep -oE '"packageManager":\s*"[^"]*"' package.json 2>/dev/null | grep -oE '[a-z]+@[0-9][^"]*' || echo NOT_SET)"
echo "=== NPMRC ===" && grep -E "ignore-scripts|min-release-age|save-exact" .npmrc 2>/dev/null || echo "NOT_SET"
echo "=== EXOTIC_DEPS ===" && grep -oE '"[^"]+": "(git\+?https?://[^"]+|github:[^"]+|bitbucket:[^"]+|gitlab:[^"]+|[^"]+\.tgz|file:\.\.)"' package.json 2>/dev/null || echo "NONE"
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
```

## Step 2 — version rules

**Yarn v1**: 🚨 CRITICAL for PM-1 — scripts run by default, no allowlist. Output: "Yarn Classic detected — lifecycle scripts enabled with no protection. Same exposure as npm without ignore-scripts. Migrate to pnpm or Yarn Berry v4."
**Yarn v2/v3**: apply Berry checks; scripts-off-by-default arrived in v4.14.
**pnpm < 10.0**: allowBuilds-as-default absent — flag.
**pnpm < 10.26.2**: CVE-2025-69263/69264 unpatched — git dep script bypass. Flag regardless.

## Step 3 — checks

Apply only checks for detected manager. Read signals from Step 1 output — do not re-read files.

**PM-1 Lifecycle script control**

pnpm: DANGEROUSLY=YES → 🚨 CRITICAL "dangerouslyAllowAllBuilds: true — all pnpm script protection disabled. e.g. Shai-Hulud (Sep 2025) used postinstall hooks to steal credentials from 796 packages; this setting would have let it run." DANGEROUSLY=NO → ✅ PASS (pnpm v10 default). Then read BUILD_POLICY extraction: if `allowBuilds` present, list packages and flag non-native entries (expected: esbuild, sharp, canvas, fsevents, node-gyp); if `onlyBuiltDependencies`/`ignoredBuiltDependencies` present, note migration to `allowBuilds`; if `strictDepBuilds: true` absent, add ⚡ WARN to HARDENING section.

npm: Read NPMRC for `ignore-scripts`. Not found or `ignore-scripts=false` → 🚨 CRITICAL "lifecycle scripts enabled by default — preinstall/install/postinstall run on every npm install. e.g. Axios (Mar 2026) used a postinstall hook to deploy a cross-platform RAT to every machine that ran npm install during a 3h window." `ignore-scripts=true` → PASS (check PackageGate: if EXOTIC_DEPS ≠ NONE, downgrade to ⚡ WARN).

Yarn v1: 🚨 CRITICAL "Yarn Classic — scripts run by default with no allowlist. Same exposure as npm without ignore-scripts. e.g. Shai-Hulud's postinstall worm would have executed on every yarn install. Migrate to pnpm or Yarn Berry v4."
Yarn v2/v3: read YARNRC for `enableScripts`. Absent → ⚡ WARN "confirm Yarn ≥4.14 — scripts-off default arrived in v4.14."
Yarn ≥4.14: `enableScripts` absent/false → ✅ PASS. `enableScripts: true` → 🚨 CRITICAL "explicitly re-enabled lifecycle scripts — Yarn v4.14 ships with scripts off; this reverses that. e.g. Shai-Hulud's postinstall payload would execute on every yarn install."
Bun: ⚡ WARN "trustedDependencies validates names only, not sources — git dep with trusted name bypasses it."

**PM-2 Release age gate**

Read RELEASE_AGE extraction (and GLOBAL_RELEASE_AGE for pnpm). Normalise to days for output.

Unit conversion: pnpm value ÷ 1440 = days (10080 = 7d; if >43800 → WARN wrong unit). Bun ÷ 86400 = days. Yarn: parse string ("7d"/"1w"/"168h" = 7d; raw int → WARN ambiguous unit). npm: value already days.

Verdicts — apply to the *effective* value after conversion:
- NOT_SET with no exclude list → 🚨 CRITICAL "release age: 0d — every newly published version installs immediately. e.g. Axios 1.14.1 (Mar 2026) was live for 3h, Shai-Hulud 2.0 (Nov 2025) for 12h, chalk/debug (Sep 2025) for 2.5h — all would have landed."
- Exclude present, base NOT_SET → 🚨 CRITICAL "exclude list set but gate inactive — team believes release-age protection is on; it is not. e.g. Axios 1.14.1 would have installed silently despite the apparent configuration."
- Exclude present, base set → ✅ note excluded packages, flag non-internal-scoped ones
- <1d → ⚡ WARN
- 1–6d → ✅ PASS + note "consider 7d"
- ≥7d → ✅ PASS

**PM-3 packageManager field**

Read PKG_MANAGER_FIELD signal.

- `NOT_SET` → ⚡ WARN "packageManager field absent — manager version floats between environments. Add `\"packageManager\": \"pnpm@x.y.z\"` to package.json."
- Present, fully pinned with patch (e.g. `pnpm@10.26.2`) → ✅ PASS. Cross-check: if version is below known CVE threshold (pnpm < 10.26.2), escalate to 🚨 CRITICAL "pinned to CVE-affected version — update to ≥10.26.2. e.g. pnpm <10.26.2 allows a git dependency to override the git binary via .npmrc and execute scripts even with dangerouslyAllowAllBuilds: false (CVE-2025-69263)."
- Present, partially pinned (e.g. `pnpm@10` or `pnpm@10.26`) → ⚡ WARN "missing patch version — pin to exact (e.g. pnpm@10.26.2) to prevent silent patch updates."

**PM-4 Lockfile**

Read LOCKFILE signal. ABSENT → 🚨 CRITICAL "no lockfile — every install resolves versions fresh from the registry. e.g. running pnpm install during Axios's 3h attack window would have pulled 1.14.1 with no barrier." Read LOCKFILE_GITIGNORED. YES → 🚨 CRITICAL "lockfile gitignored — --frozen-lockfile has no baseline to enforce; teams fall back to unfrozen installs. e.g. Axios 1.14.1 would resolve on any CI run during the attack window." Both OK → ✅ PASS.

**PM-5 Exotic sources**

Read EXOTIC_DEPS. NONE → ✅ PASS for direct deps. Then read HARDENING for `blockExoticSubdeps`: present+true → ✅; absent → ⚡ WARN (pnpm only).
npm + EXOTIC_DEPS ≠ NONE → 🔶 FAIL (PackageGate unpatched bypass).
pnpm <10.26.2 + EXOTIC_DEPS ≠ NONE → 🔶 FAIL (CVE-2025-69263/69264).
pnpm ≥10.26.2 + EXOTIC_DEPS ≠ NONE → ⚡ WARN.

**PM-6 Trust policy** (pnpm only)

Read HARDENING for `trustPolicy`. `no-downgrade` present → ✅ PASS. Absent → ⚡ WARN.

## Step 4 — output format

**HARD STOP: output ends after ✅ PASSING. Do not generate patch files, config summaries, YAML blocks, or offers to apply fixes. Each fix is already specified inline in its section. Adding anything after PASSING is explicitly prohibited.**

No separate check results block. Each check appears exactly once inside its category. PASSING goes last.

**Icon system — shape and color both carry meaning:**
- 🚨 CRITICAL — any of: unpatched CVE in installed tooling; dangerouslyAllowAllBuilds: true; npm ignore-scripts absent (scripts run by default — primary attack vector); release age not configured on any manager; minimumReleaseAgeExclude set without minimumReleaseAge (false security posture); lockfile gitignored. Do not use for optional hardening gaps.
- 🔶 FAIL — real gap needing a fix (Yarn Classic, lockfile absent)
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

[sections...]
```

Omit any zero-count category from line 2. If everything passes: `✅ all passing`.

Line 2 is a count of *checks*, not sections. Count each PM finding that has a result.

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
Every 🚨 CRITICAL finding must include the `e.g.` line from the check definition — do not paraphrase it into a CVE description. The named incident (Axios, Shai-Hulud, chalk/debug) is what makes the risk concrete. Output the incident name and date exactly as specified in the check, e.g.:
```
  🚨 PM2  release age: 0d — packages install immediately
          e.g. Axios 1.14.1 (Mar 2026) was live 3h, Shai-Hulud (Nov 2025) 12h — both inside a 7d gate
          └─ pnpm-workspace.yaml: minimumReleaseAge: 10080  # 7 days in minutes
```
1-2 lines max. Name specific files and exact values. State combined impact in one clause. If CVE present, include it first. Do not repeat this line anywhere else in the output.

Format: `→ [verb] [what with exact values] — [impact]`

**Never add after PASSING:** no patch blocks, no config summaries, no YAML, no "Want me to apply?" — output stops at the last ✅ or ➖ line. This is a hard rule.
