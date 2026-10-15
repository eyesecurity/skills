#!/usr/bin/env bash
# complisec — shared helpers for the audit hooks.
#
# Sourced by audit-session-start.sh and audit-tool-call.sh. Nothing here writes
# to stdout: a SessionStart hook's stdout becomes agent context, so only the
# calling hook decides what Claude sees.

# Project root, resolved the way every complisec skill documents it:
# .compliance/ lives at the project root. CLAUDE_PROJECT_DIR is set by Claude
# Code; the hook payload's cwd is the fallback.
# $1 = cwd from the hook payload
audit_project_dir() {
  if [ -n "${CLAUDE_PROJECT_DIR:-}" ]; then
    printf '%s' "$CLAUDE_PROJECT_DIR"
  elif [ -n "${1:-}" ]; then
    printf '%s' "$1"
  else
    printf '%s' "$PWD"
  fi
}

# The audit trail is opt-in per project: complisec only writes where the
# project has been onboarded (.compliance/ exists, created by /complisec setup).
# Without this a globally installed plugin drops an audit log into every
# unrelated repository the user opens.
# $1 = project dir
audit_is_enabled() {
  [ -d "${1}/.compliance" ]
}

# $1 = project dir
audit_log_path() {
  printf '%s' "${1}/.compliance/audit.log"
}

# Field separator for reading jq output into shell variables. A tab cannot be
# used: bash treats tab as IFS whitespace, so consecutive tabs collapse into one
# delimiter and every empty field silently shifts the rest of the record along.
# Pair with `@tsv | gsub("\t"; "\u001f")` in jq, which keeps @tsv's escaping of
# any literal tab or newline inside a value while giving a delimiter bash will
# not fold.
AUDIT_FS=$'\037'

uuid4() {
  if [ -r /proc/sys/kernel/random/uuid ]; then
    tr 'A-Z' 'a-z' < /proc/sys/kernel/random/uuid
  elif command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr 'A-Z' 'a-z'
  else
    python3 -c 'import uuid; print(uuid.uuid4())'
  fi
}

# $1 = string to hash
sha256_hex() {
  local out
  if command -v sha256sum >/dev/null 2>&1; then
    out=$(printf '%s' "$1" | sha256sum)
  else
    out=$(printf '%s' "$1" | shasum -a 256)
  fi
  printf '%s' "${out%% *}"
}

# trace_id — 32 lowercase hex, identical for every event in a session and
# derived only from the session id, so the tool hooks reach the same value as
# the SessionStart hook without sharing any state. Claude Code session ids are
# UUIDs, so stripping the dashes already yields a valid trace_id and keeps the
# audit log joinable to the transcript by eye; anything else gets hashed.
# $1 = session_id
audit_trace_id() {
  local candidate=${1//-/}
  candidate=${candidate,,}
  if [[ $candidate =~ ^[0-9a-f]{32}$ ]]; then
    printf '%s' "$candidate"
  else
    local hash
    hash=$(sha256_hex "$1")
    printf '%s' "${hash:0:32}"
  fi
}

# span_id — 16 lowercase hex, derived from a per-operation id so that paired
# events (a tool request and its result) share one span without shared state.
# $1 = operation id
audit_span_id() {
  local hash
  hash=$(sha256_hex "$1")
  printf '%s' "${hash:0:16}"
}

audit_now() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

# Append one event. A single write of a line well under PIPE_BUF to an O_APPEND
# descriptor cannot interleave, so concurrent hooks stay line-clean.
# $1 = log path, $2 = JSON line
audit_append() {
  printf '%s\n' "$2" >> "$1"
}
