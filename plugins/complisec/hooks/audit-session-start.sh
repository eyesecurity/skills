#!/usr/bin/env bash
# complisec — SessionStart audit hook.
#
# Writes one session/start audit event per session boundary (startup, resume,
# /clear, compaction, fork) and hands Claude the trace_id to reuse, so events
# the agent writes itself correlate with the hook-written ones instead of
# opening a second trace.
#
# Never blocks and never fails a session: a compliance control that breaks the
# editor is a compliance control that gets switched off.

set -uo pipefail

# Report a dead audit trail and stop. Used for the failures that happen before,
# or instead of, jq being available — so it hand-builds the JSON. Callers pass
# a plain ASCII message with no quotes, backslashes or newlines.
# $1 = message
inactive() {
  printf '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"%s"}}\n' "$1"
  exit 0
}

script_dir=${BASH_SOURCE[0]%/*}
[ "$script_dir" = "${BASH_SOURCE[0]}" ] && script_dir=.
# shellcheck source=audit-lib.sh
. "${script_dir}/audit-lib.sh" 2>/dev/null || inactive \
  "complisec audit trail INACTIVE: hooks/audit-lib.sh could not be loaded, so no audit events are being recorded. The complisec plugin install looks incomplete - tell the user to reinstall it."

# $1 = context text for Claude
emit_context() {
  jq -n --arg ctx "$1" \
    '{hookSpecificOutput: {hookEventName: "SessionStart", additionalContext: $ctx}}'
}

payload=$(cat)

# jq is the only dependency. Say so in context rather than degrading quietly —
# a silently inactive audit trail is the failure mode this hook exists to fix.
command -v jq >/dev/null 2>&1 || inactive \
  "complisec audit trail INACTIVE: jq is not installed, so the complisec hooks cannot write audit events. Tell the user to install jq to restore automatic ISO 27001 A.8.15 / NIS2 Art. 21 evidence. Until then every audit event must be written by hand per skills/audit-logging/SKILL.md."

IFS="$AUDIT_FS" read -r session_id source payload_cwd transcript_path < <(
  jq -r 'def s(x): (x // "") | tostring;
         [s(.session_id), s(.source), s(.cwd), s(.transcript_path)]
         | @tsv | gsub("\t"; "\u001f")' <<<"$payload"
)

[ -n "$session_id" ] || session_id=$(uuid4)
[ -n "$source" ] || source="unknown"

project_dir=$(audit_project_dir "$payload_cwd")

if ! audit_is_enabled "$project_dir"; then
  emit_context "complisec audit trail INACTIVE for this project: ${project_dir} has no .compliance/ directory, so no audit events are being recorded. Run /complisec setup to onboard this project, or create .compliance/ to start collecting ISO 27001 A.8.15 / NIS2 Art. 21 evidence."
  exit 0
fi

trace_id=$(audit_trace_id "$session_id")

event=$(jq -nc \
  --arg event_id "$(uuid4)" \
  --arg timestamp "$(audit_now)" \
  --arg trace_id "$trace_id" \
  --arg summary "Claude Code session start (source=${source})" \
  --arg session_id "$session_id" \
  --arg source "$source" \
  --arg project_dir "$project_dir" \
  --arg transcript_path "$transcript_path" \
  '{
     event_id: $event_id,
     timestamp: $timestamp,
     trace_id: $trace_id,
     event_class: "session",
     activity: "start",
     severity: "INFO",
     outcome: "success",
     summary: $summary,
     agent_id: "claude-code",
     metadata: ({
       session_id: $session_id,
       source: $source,
       project_dir: $project_dir,
       transcript_path: $transcript_path,
       emitted_by: "complisec/hooks/audit-session-start.sh"
     } | with_entries(select(.value != "")))
   }')

audit_append "$(audit_log_path "$project_dir")" "$event"

emit_context "complisec audit trail active for this session.
trace_id: ${trace_id}
Use this exact trace_id on every audit event you write this session. Do not generate a new one — a second trace splits the session's evidence in two.
Audit log: .compliance/audit.log (append-only JSONL, one event per line, schema at skills/audit-logging/audit-event.schema.json).
This session boundary has already been logged by the hook — do not log it again.
Events the hook cannot see remain yours to write: decision records (ADRs), data_access, and error events. See skills/audit-logging/SKILL.md."
