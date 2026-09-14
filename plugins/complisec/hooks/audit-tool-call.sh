#!/usr/bin/env bash
# complisec — PreToolUse / PostToolUse / PostToolUseFailure / PermissionDenied
# audit hook.
#
# Makes steps 3-4 of the audit-logging skill ("log a tool_call event before and
# after tool execution") deterministic instead of best-effort. One script serves
# every tool event; it branches on hook_event_name.
#
# This hook writes nothing to stdout, deliberately. A PermissionDenied hook can
# return hookSpecificOutput.retry to let the model retry a refused call, and an
# audit control must observe what happened without ever altering it.
#
# The two events for one tool call share a span_id derived from tool_use_id, so
# a request and its result join without any shared state between hook processes.
#
# What is deliberately NOT logged: anything out of tool_input except file_path.
# A Bash command line or a Write payload can carry a credential, and this log is
# append-only with a retention floor measured in months. tool_use_id is recorded
# instead — it joins the event to the transcript, where the detail already lives.
#
# Never blocks: every exit path is 0, and no output is produced on success.
# PreToolUse stdout is not agent context, so a broken install is reported by the
# SessionStart hook rather than here.

set -uo pipefail

script_dir=${BASH_SOURCE[0]%/*}
[ "$script_dir" = "${BASH_SOURCE[0]}" ] && script_dir=.
# shellcheck source=audit-lib.sh
. "${script_dir}/audit-lib.sh" 2>/dev/null || exit 0

command -v jq >/dev/null 2>&1 || exit 0

payload=$(cat)

# Outcome detection is defensive: tool_response is an object for some tools and
# a bare string for others, and an absent field simply reads as null.
IFS="$AUDIT_FS" read -r hook_event session_id tool_name tool_use_id payload_cwd \
                       permission_mode file_path detected_outcome exit_code \
                       deny_reason < <(
  jq -r 'def s(x): (x // "") | tostring;
         [ s(.hook_event_name),
           s(.session_id),
           s(.tool_name),
           s(.tool_use_id),
           s(.cwd),
           s(.permission_mode),
           (if (.tool_input | type) == "object" then s(.tool_input.file_path) else "" end),
           (if (.tool_response | type) == "object"
              and ( .tool_response.is_error == true
                 or .tool_response.success == false
                 or .tool_response.interrupted == true
                 or .tool_response.error != null )
            then "failure" else "success" end),
           (if (.tool_response | type) == "object"
              and (.tool_response.exit_code | type) == "number"
            then s(.tool_response.exit_code) else "" end),
           s(.deny_reason)
         ] | @tsv | gsub("\t"; "\u001f")' <<<"$payload"
)

[ -n "$tool_name" ] || exit 0

project_dir=$(audit_project_dir "$payload_cwd")
audit_is_enabled "$project_dir" || exit 0

# Activity per the schema. Unrecognised tools fall through to "execute": the
# conservative label. Never downgrade an unknown tool to "read".
case "$tool_name" in
  Read|Grep|Glob|NotebookRead|WebFetch|WebSearch|ListAgents|TaskOutput)
    activity="read" ;;
  Write|Edit|MultiEdit|NotebookEdit|TodoWrite|Artifact)
    activity="write" ;;
  *)
    activity="execute" ;;
esac

case "$hook_event" in
  PreToolUse)
    # "deferred" = recorded at request time, resolution follows in the paired
    # result event with the same span_id. Logging the request too is what keeps
    # a denied call visible: neither result event fires for those.
    outcome="deferred"
    severity="INFO"
    summary="Tool requested: ${tool_name}"
    ;;
  PostToolUseFailure)
    # PostToolUse does not fire for a failed tool call — this event does, and
    # without it every failure would be left as a request with no resolution.
    # Its tool_response is often a bare string, so the outcome is taken from the
    # event name rather than inferred from the response.
    outcome="failure"
    severity="LOW"
    summary="Tool failed: ${tool_name}"
    ;;
  PermissionDenied)
    # The permission system refused the call before it ran, so neither result
    # event fires — without this the request would sit in the log unresolved,
    # indistinguishable from a crash. "blocked" is the outcome a compliance
    # reviewer filters for, and this is the only hook that produces it.
    outcome="blocked"
    severity="MEDIUM"
    summary="Tool blocked by permission policy: ${tool_name}"
    ;;
  *)
    outcome="$detected_outcome"
    summary="Tool completed: ${tool_name} (${outcome})"
    if [ "$outcome" = "failure" ]; then severity="LOW"; else severity="INFO"; fi
    ;;
esac

# deny_reason says why the call was refused, which is the most useful part of a
# block event — but it can quote the command it refused, and this hook does not
# log tool input. Off by default; set COMPLISEC_AUDIT_DENY_REASON=1 in the "env"
# block of settings.json to record it where the org's risk appetite allows.
if [ "${COMPLISEC_AUDIT_DENY_REASON:-0}" = "1" ]; then
  logged_deny_reason="$deny_reason"
else
  logged_deny_reason=""
fi

event=$(jq -nc \
  --arg event_id "$(uuid4)" \
  --arg timestamp "$(audit_now)" \
  --arg trace_id "$(audit_trace_id "$session_id")" \
  --arg span_id "${tool_use_id:+$(audit_span_id "$tool_use_id")}" \
  --arg activity "$activity" \
  --arg severity "$severity" \
  --arg outcome "$outcome" \
  --arg summary "$summary" \
  --arg tool_name "$tool_name" \
  --arg exit_code "$exit_code" \
  --arg file_path "$file_path" \
  --arg session_id "$session_id" \
  --arg tool_use_id "$tool_use_id" \
  --arg permission_mode "$permission_mode" \
  --arg hook_event "$hook_event" \
  --arg deny_reason "$logged_deny_reason" \
  '{
     event_id: $event_id,
     timestamp: $timestamp,
     trace_id: $trace_id,
     event_class: "tool_call",
     activity: $activity,
     severity: $severity,
     outcome: $outcome,
     summary: $summary,
     agent_id: "claude-code",
     tool: ({ name: $tool_name }
            + (if $exit_code == "" then {} else { exit_code: ($exit_code | tonumber) } end)),
     metadata: ({
       session_id: $session_id,
       tool_use_id: $tool_use_id,
       permission_mode: $permission_mode,
       hook_event: $hook_event,
       deny_reason: $deny_reason,
       emitted_by: "complisec/hooks/audit-tool-call.sh"
     } | with_entries(select(.value != "")))
   }
   + (if $span_id == "" then {} else { span_id: $span_id } end)
   + (if $file_path == "" then {} else { resource: { type: "file", id: $file_path } } end)')

audit_append "$(audit_log_path "$project_dir")" "$event"
exit 0
