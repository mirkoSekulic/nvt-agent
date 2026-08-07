#!/usr/bin/env bash
set -euo pipefail

source "$HOME/.nvt-agent/env"

session="${AGENT_SESSION:-agent}"
command_file="$HOME/.nvt-agent/agent-command.json"
max_attempts="${NVT_AGENT_SESSION_MAX_START_ATTEMPTS:-3}"
fast_exit_seconds="${NVT_AGENT_SESSION_FAST_EXIT_SECONDS:-5}"
ready_marker="${NVT_AGENT_SESSION_READY_MARKER:-${NVT_STATE_DIR:-$HOME/.nvt-agent}/agentd/session-launched}"
resume_marker="${NVT_AGENT_SESSION_RESUME_MARKER:-${NVT_STATE_DIR:-$HOME/.nvt-agent}/runtime-session.json}"
session_exec="${NVT_AGENT_SESSION_EXEC:-/usr/local/bin/start-agent-session-exec}"
session_shell="${NVT_AGENT_SESSION_SHELL:-bash}"
if [ -n "${NVT_AGENT_SESSION_RESUME_STATE_COMMAND:-}" ]; then
  resume_state=("$NVT_AGENT_SESSION_RESUME_STATE_COMMAND")
elif command -v session-resume-state >/dev/null 2>&1; then
  resume_state=("$(command -v session-resume-state)")
else
  resume_state=(python3 "$(dirname "$0")/session-resume-state.py")
fi

mark_session_launched() {
  marker_dir="$(dirname "$ready_marker")"
  mkdir -p "$marker_dir"
  temporary="${ready_marker}.$$"
  printf '%s\n' "$session" > "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$ready_marker"
}

# A persisted state directory must not make a new container/session generation
# ready. The marker is republished only after this invocation completes its
# existing fast-exit stability check.
rm -f "$ready_marker"

if [ ! -f "$command_file" ]; then
  python3 - "$command_file" <<'PY'
import json
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(json.dumps({"command": "codex", "args": []}) + "\n", encoding="utf-8")
PY
fi

# A missing valid marker selects the ordinary fresh command. The marker is
# created only after that session passes the existing stability check.
launch_mode="$("${resume_state[@]}" prepare "$command_file" "$resume_marker")"

if tmux has-session -t "$session" 2>/dev/null; then
  sleep "$fast_exit_seconds"
  if tmux has-session -t "$session" 2>/dev/null; then
    "${resume_state[@]}" established "$command_file" "$resume_marker" "$launch_mode"
    mark_session_launched
    exit 0
  fi
  echo "start-agent-session: existing tmux session ${session} exited within ${fast_exit_seconds}s" >&2
fi

attempt_limit="$max_attempts"
if [ "$launch_mode" = "fresh" ]; then
  # A configured initial prompt is part of the fresh command arguments. Avoid
  # replaying it within the fast-exit retry loop.
  attempt_limit=1
fi
command_mode="$launch_mode"
if [ "$command_mode" = "legacy" ]; then
  command_mode="fresh"
fi

attempt=1
while [ "$attempt" -le "$attempt_limit" ]; do
  if [ "$launch_mode" = "legacy" ]; then
    echo "start-agent-session: starting tmux session ${session} (attempt ${attempt}/${attempt_limit})"
  else
    echo "start-agent-session: starting tmux session ${session} with ${launch_mode} command (attempt ${attempt}/${attempt_limit})"
  fi
  if tmux new-session -d -s "$session" -c "${NVT_WORKSPACE}" \
    "\"${session_shell}\" -lc 'source \"\$HOME/.nvt-agent/env\"; exec \"${session_exec}\" \"${command_file}\" \"${command_mode}\"'"; then
    sleep "$fast_exit_seconds"
    if tmux has-session -t "$session" 2>/dev/null; then
      "${resume_state[@]}" established "$command_file" "$resume_marker" "$launch_mode"
      mark_session_launched
      exit 0
    fi
    echo "start-agent-session: tmux session ${session} exited within ${fast_exit_seconds}s" >&2
  fi
  attempt=$((attempt + 1))
done

if [ "$launch_mode" = "legacy" ]; then
  echo "start-agent-session: tmux session ${session} failed after ${attempt_limit} attempts" >&2
else
  echo "start-agent-session: tmux session ${session} ${launch_mode} command failed after ${attempt_limit} attempts" >&2
fi
exit 1
