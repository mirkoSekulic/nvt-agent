#!/usr/bin/env bash
set -euo pipefail

source "$HOME/.nvt-agent/env"

session="${AGENT_SESSION:-agent}"
command_file="$HOME/.nvt-agent/agent-command.json"
max_attempts="${NVT_AGENT_SESSION_MAX_START_ATTEMPTS:-3}"
fast_exit_seconds="${NVT_AGENT_SESSION_FAST_EXIT_SECONDS:-5}"
ready_marker="${NVT_AGENT_SESSION_READY_MARKER:-${NVT_STATE_DIR:-$HOME/.nvt-agent}/agentd/session-launched}"

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

if tmux has-session -t "$session" 2>/dev/null; then
  sleep "$fast_exit_seconds"
  if tmux has-session -t "$session" 2>/dev/null; then
    mark_session_launched
    exit 0
  fi
  echo "start-agent-session: existing tmux session ${session} exited within ${fast_exit_seconds}s" >&2
fi

if [ ! -f "$command_file" ]; then
  python3 - "$command_file" <<'PY'
import json
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(json.dumps({"command": "codex", "args": []}) + "\n", encoding="utf-8")
PY
fi

attempt=1
while [ "$attempt" -le "$max_attempts" ]; do
  echo "start-agent-session: starting tmux session ${session} (attempt ${attempt}/${max_attempts})"
  if tmux new-session -d -s "$session" -c "${NVT_WORKSPACE}" \
    "bash -lc 'source \"\$HOME/.nvt-agent/env\"; exec /usr/local/bin/start-agent-session-exec \"${command_file}\"'"; then
    sleep "$fast_exit_seconds"
    if tmux has-session -t "$session" 2>/dev/null; then
      mark_session_launched
      exit 0
    fi
    echo "start-agent-session: tmux session ${session} exited within ${fast_exit_seconds}s" >&2
  fi
  attempt=$((attempt + 1))
done

echo "start-agent-session: tmux session ${session} failed after ${max_attempts} attempts" >&2
exit 1
