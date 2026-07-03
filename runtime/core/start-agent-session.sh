#!/usr/bin/env bash
set -euo pipefail

source "$HOME/.nvt-agent/env"

session="${AGENT_SESSION:-agent}"
command_file="$HOME/.nvt-agent/agent-command.json"
max_attempts="${NVT_AGENT_SESSION_MAX_START_ATTEMPTS:-3}"
fast_exit_seconds="${NVT_AGENT_SESSION_FAST_EXIT_SECONDS:-5}"

if tmux has-session -t "$session" 2>/dev/null; then
  exit 0
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
      exit 0
    fi
    echo "start-agent-session: tmux session ${session} exited within ${fast_exit_seconds}s" >&2
  fi
  attempt=$((attempt + 1))
done

echo "start-agent-session: tmux session ${session} failed after ${max_attempts} attempts" >&2
exit 1
