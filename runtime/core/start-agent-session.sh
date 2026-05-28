#!/usr/bin/env bash
set -euo pipefail

source "$HOME/.nvt-agent/env"

session="${AGENT_SESSION:-agent}"
command_file="$HOME/.nvt-agent/agent-command.json"

if ! tmux has-session -t "$session" 2>/dev/null; then
  if [ ! -f "$command_file" ]; then
    python3 - "$command_file" <<'PY'
import json
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(json.dumps({"command": "codex", "args": []}) + "\n", encoding="utf-8")
PY
  fi
  tmux new-session -d -s "$session" -c "${NVT_WORKSPACE}" \
    "bash -lc 'source \"\$HOME/.nvt-agent/env\"; exec /usr/local/bin/start-agent-session-exec \"${command_file}\"'"
fi
