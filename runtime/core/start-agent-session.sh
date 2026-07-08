#!/usr/bin/env bash
set -euo pipefail

source "$HOME/.nvt-agent/env"

session="${AGENT_SESSION:-agent}"
command_file="$HOME/.nvt-agent/agent-command.json"
max_attempts="${NVT_AGENT_SESSION_MAX_START_ATTEMPTS:-3}"
fast_exit_seconds="${NVT_AGENT_SESSION_FAST_EXIT_SECONDS:-5}"

# The session driver (zellij by default, tmux when configured) is resolved by
# the agent-session adapter, which is the single place that knows how to talk to
# each multiplexer. Override the binary only for tests.
agent_session="${NVT_AGENT_SESSION_BIN:-agent-session}"

if $agent_session exists --session "$session"; then
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

driver="$($agent_session driver)"

attempt=1
while [ "$attempt" -le "$max_attempts" ]; do
  echo "start-agent-session: starting ${driver} session ${session} (attempt ${attempt}/${max_attempts})"
  if $agent_session start --session "$session" --command-file "$command_file" --workdir "${NVT_WORKSPACE}"; then
    sleep "$fast_exit_seconds"
    if $agent_session exists --session "$session"; then
      exit 0
    fi
    echo "start-agent-session: ${driver} session ${session} exited within ${fast_exit_seconds}s" >&2
  fi
  attempt=$((attempt + 1))
done

echo "start-agent-session: ${driver} session ${session} failed after ${max_attempts} attempts" >&2
exit 1
