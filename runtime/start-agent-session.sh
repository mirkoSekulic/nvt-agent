#!/usr/bin/env bash
set -euo pipefail

source "$HOME/.nvt-agent/env"

session="${AGENT_SESSION:-agent}"
command="${AGENT_COMMAND:-codex}"

if ! tmux has-session -t "$session" 2>/dev/null; then
  tmux new-session -d -s "$session" -c "${NVT_WORKSPACE}" \
    "bash -lc 'source \"\$HOME/.nvt-agent/env\"; exec ${command}'"
fi
