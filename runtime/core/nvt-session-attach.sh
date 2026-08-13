#!/usr/bin/env bash
set -euo pipefail

session="${AGENT_SESSION:-agent}"
wait_seconds="${NVT_SESSION_ATTACH_WAIT_SECONDS:-60}"

if ! command -v tmux >/dev/null 2>&1; then
  echo "nvt-session-attach: tmux session backend is not installed" >&2
  exit 127
fi

if ! [[ "${wait_seconds}" =~ ^[0-9]+$ ]] || [ "${wait_seconds}" -lt 1 ] || [ "${wait_seconds}" -gt 300 ]; then
  echo "nvt-session-attach: NVT_SESSION_ATTACH_WAIT_SECONDS must be an integer from 1 to 300" >&2
  exit 2
fi

deadline=$((SECONDS + wait_seconds))
while ! tmux has-session -t "${session}" 2>/dev/null; do
  if [ "${SECONDS}" -ge "${deadline}" ]; then
    echo "nvt-session-attach: agent session ${session} was not available within ${wait_seconds}s" >&2
    exit 1
  fi
  sleep 1
done

exec tmux attach-session -t "${session}"
