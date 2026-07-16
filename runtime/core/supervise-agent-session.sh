#!/usr/bin/env bash
set -uo pipefail

session="${AGENT_SESSION:-agent}"
poll_interval="${NVT_AGENT_SESSION_SUPERVISOR_INTERVAL_SECONDS:-1}"
termination_message_path="${NVT_TERMINATION_MESSAGE_PATH:-/dev/termination-log}"

if [[ ! "$poll_interval" =~ ^[0-9]+([.][0-9]+)?$ ]] || [[ "$poll_interval" =~ ^0+([.]0+)?$ ]]; then
  echo "supervise-agent-session: NVT_AGENT_SESSION_SUPERVISOR_INTERVAL_SECONDS must be positive" >&2
  exit 2
fi

shutdown_requested=0
sleep_pid=""

request_shutdown() {
  shutdown_requested=1
  if [ -n "$sleep_pid" ]; then
    kill "$sleep_pid" 2>/dev/null || true
  fi
}

intentional_shutdown() {
  [ "$shutdown_requested" -eq 1 ] || valid_lifecycle_message
}

valid_lifecycle_message() {
  [ -f "$termination_message_path" ] || return 1
  python3 - "$termination_message_path" 2>/dev/null <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "rb") as handle:
    raw = handle.read(4097)
if not raw or len(raw) > 4096:
    raise SystemExit(1)
try:
    message = json.loads(raw.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(message, dict) or set(message) != {"nvtLifecycleEvent", "outcome"}:
    raise SystemExit(1)
event = message["nvtLifecycleEvent"]
outcome = message["outcome"]
if (
    not isinstance(event, str)
    or not event
    or len(event) > 256
    or any(ord(char) < 32 or ord(char) == 127 for char in event)
    or outcome not in {"completed", "failed"}
):
    raise SystemExit(1)
PY
}

pause_between_checks() {
  sleep "$poll_interval" &
  sleep_pid=$!
  wait "$sleep_pid" 2>/dev/null || true
  sleep_pid=""
  if intentional_shutdown; then
    exit 0
  fi
}

trap request_shutdown TERM INT

missing_checks=0
while true; do
  if intentional_shutdown; then
    exit 0
  fi
  if tmux has-session -t "$session" 2>/dev/null; then
    missing_checks=0
  else
    missing_checks=$((missing_checks + 1))
    if intentional_shutdown; then
      exit 0
    fi
    if [ "$missing_checks" -ge 2 ]; then
      echo "supervise-agent-session: tmux session ${session} disappeared" >&2
      exit 1
    fi
  fi
  pause_between_checks
done
