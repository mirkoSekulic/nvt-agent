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
  [ "$shutdown_requested" -eq 1 ] || [ -s "$termination_message_path" ]
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
