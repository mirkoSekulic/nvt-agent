#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: agent-capture [--lines <count>] [--out <path>] [--session <name>] [--print]

Capture recent output from the agent session (driver-aware: zellij or tmux).

Options:
  -n, --lines <count>    Number of recent lines to capture (default: 100)
  -o, --out <path>       Output file path (default: agent-capture.txt)
  -t, --session <name>   tmux session or pane target (default: $AGENT_SESSION or agent)
  -p, --print            Print capture to stdout instead of writing a file
  -h, --help             Show this help
EOF
}

lines=100
out="agent-capture.txt"
session="${AGENT_SESSION:-agent}"
print=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    -n|--lines)
      if [ "$#" -lt 2 ]; then
        echo "agent-capture: --lines requires a value" >&2
        exit 1
      fi
      lines="$2"
      shift 2
      ;;
    -o|--out)
      if [ "$#" -lt 2 ]; then
        echo "agent-capture: --out requires a value" >&2
        exit 1
      fi
      out="$2"
      shift 2
      ;;
    -t|--session)
      if [ "$#" -lt 2 ]; then
        echo "agent-capture: --session requires a value" >&2
        exit 1
      fi
      session="$2"
      shift 2
      ;;
    -p|--print)
      print=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "agent-capture: unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

case "$lines" in
  ''|*[!0-9]*)
    echo "agent-capture: --lines must be a positive integer" >&2
    exit 1
    ;;
esac

if [ "$lines" -lt 1 ]; then
  echo "agent-capture: --lines must be a positive integer" >&2
  exit 1
fi

if [ -z "$session" ]; then
  echo "agent-capture: --session must not be empty" >&2
  exit 1
fi

# The session driver (zellij by default, tmux when configured) is resolved by
# the agent-session adapter. Override the binary only for tests.
agent_session="${NVT_AGENT_SESSION_BIN:-agent-session}"

capture() {
  $agent_session capture --session "$session" --lines "$lines"
}

if [ "$print" = true ] || [ "$out" = "-" ]; then
  capture
else
  capture >"$out"
  echo "agent-capture: wrote $out" >&2
fi
