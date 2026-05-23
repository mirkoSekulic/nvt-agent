#!/usr/bin/env bash
set -euo pipefail

mkdir -p "$HOME/.nvt-agent" "${NVT_WORKSPACE:-/workspace}"

export MISE_DATA_DIR="${MISE_DATA_DIR:-$HOME/.local/share/mise}"
export PATH="$HOME/.local/bin:$HOME/bin:$HOME/.local/share/mise/shims:${PATH}"

cat > "$HOME/.nvt-agent/env" <<EOF
export NVT_WORKSPACE="${NVT_WORKSPACE:-/workspace}"
export CODE_SERVER_PORT="${CODE_SERVER_PORT:-4090}"
export MISE_DATA_DIR="${MISE_DATA_DIR}"
export PATH="${PATH}"
EOF

bootstrap "${NVT_AGENT_CONFIG_FILE:-/nvt-agent/agent.yaml}"
write-agent-instructions

if [ -x /workspace/.nvt-agent/bootstrap.sh ]; then
  /workspace/.nvt-agent/bootstrap.sh
fi

run-plugins before-agent "${NVT_AGENT_CONFIG_FILE:-/nvt-agent/agent.yaml}"

start-code-server
start-agent-session
run-plugins after-agent "${NVT_AGENT_CONFIG_FILE:-/nvt-agent/agent.yaml}" &

tail -f /dev/null
