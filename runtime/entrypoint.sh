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

nvt-install-tools "${NVT_TOOLS_FILE:-/nvt-agent/tools.yaml}"

if [ -x /workspace/.nvt-agent/install-tools.sh ]; then
  /workspace/.nvt-agent/install-tools.sh
fi

nvt-start-code-server
nvt-start-agent-session

tail -f /dev/null
