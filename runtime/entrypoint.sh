#!/usr/bin/env bash
set -euo pipefail

mkdir -p "$HOME/.nvt-agent" "${NVT_WORKSPACE:-/workspace}"

cat > "$HOME/.nvt-agent/env" <<EOF
export NVT_WORKSPACE="${NVT_WORKSPACE:-/workspace}"
export CODE_SERVER_PORT="${CODE_SERVER_PORT:-4090}"
export PATH="${PATH}"
EOF

if [ -x /workspace/.nvt-agent/install-tools.sh ]; then
  /workspace/.nvt-agent/install-tools.sh
fi

nvt-start-code-server
nvt-start-agent-session

tail -f /dev/null
