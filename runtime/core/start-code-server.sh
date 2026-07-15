#!/usr/bin/env bash
set -euo pipefail

source "$HOME/.nvt-agent/env"

code-server \
  --bind-addr "0.0.0.0:${CODE_SERVER_PORT}" \
  --auth none \
  --disable-telemetry \
  --disable-update-check \
  "${NVT_WORKSPACE}" \
  >"$HOME/.nvt-agent/code-server.log" 2>&1 &
