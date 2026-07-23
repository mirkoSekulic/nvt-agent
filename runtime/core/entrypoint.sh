#!/usr/bin/env bash
set -euo pipefail

export NVT_STATE_DIR="${NVT_STATE_DIR:-$HOME/.nvt-agent}"

# Non-root only: make the mounted home and workspace writable by the current
# user before anything writes to them. Scoped — root (uid 0) skips this
# entirely, so the default path is unchanged — and best-effort via the agent's
# passwordless sudo. Top-level dirs only (cheap); pre-existing host-owned files
# in a bind-mounted workspace may still need host-side ownership.
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  sudo chown "$(id -u):$(id -g)" "$HOME" "${NVT_WORKSPACE:-/workspace}" 2>/dev/null || true
  # The runtime-auth dirs are separately mounted (compose bind mounts of the
  # per-agent auth copy; a k8s emptyDir), so the top-level chown above does not
  # reach them. Recurse them (small credential dirs) so the tool can create and
  # update credentials, e.g. Claude Code's .claude/.credentials.json.
  for auth_dir in "$HOME/.codex" "$HOME/.claude"; do
    [ -d "$auth_dir" ] && sudo chown -R "$(id -u):$(id -g)" "$auth_dir" 2>/dev/null || true
  done
fi

mkdir -p "$HOME/.nvt-agent" "$NVT_STATE_DIR" "${NVT_WORKSPACE:-/workspace}"

# The default agentd socket lives under /run, which is root-owned. Prepare its
# parent for the selected runtime user before agentd starts. nvt-as-root is a
# passthrough for root and uses the image's passwordless sudo in non-root mode.
agentd_socket="${NVT_AGENTD_SOCKET:-/run/nvt-agent/agentd.sock}"
agentd_runtime_dir="$(dirname "$agentd_socket")"
nvt-as-root install -d -m 0700 -o "$(id -u)" -g "$(id -g)" "$agentd_runtime_dir"

export MISE_DATA_DIR="${MISE_DATA_DIR:-$HOME/.local/share/mise}"
export PATH="$HOME/.local/bin:$HOME/bin:$HOME/.local/share/mise/shims:${PATH}"

cat > "$HOME/.nvt-agent/env" <<EOF
export NVT_WORKSPACE="${NVT_WORKSPACE:-/workspace}"
export NVT_STATE_DIR="${NVT_STATE_DIR}"
export CODE_SERVER_PORT="${CODE_SERVER_PORT:-4090}"
export MISE_DATA_DIR="${MISE_DATA_DIR}"
export PATH="${PATH}"
EOF

profile_snippet='[ -f "$HOME/.nvt-agent/env" ] && source "$HOME/.nvt-agent/env"'
touch "$HOME/.bashrc"
if ! grep -Fqx "$profile_snippet" "$HOME/.bashrc"; then
  printf '\n%s\n' "$profile_snippet" >> "$HOME/.bashrc"
fi

bootstrap "${NVT_AGENT_CONFIG_FILE:-/nvt-agent/agent.yaml}"
export-plugin-tools "${NVT_AGENT_CONFIG_FILE:-/nvt-agent/agent.yaml}"
write-agent-instructions

if [ -x /workspace/.nvt-agent/bootstrap.sh ]; then
  /workspace/.nvt-agent/bootstrap.sh
fi

run-plugins before-agent "${NVT_AGENT_CONFIG_FILE:-/nvt-agent/agent.yaml}"

agentd &
start-code-server
start-agent-session

# Kubernetes lifecycle reporting writes /dev/termination-log and signals PID
# 1. Forward intentional shutdown to the session supervisor and reap it so
# kubelet observes a clean exit. Unexpected session loss exits non-zero.
supervisor_pid=""
intentional_shutdown() {
  trap '' TERM INT
  if [ -n "$supervisor_pid" ]; then
    kill -TERM "$supervisor_pid" 2>/dev/null || true
    wait "$supervisor_pid" 2>/dev/null || true
  fi
  exit 0
}
trap intentional_shutdown TERM INT

run-plugins after-agent "${NVT_AGENT_CONFIG_FILE:-/nvt-agent/agent.yaml}" &
supervise-agent-session &
supervisor_pid=$!
if wait "$supervisor_pid"; then
  supervisor_status=0
else
  supervisor_status=$?
fi
supervisor_pid=""
exit "$supervisor_status"
