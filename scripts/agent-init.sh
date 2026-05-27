#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --name <name> [--type codex|claude]" >&2
}

render_template() {
  local template="$1"
  local target="$2"
  python3 - "$template" "$target" <<'PY'
import os
import sys
from pathlib import Path

template = Path(sys.argv[1])
target = Path(sys.argv[2])
content = template.read_text(encoding="utf-8")
for key, value in os.environ.items():
    content = content.replace("{{" + key + "}}", value)
target.write_text(content, encoding="utf-8")
PY
}

name=""
agent_type="codex"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --name)
      if [ "$#" -lt 2 ]; then
        usage
        exit 1
      fi
      name="$2"
      shift 2
      ;;
    --type)
      if [ "$#" -lt 2 ]; then
        usage
        exit 1
      fi
      agent_type="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [ -z "$name" ]; then
  usage
  exit 1
fi

case "$agent_type" in
  codex|claude) ;;
  *)
    echo "invalid agent type: $agent_type" >&2
    echo "agent type must be codex or claude" >&2
    exit 1
    ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
templates_dir="$repo_root/templates"
broker_dir="$repo_root/.broker"
broker_agents_file="$broker_dir/agents.yaml"

bash "$script_dir/validate-agent-name.sh" "$name"

agent_dir="$repo_root/.agents/$name"
env_file="$agent_dir/env"
agent_config_file="$agent_dir/agent.yaml"
workspace_dir="$agent_dir/workspace"
custom_plugins_dir="$agent_dir/custom-plugins"
claude_config_dir="$agent_dir/auth/claude"
codex_config_dir="${HOME}/.codex"

mkdir -p "$workspace_dir" "$custom_plugins_dir" "$claude_config_dir" "$broker_dir"

if [ ! -f "$broker_dir/broker.yaml" ]; then
  cp "$templates_dir/broker.yaml" "$broker_dir/broker.yaml"
  echo "created $broker_dir/broker.yaml"
fi

if [ ! -f "$broker_agents_file" ]; then
  cp "$templates_dir/broker-agents.yaml" "$broker_agents_file"
  echo "created $broker_agents_file"
fi

if [ ! -f "$broker_dir/env" ]; then
  cp "$templates_dir/broker-env" "$broker_dir/env"
  echo "created $broker_dir/env"
fi

broker_token=""
if [ -f "$env_file" ]; then
  broker_token="$(grep -E '^NVT_BROKER_TOKEN=' "$env_file" | tail -n 1 | cut -d= -f2- || true)"
fi
if [ -z "$broker_token" ]; then
  broker_token="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
fi

if [ ! -f "$env_file" ]; then
  AGENT_NAME="$name" \
    AGENT_HOST="$name.agent.localhost" \
    AGENT_ENV_FILE="$env_file" \
    WORKSPACE_DIR="$workspace_dir" \
    NVT_WORKSPACE="$workspace_dir" \
    CUSTOM_PLUGINS_DIR="$custom_plugins_dir" \
    AGENT_CONFIG_FILE="$agent_config_file" \
    NVT_BROKER_TOKEN="$broker_token" \
    CODEX_CONFIG_DIR="$codex_config_dir" \
    CLAUDE_CONFIG_DIR="$claude_config_dir" \
    render_template "$templates_dir/env" "$env_file"
  echo "created $env_file"
else
  if ! grep -q '^NVT_BROKER_URL=' "$env_file"; then
    {
      printf '\n'
      printf 'NVT_BROKER_URL=http://broker:7347\n'
    } >>"$env_file"
    echo "updated $env_file"
  fi
  if ! grep -q '^NVT_BROKER_TOKEN=' "$env_file"; then
    {
      printf 'NVT_BROKER_TOKEN=%s\n' "$broker_token"
    } >>"$env_file"
    echo "updated $env_file"
  fi
  echo "exists  $env_file"
fi

python3 "$script_dir/broker-agents.py" \
  --agents-file "$broker_agents_file" \
  register \
  --name "$name" \
  --token "$broker_token"

if [ ! -f "$agent_config_file" ]; then
  AGENT_TYPE="$agent_type" render_template "$templates_dir/agent.yaml" "$agent_config_file"
  echo "created $agent_config_file"
else
  echo "exists  $agent_config_file"
fi

echo "workspace $workspace_dir"
