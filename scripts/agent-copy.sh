#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --from <name> --to <name> [--force] [--no-copy-grants] [--copy-workspace] [--copy-auth|--no-copy-auth]" >&2
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

from_name=""
to_name=""
force=0
copy_grants=1
copy_workspace=0
copy_auth=auto

while [ "$#" -gt 0 ]; do
  case "$1" in
    --from)
      if [ "$#" -lt 2 ]; then
        usage
        exit 1
      fi
      from_name="$2"
      shift 2
      ;;
    --to)
      if [ "$#" -lt 2 ]; then
        usage
        exit 1
      fi
      to_name="$2"
      shift 2
      ;;
    --force)
      force=1
      shift
      ;;
    --no-copy-grants)
      copy_grants=0
      shift
      ;;
    --copy-workspace)
      copy_workspace=1
      shift
      ;;
    --copy-auth)
      copy_auth=1
      shift
      ;;
    --no-copy-auth)
      copy_auth=0
      shift
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

if [ -z "$from_name" ] || [ -z "$to_name" ]; then
  usage
  exit 1
fi

if [ "$copy_auth" = "auto" ]; then
  copy_auth="$copy_workspace"
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
templates_dir="$repo_root/templates"
broker_dir="$repo_root/.broker"
broker_agents_file="$broker_dir/agents.yaml"

bash "$script_dir/validate-agent-name.sh" "$from_name"
bash "$script_dir/validate-agent-name.sh" "$to_name"

if [ "$from_name" = "$to_name" ]; then
  echo "FROM and TO must be different agents" >&2
  exit 1
fi

from_dir="$repo_root/.agents/$from_name"
to_dir="$repo_root/.agents/$to_name"
from_config_file="$from_dir/agent.yaml"
from_workspace_dir="$from_dir/workspace"
from_auth_dir="$from_dir/auth"
to_env_file="$to_dir/env"
to_config_file="$to_dir/agent.yaml"
to_workspace_dir="$to_dir/workspace"
to_local_instructions_file="$to_workspace_dir/AGENTS.local.md"
to_custom_plugins_dir="$to_dir/custom-plugins"
to_claude_config_dir="$to_dir/auth/claude"
to_codex_config_dir="$to_dir/auth/codex"

if [ ! -f "$from_config_file" ]; then
  echo "source agent is not initialized: $from_config_file does not exist" >&2
  exit 1
fi

if [ -e "$to_dir" ] && [ "$force" -ne 1 ]; then
  echo "target agent already exists: $to_dir (use FORCE=1 or --force to overwrite)" >&2
  exit 1
fi

if [ -e "$to_dir" ]; then
  rm -rf "$to_dir"
fi

mkdir -p "$to_workspace_dir" "$to_custom_plugins_dir" "$to_claude_config_dir" "$to_codex_config_dir" "$broker_dir"

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

broker_token="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"

AGENT_NAME="$to_name" \
  AGENT_HOST="$to_name.agent.localhost" \
  AGENT_ENV_FILE="$to_env_file" \
  WORKSPACE_DIR="$to_workspace_dir" \
  NVT_WORKSPACE="$to_workspace_dir" \
  CUSTOM_PLUGINS_DIR="$to_custom_plugins_dir" \
  AGENT_CONFIG_FILE="$to_config_file" \
  NVT_BROKER_TOKEN="$broker_token" \
  CODEX_CONFIG_DIR="$to_codex_config_dir" \
  CLAUDE_CONFIG_DIR="$to_claude_config_dir" \
  render_template "$templates_dir/env" "$to_env_file"
echo "created $to_env_file"

cp "$from_config_file" "$to_config_file"
echo "created $to_config_file"

from_local_instructions_file="$from_dir/workspace/AGENTS.local.md"
if [ "$copy_workspace" -eq 1 ] && [ -d "$from_workspace_dir" ]; then
  cp -R "$from_workspace_dir"/. "$to_workspace_dir"/
  echo "copied $from_workspace_dir to $to_workspace_dir"
elif [ -f "$from_local_instructions_file" ]; then
  cp "$from_local_instructions_file" "$to_local_instructions_file"
  echo "created $to_local_instructions_file"
fi

if [ "$copy_auth" -eq 1 ] && [ -d "$from_auth_dir" ]; then
  cp -R "$from_auth_dir"/. "$to_dir/auth"/
  echo "copied $from_auth_dir to $to_dir/auth"
fi

copy_grants_arg="--copy-grants"
if [ "$copy_grants" -ne 1 ]; then
  copy_grants_arg="--no-copy-grants"
fi

python3 "$script_dir/broker-agents.py" \
  --agents-file "$broker_agents_file" \
  copy-register \
  --from-name "$from_name" \
  --name "$to_name" \
  --token "$broker_token" \
  "$copy_grants_arg"

echo "copied agent $from_name to $to_name"
