#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --name <name> [--type codex|claude]" >&2
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

"$script_dir/validate-agent-name.sh" "$name"

agent_dir="$repo_root/.agents/$name"
env_file="$agent_dir/env"
tools_file="$agent_dir/tools.yaml"
workspace_dir="$agent_dir/workspace"
claude_config_dir="$agent_dir/auth/claude"
codex_config_dir="${HOME}/.codex"

mkdir -p "$workspace_dir" "$claude_config_dir"

if [ ! -f "$env_file" ]; then
  cat > "$env_file" <<EOF
AGENT_NAME=$name
AGENT_DOMAIN=agent.localhost
AGENT_HOST=$name.agent.localhost
AGENT_COMMAND=$agent_type

AGENT_ENV_FILE=$env_file
WORKSPACE_DIR=$workspace_dir
NVT_WORKSPACE=$workspace_dir
TOOLS_FILE=$tools_file
NVT_TOOLS_FILE=/nvt-agent/tools.yaml

CODEX_CONFIG_DIR=$codex_config_dir
CLAUDE_CONFIG_DIR=$claude_config_dir
EOF
  echo "created $env_file"
else
  echo "exists  $env_file"
fi

if [ ! -f "$tools_file" ]; then
  cat > "$tools_file" <<'EOF'
tools:
  apt: []
  mise: []
  shell: []
EOF
  echo "created $tools_file"
else
  echo "exists  $tools_file"
fi

echo "workspace $workspace_dir"
