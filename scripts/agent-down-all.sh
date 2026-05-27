#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
agents_dir="$repo_root/.agents"

found=0
for env_file in "$agents_dir"/*/env; do
  [ -f "$env_file" ] || continue
  found=1

  unset AGENT_NAME
  set -a
  source "$env_file"
  set +a

  name="${AGENT_NAME:-$(basename "$(dirname "$env_file")")}"
  bash "$script_dir/validate-agent-name.sh" "$name"

  docker compose \
    -p "agent-$name" \
    --env-file "$env_file" \
    -f "$repo_root/compose.agent.yaml" \
    down

  echo "agent $name is down"
done

if [ "$found" -eq 0 ]; then
  echo "no agents initialized"
fi
