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
  egressd_env_file="$agents_dir/$name/egressd.env"
  compose_env_args=(--env-file "$env_file")
  if [ -f "$egressd_env_file" ]; then
    compose_env_args+=(--env-file "$egressd_env_file")
  fi

  docker compose \
    -p "agent-$name" \
    "${compose_env_args[@]}" \
    -f "$repo_root/compose.agent.yaml" \
    down

  echo "agent $name is down"
done

if [ "$found" -eq 0 ]; then
  echo "no agents initialized"
fi
