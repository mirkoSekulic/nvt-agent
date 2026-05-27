#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
agents_dir="$repo_root/.agents"
proxy_port="${NVT_PROXY_PORT:-4090}"

printf "%-24s %-10s %-8s %s\n" "NAME" "STATUS" "TYPE" "URL"

found=0
for env_file in "$agents_dir"/*/env; do
  [ -f "$env_file" ] || continue
  found=1

  unset AGENT_NAME AGENT_HOST
  set -a
  source "$env_file"
  set +a

  name="${AGENT_NAME:-$(basename "$(dirname "$env_file")")}"
  bash "$script_dir/validate-agent-name.sh" "$name"

  container_id="$(
    docker compose \
      -p "agent-$name" \
      --env-file "$env_file" \
      -f "$repo_root/compose.agent.yaml" \
      ps -q agent 2>/dev/null || true
  )"

  if [ -n "$container_id" ]; then
    status="$(docker inspect -f '{{.State.Status}}' "$container_id" 2>/dev/null || echo unknown)"
  else
    status="stopped"
  fi

  printf "%-24s %-10s %-8s http://%s:%s\n" \
    "$name" \
    "$status" \
    "-" \
    "${AGENT_HOST:-$name.agent.localhost}" \
    "$proxy_port"
done

if [ "$found" -eq 0 ]; then
  echo "no agents initialized"
fi
