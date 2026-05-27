#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
templates_dir="$repo_root/templates"
broker_dir="$repo_root/.broker"

if ! docker network inspect agents-proxy >/dev/null 2>&1; then
  docker network create agents-proxy >/dev/null
fi

mkdir -p "$broker_dir"
if [ ! -f "$broker_dir/broker.yaml" ]; then
  cp "$templates_dir/broker.yaml" "$broker_dir/broker.yaml"
fi
if [ ! -f "$broker_dir/agents.yaml" ]; then
  cp "$templates_dir/broker-agents.yaml" "$broker_dir/agents.yaml"
fi
if [ ! -f "$broker_dir/env" ]; then
  cp "$templates_dir/broker-env" "$broker_dir/env"
fi

docker compose -f "$repo_root/compose.infra.yaml" up -d
