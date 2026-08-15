#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
broker_dir="$repo_root/.broker"

compose_args=(-f "$repo_root/compose.infra.yaml")
if [ -f "$broker_dir/compose.producers.yaml" ]; then
  compose_args+=(-f "$broker_dir/compose.producers.yaml")
fi

docker compose "${compose_args[@]}" down
