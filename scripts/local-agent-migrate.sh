#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
manifest="${1:-$repo_root/.agents/local-controller-migration.yaml}"
output="${2:-$repo_root/.broker/local-controller.json}"

if [ ! -f "$manifest" ]; then
  echo "local-agent-migrate: manifest not found" >&2
  exit 1
fi

mkdir -p "$repo_root/.broker"
(
  cd "$repo_root/localcontroller"
  go run ./cmd/nvt-local-migrate \
    --manifest "$manifest" \
    --agents-root "$repo_root/.agents" \
    --broker-agents "$repo_root/.broker/agents.yaml" \
    --broker-config "$repo_root/.broker/broker.yaml" \
    --output "$output"
)
echo "wrote $output"
