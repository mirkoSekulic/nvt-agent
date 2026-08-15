#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
manifest="${1:-$repo_root/templates/local-controller-migration.yaml}"
if [[ "$manifest" != /* ]]; then
  manifest="$repo_root/$manifest"
fi

if (
  cd "$repo_root/localcontroller"
  go run ./cmd/nvt-local-migrate \
    --check \
    --manifest "$manifest" \
    --agents-root "$repo_root/.agents" \
    --broker-agents "$repo_root/.broker/agents.yaml" \
    --broker-config "$repo_root/.broker/broker.yaml"
) >/dev/null 2>&1; then
  echo "local-agent-migration-real-config-proof: PASS"
else
  echo "local-agent-migration-real-config-proof: FAIL"
  exit 1
fi
