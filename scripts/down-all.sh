#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

bash "$script_dir/agent-down-all.sh"
bash "$script_dir/infra-down.sh"

echo "all agents and infra are down"
