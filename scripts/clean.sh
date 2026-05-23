#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

"$script_dir/down-all.sh"
"$script_dir/infra-network-rm.sh"

echo "cleaned infra containers and proxy network"
