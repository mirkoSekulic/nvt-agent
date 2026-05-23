#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"

docker build "$@" -t nvt-agent-runtime:latest -f "$repo_root/runtime/Dockerfile" "$repo_root"
