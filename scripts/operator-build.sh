#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
image="${IMAGE:-nvt-operator:latest}"

docker build "$@" -t "$image" -f "$repo_root/operator/Dockerfile" "$repo_root"
