#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"

docker build -t nvt-broker:latest -f "$repo_root/broker/Dockerfile" "$repo_root"
