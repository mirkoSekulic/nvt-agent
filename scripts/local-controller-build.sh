#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"

docker build -t nvt-local-controller:latest -f "$repo_root/localcontroller/Dockerfile" "$repo_root"
