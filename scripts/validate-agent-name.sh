#!/usr/bin/env bash
set -euo pipefail

name="${1:-}"

if [[ ! "$name" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]]; then
  echo "invalid agent name: $name" >&2
  echo "agent names must use lowercase letters, numbers, and hyphens, and start/end with a letter or number" >&2
  exit 1
fi
