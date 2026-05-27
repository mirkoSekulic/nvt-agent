#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --name <name>" >&2
}

name=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --name)
      if [ "$#" -lt 2 ]; then
        usage
        exit 1
      fi
      name="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [ -z "$name" ]; then
  usage
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"

bash "$script_dir/validate-agent-name.sh" "$name"

env_file="$repo_root/.agents/$name/env"

if [ ! -f "$env_file" ]; then
  echo "agent $name is not initialized; run: make agent-init NAME=$name" >&2
  exit 1
fi

docker compose \
  -p "agent-$name" \
  --env-file "$env_file" \
  -f "$repo_root/compose.agent.yaml" \
  down

echo "agent $name is down"
