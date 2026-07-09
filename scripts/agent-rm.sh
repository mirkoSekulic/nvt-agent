#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --name <name> [--force]" >&2
}

name=""
force=0

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
    --force)
      force=1
      shift
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

agent_dir="$repo_root/.agents/$name"
env_file="$agent_dir/env"
egressd_env_file="$agent_dir/egressd.env"

if [ ! -d "$agent_dir" ]; then
  echo "agent $name does not exist"
  exit 0
fi

if [ "$force" -ne 1 ]; then
  printf "remove agent %s, including local files and Docker volumes? [y/N] " "$name" >&2
  read -r answer
  case "$answer" in
    y|Y|yes|YES) ;;
    *)
      echo "aborted" >&2
      exit 1
      ;;
  esac
fi

if [ -f "$env_file" ]; then
  compose_env_args=(--env-file "$env_file")
  if [ -f "$egressd_env_file" ]; then
    compose_env_args+=(--env-file "$egressd_env_file")
  fi
  docker compose \
    -p "agent-$name" \
    "${compose_env_args[@]}" \
    -f "$repo_root/compose.agent.yaml" \
    down -v
fi

rm -rf "$agent_dir"

echo "removed agent $name"
