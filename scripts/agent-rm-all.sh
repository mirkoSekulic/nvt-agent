#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 [--force]" >&2
}

force=0

while [ "$#" -gt 0 ]; do
  case "$1" in
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

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
agents_dir="$repo_root/.agents"

agent_names=()
for agent_dir in "$agents_dir"/*; do
  [ -d "$agent_dir" ] || continue
  [ -f "$agent_dir/env" ] || continue
  name="$(basename "$agent_dir")"
  "$script_dir/validate-agent-name.sh" "$name"
  agent_names+=("$name")
done

if [ "${#agent_names[@]}" -eq 0 ]; then
  echo "no agents initialized"
  exit 0
fi

if [ "$force" -ne 1 ]; then
  printf "remove all agents, including local files and Docker volumes? [y/N] " >&2
  read -r answer
  case "$answer" in
    y|Y|yes|YES) ;;
    *)
      echo "aborted" >&2
      exit 1
      ;;
  esac
fi

for name in "${agent_names[@]}"; do
  "$script_dir/agent-rm.sh" --name "$name" --force
done
