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

if [ "$force" -ne 1 ]; then
  printf "nuke all agents, agent files, Docker volumes, infra, and proxy network? [y/N] " >&2
  read -r answer
  case "$answer" in
    y|Y|yes|YES) ;;
    *)
      echo "aborted" >&2
      exit 1
      ;;
  esac
fi

"$script_dir/agent-rm-all.sh" --force
"$script_dir/infra-down.sh"
"$script_dir/infra-network-rm.sh"

echo "nuked all agents, infra, and proxy network"
