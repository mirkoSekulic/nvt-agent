#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --name <name> --provider <provider> --repo <owner/repo> [--materialization file-bundle|header-inject]" >&2
}

name=""
provider=""
repo=""
materialization="file-bundle"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --name)
      name="${2:-}"
      shift 2
      ;;
    --provider)
      provider="${2:-}"
      shift 2
      ;;
    --repo)
      repo="${2:-}"
      shift 2
      ;;
    --materialization)
      materialization="${2:-}"
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

if [ -z "$name" ] || [ -z "$provider" ] || [ -z "$repo" ]; then
  usage
  exit 1
fi
case "$materialization" in
  file-bundle|header-inject) ;;
  *)
    echo "invalid materialization: $materialization" >&2
    usage
    exit 1
    ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"

bash "$script_dir/validate-agent-name.sh" "$name"

agents_file="$repo_root/.broker/agents.yaml"
if [ ! -f "$agents_file" ]; then
  echo "broker agents file does not exist; run: make agent-init NAME=$name" >&2
  exit 1
fi

python3 "$script_dir/broker-agents.py" \
  --agents-file "$agents_file" \
  grant \
  --name "$name" \
  --provider "$provider" \
  --repo "$repo" \
  --materialization "$materialization"

echo "granted $name provider=$provider repo=$repo materialization=$materialization"
