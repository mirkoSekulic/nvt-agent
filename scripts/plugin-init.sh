#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --name <name> [--dir <dir>]" >&2
}

render_template() {
  local template="$1"
  local target="$2"
  python3 - "$template" "$target" <<'PY'
import os
import sys
from pathlib import Path

template = Path(sys.argv[1])
target = Path(sys.argv[2])
content = template.read_text(encoding="utf-8")
for key, value in os.environ.items():
    content = content.replace("{{" + key + "}}", value)
target.write_text(content, encoding="utf-8")
PY
}

name=""
target_dir="runtime/plugins"

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
    --dir)
      if [ "$#" -lt 2 ]; then
        usage
        exit 1
      fi
      target_dir="$2"
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
templates_dir="$repo_root/templates/plugin"

bash "$script_dir/validate-agent-name.sh" "$name"

case "$target_dir" in
  /*) plugins_dir="$target_dir" ;;
  *) plugins_dir="$repo_root/$target_dir" ;;
esac

plugin_dir="$plugins_dir/$name"
if [ -e "$plugin_dir" ]; then
  echo "plugin already exists: $plugin_dir" >&2
  exit 1
fi

if [ "$plugins_dir" = "$repo_root/runtime/plugins" ]; then
  plugin_command="/usr/local/lib/nvt-agent/plugins/$name/run.sh"
else
  plugin_command="/custom-plugins/$name/run.sh"
fi

mkdir -p "$plugin_dir"

PLUGIN_NAME="$name" \
PLUGIN_COMMAND="$plugin_command" \
  render_template "$templates_dir/plugin.yaml" "$plugin_dir/plugin.yaml"

PLUGIN_NAME="$name" \
  render_template "$templates_dir/run.sh" "$plugin_dir/run.sh"
chmod +x "$plugin_dir/run.sh"

PLUGIN_NAME="$name" \
PLUGIN_COMMAND="$plugin_command" \
  render_template "$templates_dir/README.md" "$plugin_dir/README.md"

echo "created $plugin_dir"
