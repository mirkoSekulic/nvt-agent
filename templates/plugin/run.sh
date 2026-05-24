#!/usr/bin/env bash
set -euo pipefail

command="${1:-run}"

case "$command" in
  run)
    echo "{{PLUGIN_NAME}}"
    ;;
  doctor)
    command -v bash >/dev/null
    echo "ok bash available"
    ;;
  ready)
    exit 0
    ;;
  *)
    echo "usage: $0 [run|doctor|ready]" >&2
    exit 2
    ;;
esac
