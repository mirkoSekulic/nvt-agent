#!/usr/bin/env bash
set -euo pipefail

source="${NVT_PROMPT_SOURCE:-plugin}"

if [ "$#" -gt 0 ]; then
  exec agentdctl prompt --source "$source" --external "$@"
fi

if [ -t 0 ]; then
  echo "prompt-agent: expected prompt argument or stdin" >&2
  exit 1
fi

exec agentdctl prompt --source "$source" --external
