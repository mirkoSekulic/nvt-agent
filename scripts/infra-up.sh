#!/usr/bin/env bash
set -euo pipefail

if ! docker network inspect agents-proxy >/dev/null 2>&1; then
  docker network create agents-proxy >/dev/null
fi

docker compose -f compose.infra.yaml up -d
