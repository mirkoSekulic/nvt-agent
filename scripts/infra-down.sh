#!/usr/bin/env bash
set -euo pipefail

docker compose -f compose.infra.yaml down
