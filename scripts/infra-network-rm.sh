#!/usr/bin/env bash
set -euo pipefail

network="${NVT_PROXY_NETWORK:-agents-proxy}"

if ! docker network inspect "$network" >/dev/null 2>&1; then
  echo "network $network does not exist"
  exit 0
fi

docker network rm "$network"
echo "removed network $network"
