#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
templates_dir="$repo_root/templates"
broker_dir="$repo_root/.broker"

if ! docker network inspect agents-proxy >/dev/null 2>&1; then
  docker network create agents-proxy >/dev/null
fi

mkdir -p "$broker_dir"
if [ ! -f "$broker_dir/broker.yaml" ]; then
  cp "$templates_dir/broker.yaml" "$broker_dir/broker.yaml"
fi
if [ ! -f "$broker_dir/agents.yaml" ]; then
  cp "$templates_dir/broker-agents.yaml" "$broker_dir/agents.yaml"
fi
if [ ! -f "$broker_dir/env" ]; then
  cp "$templates_dir/broker-env" "$broker_dir/env"
fi
if [ ! -f "$broker_dir/local-controller.key" ]; then
  (umask 077; openssl rand 32 >"$broker_dir/local-controller.key")
fi
chmod 600 "$broker_dir/local-controller.key"
for token_name in local-controller-admin-token local-controller-route-token; do
  if [ ! -f "$broker_dir/$token_name" ]; then
    (umask 077; openssl rand -hex 32 >"$broker_dir/$token_name")
  fi
  chmod 600 "$broker_dir/$token_name"
done

# The gateway remains non-root while reading its mode-0600 bind-mounted route
# credential on native Linux. Docker Desktop also accepts the numeric host UID.
export NVT_LOCAL_GATEWAY_UID="$(id -u)"
export NVT_LOCAL_GATEWAY_GID="$(id -g)"

if [ -f "$broker_dir/local-controller.yaml" ] && [ -z "${NVT_LOCAL_CONTROLLER_CONFIG+x}" ]; then
  export NVT_LOCAL_CONTROLLER_CONFIG=/broker-state/local-controller.yaml
fi

docker compose -f "$repo_root/compose.infra.yaml" up -d
