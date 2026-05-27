#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --name <name> --port <remote-port> [--local <local-port>]" >&2
}

valid_port() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

name=""
port=""
local_port=""

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
    --port)
      if [ "$#" -lt 2 ]; then
        usage
        exit 1
      fi
      port="$2"
      shift 2
      ;;
    --local)
      if [ "$#" -lt 2 ]; then
        usage
        exit 1
      fi
      local_port="$2"
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

if [ -z "$name" ] || [ -z "$port" ]; then
  usage
  exit 1
fi
if [ -z "$local_port" ]; then
  local_port="$port"
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"

bash "$script_dir/validate-agent-name.sh" "$name"

env_file="$repo_root/.agents/$name/env"
if [ ! -f "$env_file" ]; then
  echo "agent $name is not initialized; run: make agent-init NAME=$name" >&2
  exit 1
fi

if ! valid_port "$port"; then
  echo "invalid PORT: $port" >&2
  exit 1
fi
if ! valid_port "$local_port"; then
  echo "invalid LOCAL: $local_port" >&2
  exit 1
fi

container_id="$(docker compose \
  -p "agent-$name" \
  --env-file "$env_file" \
  -f "$repo_root/compose.agent.yaml" \
  ps -q agent)"
if [ -z "$container_id" ]; then
  echo "agent $name is not running" >&2
  exit 1
fi

agents_proxy_id="$(docker network inspect -f '{{.ID}}' agents-proxy)"
agent_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{if eq .NetworkID "'"$agents_proxy_id"'"}}{{.IPAddress}}{{end}}{{end}}' "$container_id")"
if [ -z "$agent_ip" ]; then
  echo "agent $name is not attached to agents-proxy" >&2
  exit 1
fi

echo "forward http://127.0.0.1:$local_port -> $name:$port"
echo "using alpine/socat; Docker may pull the image on first use"
exec docker run --rm \
  -p "127.0.0.1:$local_port:$local_port" \
  --network agents-proxy \
  alpine/socat \
  "TCP-LISTEN:$local_port,fork,reuseaddr" \
  "TCP:$agent_ip:$port"
