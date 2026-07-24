#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --name <name>" >&2
}

name=""

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

bash "$script_dir/validate-agent-name.sh" "$name"

env_file="$repo_root/.agents/$name/env"
egressd_env_file="$repo_root/.agents/$name/egressd.env"

if [ ! -f "$env_file" ]; then
  echo "agent $name is not initialized; run: make agent-init NAME=$name" >&2
  exit 1
fi

set -a
source "$env_file"
set +a

# Upgrade only nvt's marker-owned egress block. Existing identities, Secrets,
# runtime settings, and unmarked user-authored YAML remain untouched.
egress_mode="${NVT_EGRESS_MODE:-}"
if [ -z "$egress_mode" ]; then
  case "${MEDIATED:-0}" in
    1|true|TRUE|True|yes|YES|Yes) egress_mode="mediated" ;;
    *) egress_mode="direct" ;;
  esac
fi
python3 "$script_dir/render-managed-egress.py" \
  --agent-config "$AGENT_CONFIG_FILE" \
  --broker-agents "$repo_root/.broker/agents.yaml" \
  --agent-name "$name" \
  --mode "$egress_mode" \
  --egressd-config "$EGRESSD_CONFIG_FILE"

expose_compose_file="$repo_root/.agents/$name/compose.expose.yaml"

python3 "$script_dir/render-agent-expose.py" \
  --agent-config "$AGENT_CONFIG_FILE" \
  --agent-name "$AGENT_NAME" \
  --agent-host "$AGENT_HOST" \
  --output "$expose_compose_file"

if [ "$egress_mode" = "mediated" ]; then
  dind_image="${DIND_IMAGE:-nvt-dind:latest}"
  export DIND_IMAGE="$dind_image"
  if ! docker image inspect "$dind_image" >/dev/null 2>&1; then
    echo "required DinD image $dind_image is missing; build it with: make dind-build DIND_IMAGE=$dind_image" >&2
    exit 1
  fi
fi

if ! docker network inspect agents-proxy >/dev/null 2>&1; then
  docker network create agents-proxy >/dev/null
fi

compose_env_args=(--env-file "$env_file")
if [ -f "$egressd_env_file" ]; then
  compose_env_args+=(--env-file "$egressd_env_file")
fi

docker compose \
  -p "agent-$name" \
  "${compose_env_args[@]}" \
  -f "$repo_root/compose.agent.yaml" \
  -f "$expose_compose_file" \
  up -d

echo "agent $name is up"
echo "url http://${AGENT_HOST}:${NVT_PROXY_PORT:-4090}"
python3 "$script_dir/render-agent-expose.py" \
  --agent-config "$AGENT_CONFIG_FILE" \
  --agent-name "$AGENT_NAME" \
  --agent-host "$AGENT_HOST" \
  --output "$expose_compose_file" \
  --print-urls
