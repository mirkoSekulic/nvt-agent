#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" != "2" ]]; then
  echo "usage: $0 <registry-owner> <release-tag>" >&2
  exit 2
fi

owner="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
release_tag="$2"
if [[ ! "${owner}" =~ ^[a-z0-9][a-z0-9-]*$ ]] ||
   [[ ! "${release_tag}" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
  echo "invalid public image verification metadata" >&2
  exit 2
fi

images=(
  nvt-agent-runtime
  nvt-dind
  nvt-broker
  nvt-egressd
  nvt-captured
  nvt-operator
  nvt-agent-gateway
  nvt-github-comments-producer
)

# An empty, private Docker config prevents credentials from the preceding GHCR
# login step or host credential helpers from being reused for this proof.
anonymous_config="$(mktemp -d)"
trap 'rm -rf "${anonymous_config}"' EXIT
printf '{"auths":{}}\n' >"${anonymous_config}/config.json"

for name in "${images[@]}"; do
  image="ghcr.io/${owner}/${name}:${release_tag}"
  verified=0
  for _ in $(seq 1 "${NVT_PUBLIC_VERIFY_ATTEMPTS:-10}"); do
    if DOCKER_CONFIG="${anonymous_config}" docker manifest inspect "${image}" >/dev/null 2>&1; then
      verified=1
      break
    fi
    sleep "${NVT_PUBLIC_VERIFY_DELAY_SECONDS:-2}"
  done
  if [[ "${verified}" != "1" ]]; then
    echo "image is not anonymously readable: ${image}" >&2
    exit 2
  fi
done

echo "Verified anonymous manifest access for all eight release images."
