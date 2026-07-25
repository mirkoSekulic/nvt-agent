#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KIND_BIN="${KIND_BIN:-kind}"
DIND_IMAGE="${NVT_KIND_DIND_IMAGE:-docker:27.5.1-dind}"
NETWORK_SUBNET="${NVT_KIND_NETWORK_SUBNET:-172.31.250.0/24}"
DAEMON="nvt-required-network-$RANDOM-$$"
CLUSTER="nvt-required-network-$RANDOM"
WORKDIR="$(mktemp -d "${ROOT}/.kind-required-network.XXXXXX")"
OUTER_DOCKER_HOST="${DOCKER_HOST:-}"
SOCKET_LINK="/tmp/nvt-kind-docker-$RANDOM-$$.sock"

cleanup() {
  PATH="${WORKDIR}:${PATH}" \
    NVT_DOCKER_REQUIRED_NETWORKS="${required_networks:-[]}" \
    NVT_DOCKER_REAL_BIN=/usr/bin/docker \
    NVT_DOCKER_ENSURE_BIN="${ROOT}/runtime/core/ensure-docker-networks.py" \
    DOCKER_HOST="${DOCKER_HOST:-}" \
    "${KIND_BIN}" delete cluster --name "${CLUSTER}" >/dev/null 2>&1 || true
  DOCKER_HOST="${OUTER_DOCKER_HOST}" /usr/bin/docker rm -f "${DAEMON}" >/dev/null 2>&1 || true
  rm -f "${SOCKET_LINK}"
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

command -v "${KIND_BIN}" >/dev/null || { echo "kind is required" >&2; exit 2; }
"${KIND_BIN}" version | grep -q 'kind v0.32.0' || {
  echo "kind v0.32.0 is required for this regression" >&2
  exit 2
}

ln -s "${ROOT}/runtime/core/docker-wrapper.sh" "${WORKDIR}/docker"
docker run -d --name "${DAEMON}" --privileged \
  -e DOCKER_TLS_CERTDIR= -v "${WORKDIR}/socket:/run/nvt-test" "${DIND_IMAGE}" \
  --host=unix:///run/nvt-test/docker.sock --tls=false >/dev/null
ln -s "${WORKDIR}/socket/docker.sock" "${SOCKET_LINK}"
export DOCKER_HOST="unix://${SOCKET_LINK}"
required_networks="[{\"name\":\"kind\",\"subnet\":\"${NETWORK_SUBNET}\"}]"
export NVT_DOCKER_REQUIRED_NETWORKS="${required_networks}"
export NVT_DOCKER_REAL_BIN=/usr/bin/docker
export NVT_DOCKER_ENSURE_BIN="${ROOT}/runtime/core/ensure-docker-networks.py"
export PATH="${WORKDIR}:${PATH}"

for _ in $(seq 1 60); do
  docker info >/dev/null 2>&1 && break
  sleep 1
done
docker info >/dev/null

# This prune operates only on the disposable nested daemon. The wrapper must
# recreate the unused required network synchronously before returning.
docker system prune --all --force --volumes >/dev/null
docker network inspect kind --format '{{.EnableIPv6}} {{(index .IPAM.Config 0).Subnet}}' |
  grep -qx "false ${NETWORK_SUBNET}"

"${KIND_BIN}" create cluster --name "${CLUSTER}" --wait 180s
"${KIND_BIN}" get nodes --name "${CLUSTER}" | grep -q "${CLUSTER}-control-plane"
docker network inspect kind --format '{{.EnableIPv6}} {{(index .IPAM.Config 0).Subnet}}' |
  grep -qx "false ${NETWORK_SUBNET}"

echo "kind v0.32.0 required IPv4 network smoke passed"
