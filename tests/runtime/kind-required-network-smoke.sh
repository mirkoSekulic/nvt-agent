#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KIND_BIN="${KIND_BIN:-kind}"
# The regression must run against the production NVT DinD image: its entrypoint
# is what prepares storage/network arguments and hands startup back to the base
# image's Docker entrypoint. Stock docker:dind would silently pass while the
# NVT entrypoint was broken.
DIND_IMAGE="${NVT_DIND_TEST_IMAGE:-nvt-dind:latest}"
NETWORK_SUBNET="${NVT_KIND_NETWORK_SUBNET:-172.31.250.0/24}"
DAEMON="nvt-required-network-$RANDOM-$$"
CLUSTER="nvt-required-network-$RANDOM"
WORKDIR="$(mktemp -d "${ROOT}/.kind-required-network.XXXXXX")"
OUTER_DOCKER_HOST="${DOCKER_HOST:-}"
SOCKET_LINK="/tmp/nvt-kind-docker-$RANDOM-$$.sock"
nested_socket_ready=false

outer_docker() {
  DOCKER_HOST="${OUTER_DOCKER_HOST}" /usr/bin/docker "$@"
}

cleanup() {
  if [ "${nested_socket_ready}" = true ]; then
    PATH="${WORKDIR}:${PATH}" \
      NVT_DOCKER_REQUIRED_NETWORKS="${required_networks:-[]}" \
      NVT_DOCKER_REAL_BIN=/usr/bin/docker \
      NVT_DOCKER_ENSURE_BIN="${ROOT}/runtime/core/ensure-docker-networks.py" \
      DOCKER_HOST="${DOCKER_HOST:-}" \
      "${KIND_BIN}" delete cluster --name "${CLUSTER}" >/dev/null 2>&1 || true
  fi
  outer_docker rm -f "${DAEMON}" >/dev/null 2>&1 || true
  rm -f "${SOCKET_LINK}"
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

command -v "${KIND_BIN}" >/dev/null || { echo "kind is required" >&2; exit 2; }
"${KIND_BIN}" version | grep -q 'kind v0.32.0' || {
  echo "kind v0.32.0 is required for this regression" >&2
  exit 2
}

outer_docker image inspect "${DIND_IMAGE}" >/dev/null 2>&1 || {
  echo "required DinD image ${DIND_IMAGE} is missing; run: make dind-build DIND_IMAGE=${DIND_IMAGE}" >&2
  exit 1
}
outer_docker image inspect "${DIND_IMAGE}" --format '{{index .Config.Entrypoint 0}}' |
  grep -qx /usr/local/bin/nvt-dind-entrypoint || {
  echo "${DIND_IMAGE} is not the NVT DinD image" >&2
  exit 1
}

ln -s "${ROOT}/runtime/core/docker-wrapper.sh" "${WORKDIR}/docker"
mkdir -p "${WORKDIR}/socket"
outer_docker run -d --name "${DAEMON}" --privileged \
  -e DOCKER_TLS_CERTDIR= -v "${WORKDIR}/socket:/run/nvt-test" "${DIND_IMAGE}" \
  --host=unix:///run/nvt-test/docker.sock --tls=false >/dev/null

# The nested daemon creates its socket as root. Ask the outer daemon to grant
# this non-root runner access rather than relying on bind-mount ownership or a
# privileged host command.
for _ in $(seq 1 60); do
  if outer_docker exec "${DAEMON}" test -S /run/nvt-test/docker.sock >/dev/null 2>&1 &&
    outer_docker exec "${DAEMON}" chmod 0666 /run/nvt-test/docker.sock >/dev/null 2>&1 &&
    [ -S "${WORKDIR}/socket/docker.sock" ] &&
    [ -r "${WORKDIR}/socket/docker.sock" ] &&
    [ -w "${WORKDIR}/socket/docker.sock" ]; then
    nested_socket_ready=true
    break
  fi
  sleep 1
done
if [ "${nested_socket_ready}" != true ]; then
  echo "nested Docker socket did not become accessible to the test runner" >&2
  exit 1
fi

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

# The NVT entrypoint must hand startup back to the base image's Docker
# entrypoint, which injects docker-init as PID 1 and runs the upstream
# cgroup-v2 nesting setup. Executing dockerd directly leaves dockerd as PID 1
# and skips that setup.
outer_docker exec "${DAEMON}" cat /proc/1/comm | grep -qx docker-init || {
  echo "DinD did not start through the base image Docker entrypoint" >&2
  exit 1
}
if outer_docker exec "${DAEMON}" test -f /sys/fs/cgroup/cgroup.controllers; then
  # Evacuating the cgroup root and enabling the delegated controllers is the
  # nesting setup this smoke can observe. The resulting root cgroup.type also
  # depends on the outer host's own delegation, so it is reported rather than
  # asserted here; the AKS Kata gate is what proves the real topology.
  outer_docker exec "${DAEMON}" test -d /sys/fs/cgroup/init || {
    echo "DinD cgroup root was not evacuated by the base image entrypoint" >&2
    exit 1
  }
  outer_docker exec "${DAEMON}" grep -q . /sys/fs/cgroup/cgroup.subtree_control || {
    echo "DinD cgroup root has no delegated controllers" >&2
    exit 1
  }
  printf 'DinD cgroup root: type=%s subtree_control=%s\n' \
    "$(outer_docker exec "${DAEMON}" cat /sys/fs/cgroup/cgroup.type 2>/dev/null || echo domain)" \
    "$(outer_docker exec "${DAEMON}" cat /sys/fs/cgroup/cgroup.subtree_control)"
fi

# This prune operates only on the disposable nested daemon. The wrapper must
# recreate the unused required network synchronously before returning.
docker system prune --all --force --volumes >/dev/null
docker network inspect kind --format '{{.EnableIPv6}} {{(index .IPAM.Config 0).Subnet}}' |
  grep -qx "false ${NETWORK_SUBNET}"

"${KIND_BIN}" create cluster --name "${CLUSTER}" --wait 180s
"${KIND_BIN}" get nodes --name "${CLUSTER}" | grep -q "${CLUSTER}-control-plane"
docker network inspect kind --format '{{.EnableIPv6}} {{(index .IPAM.Config 0).Subnet}}' |
  grep -qx "false ${NETWORK_SUBNET}"

printf 'kind v0.32.0 required IPv4 network smoke passed against %s\n' "${DIND_IMAGE}"
