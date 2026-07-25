#!/usr/bin/env bash
set -euo pipefail

IMAGE="${NVT_DIND_TEST_IMAGE:-nvt-dind:test}"
NESTED_IMAGE="${NVT_DIND_KMSG_NESTED_IMAGE:-busybox:1.36}"
DAEMON="nvt-dind-kmsg-${RANDOM}-$$"

cleanup() {
  docker rm -f "${DAEMON}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker image inspect "${IMAGE}" >/dev/null 2>&1 || {
  echo "required DinD image ${IMAGE} is missing" >&2
  exit 1
}

docker run -d --privileged --name "${DAEMON}" \
  -e DOCKER_TLS_CERTDIR= \
  -e NVT_DIND_KERNEL_LOG_DEVICE=true \
  "${IMAGE}" --tls=false >/dev/null

for _ in $(seq 1 60); do
  if docker exec "${DAEMON}" docker info >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "${DAEMON}" docker info >/dev/null

docker exec "${DAEMON}" sh -ec \
  'test -c /dev/kmsg && test "$(stat -c "%t:%T" /dev/kmsg)" = 1:b'
docker exec "${DAEMON}" docker run --rm --privileged "${NESTED_IMAGE}" sh -ec \
  'test -c /dev/kmsg && test "$(stat -c "%t:%T" /dev/kmsg)" = 1:b'

# Prove that NVT itself creates the device rather than merely accepting one
# inherited from the outer container runtime. The real entrypoint runs against
# isolated empty device directories, while a stub vendor entrypoint stops
# before starting a second daemon.
created_device="$(docker exec -i "${DAEMON}" sh -s <<'PROBE'
set -eu
run_entrypoint() {
  probe="$1"
  intent="$2"
  rm -rf "${probe}"
  mkdir -p "${probe}/bin" "${probe}/data" "${probe}/run"
  printf '%s\n' '#!/bin/sh' 'exit 0' >"${probe}/bin/dockerd-entrypoint.sh"
  chmod 0755 "${probe}/bin/dockerd-entrypoint.sh"
  (
    PATH="${probe}/bin:${PATH}" \
      NVT_DIND_DEVICE_DIR="${probe}" \
      NVT_DIND_DATA_ROOT="${probe}/data" \
      NVT_DIND_RUN_DIR="${probe}/run" \
      NVT_DIND_KERNEL_LOG_DEVICE="${intent}" \
      /usr/local/bin/nvt-dind-entrypoint --tls=false
  )
}
run_entrypoint /run/nvt-kmsg-off false
test ! -e /run/nvt-kmsg-off/kmsg
run_entrypoint /run/nvt-kmsg-on true
test -c /run/nvt-kmsg-on/kmsg
stat -c '%t:%T %a' /run/nvt-kmsg-on/kmsg
PROBE
)"
if [[ "${created_device}" != "1:b 600" ]]; then
  echo "entrypoint created unexpected kernel-log device metadata: ${created_device}" >&2
  exit 1
fi

echo "nested privileged kernel-log device smoke passed (created ${created_device})"
