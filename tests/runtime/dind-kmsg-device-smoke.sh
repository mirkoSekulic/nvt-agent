#!/usr/bin/env bash
set -euo pipefail

IMAGE="${NVT_DIND_TEST_IMAGE:-nvt-dind:test}"
NESTED_IMAGE="${NVT_DIND_KMSG_NESTED_IMAGE:-busybox:1.36}"
DAEMON="nvt-dind-kmsg-${RANDOM}-$$"

cleanup() {
  docker rm -f "${DAEMON}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

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

echo "nested privileged kernel-log device smoke passed"
