#!/usr/bin/env bash
set -euo pipefail

# Proves the end-to-end device contract against a built NVT DinD image:
#
# 1. with the option enabled the sidecar has a real kernel-log character device
#    (1:11) and a nested privileged container inherits it with no
#    workload-specific configuration;
# 2. the entrypoint really creates that device with mknod where the runtime does
#    not already provide one, and creates nothing when the option is off.
#
# The second check runs the entrypoint against an empty probe device directory,
# because a privileged container inherits the container runtime's /dev and may
# therefore already have /dev/kmsg for reasons unrelated to NVT.

IMAGE="${NVT_DIND_TEST_IMAGE:-nvt-dind:latest}"
NESTED_IMAGE="${NVT_DIND_NESTED_TEST_IMAGE:-busybox:1.36}"
DAEMON="nvt-dind-kmsg-${RANDOM}-$$"

cleanup() {
  docker rm -f "${DAEMON}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker image inspect "${IMAGE}" >/dev/null 2>&1 || {
  echo "required DinD image ${IMAGE} is missing; run: make dind-build DIND_IMAGE=${IMAGE}" >&2
  exit 1
}

docker run -d --name "${DAEMON}" --privileged \
  -e DOCKER_TLS_CERTDIR= -e NVT_DIND_KERNEL_LOG_DEVICE=true "${IMAGE}" \
  --host=unix:///var/run/docker.sock --tls=false >/dev/null
for _ in $(seq 1 60); do
  if docker exec "${DAEMON}" docker info >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "${DAEMON}" docker info >/dev/null

# The sidecar has a real character device, not a symlink or a regular file.
sidecar_device="$(docker exec "${DAEMON}" stat -c '%F %t %T' /dev/kmsg)"
if [[ "${sidecar_device}" != "character special file 1 b" ]]; then
  echo "DinD sidecar kernel log device is '${sidecar_device}', expected character device 1:11" >&2
  exit 1
fi

# A nested privileged container inherits the device with no extra configuration.
docker exec "${DAEMON}" docker pull "${NESTED_IMAGE}" >/dev/null
nested_device="$(docker exec "${DAEMON}" docker run --rm --privileged "${NESTED_IMAGE}" \
  stat -c '%F %t %T' /dev/kmsg)"
if [[ "${nested_device}" != "character special file 1 b" ]]; then
  echo "nested privileged container saw '${nested_device}', expected character device 1:11" >&2
  exit 1
fi

# Run the real entrypoint against empty probe device directories. A stub vendor
# entrypoint on PATH ends startup as soon as device and storage preparation is
# done, and the subshell keeps its exec from replacing the probe script.
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
if [ -e /run/nvt-kmsg-off/kmsg ]; then
  echo "kernel log device was created while the option was off" >&2
  exit 1
fi
run_entrypoint /run/nvt-kmsg-on true
stat -c '%F %t %T' /run/nvt-kmsg-on/kmsg
PROBE
)"
if [[ "${created_device}" != "character special file 1 b" ]]; then
  echo "entrypoint created '${created_device}', expected character device 1:11" >&2
  exit 1
fi

printf 'nvt-dind kernel log device smoke passed against %s (sidecar, nested, and created: %s)\n' \
  "${IMAGE}" "${nested_device}"
