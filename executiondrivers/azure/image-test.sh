#!/usr/bin/env bash
set -euo pipefail

IMAGE="${NVT_AZURE_DRIVER_IMAGE:-nvt-azure-execution-driver:test}"
INSPECT_IMAGE="golang:1.24-alpine@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191"
[[ "$(docker image inspect --format '{{.Config.User}}' "${IMAGE}")" == "65532:65532" ]]
[[ "$(docker image inspect --format '{{json .Config.Entrypoint}}' "${IMAGE}")" == '["/usr/local/bin/nvt-azure-driver"]' ]]
if docker image inspect --format '{{json .Config.Env}}' "${IMAGE}" | grep -Eq 'AZURE_|nvt_(eg1|ri1|rc1)_'; then
  echo "Azure image configuration contains authority material" >&2
  exit 1
fi
# The repository workspace is mounted at the same absolute path into the
# sibling Docker daemon; its private /tmp is not. Keep bind-mount fixtures in
# the shared workspace so this exercises the actual ownership and modes.
workdir="$(mktemp -d "${PWD}/.azure-image-test.XXXXXX")"
container="$(docker create "${IMAGE}")"
cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  if [[ -d "${workdir}/state" ]]; then
    docker run --rm \
      -v "${workdir}/state:/var/lib/nvt-execution-driver" \
      --entrypoint /bin/sh "${INSPECT_IMAGE}" -c \
      "chown -R $(id -u):$(id -g) /var/lib/nvt-execution-driver" >/dev/null 2>&1 || true
  fi
  rm -rf "${workdir}"
}
trap cleanup EXIT
docker cp "${container}:/opt/nvt-azure/nvt-host-bootstrap" "${workdir}/nvt-host-bootstrap"
[[ -s "${workdir}/nvt-host-bootstrap" && -x "${workdir}/nvt-host-bootstrap" ]]
for forbidden in /bin/sh /bin/bash /usr/bin/az /usr/local/bin/bicep /usr/bin/terraform /usr/bin/git; do
  if docker run --rm --entrypoint "${forbidden}" "${IMAGE}" >/dev/null 2>&1; then
    echo "Azure driver image contains forbidden runtime tool ${forbidden}" >&2
    exit 1
  fi
done
set +e
startup_output="$(docker run --rm --entrypoint /usr/local/bin/nvt-azure-driver "${IMAGE}" 2>&1)"
startup_status=$?
set -e
[[ ${startup_status} -ne 0 ]]
[[ "${startup_output}" == "nvt-azure-driver: Workload Identity or state is unavailable" ]]

# Model a fresh Kubernetes PVC after fsGroup application: the mount root stays
# root-owned but is group-writable by the non-root driver. The driver must
# create and own a private child instead of attempting to chmod the mount root.
mkdir "${workdir}/state"
docker run --rm \
  -v "${workdir}/state:/var/lib/nvt-execution-driver" \
  --entrypoint /bin/sh "${INSPECT_IMAGE}" -c \
  'chown 0:65532 /var/lib/nvt-execution-driver && chmod 0770 /var/lib/nvt-execution-driver'
printf '%s' 'projected-workload-identity-token' >"${workdir}/token"
chmod 0644 "${workdir}/token"
docker run --rm \
  --user 65532:65532 \
  -e AZURE_TENANT_ID=11111111-1111-4111-8111-111111111111 \
  -e AZURE_CLIENT_ID=22222222-2222-4222-8222-222222222222 \
  -e AZURE_FEDERATED_TOKEN_FILE=/var/run/secrets/azure/tokens/identity-token \
  -e NVT_EXECUTION_DRIVER_STATE_DIR=/var/lib/nvt-execution-driver \
  -v "${workdir}/token:/var/run/secrets/azure/tokens/identity-token:ro" \
  -v "${workdir}/state:/var/lib/nvt-execution-driver" \
  "${IMAGE}"
docker run --rm \
  -v "${workdir}/state:/var/lib/nvt-execution-driver:ro" \
  --entrypoint /bin/sh "${INSPECT_IMAGE}" -c \
  'test "$(stat -c "%u:%a" /var/lib/nvt-execution-driver)" = "0:770" && test "$(stat -c "%a" /var/lib/nvt-execution-driver/azure)" = "700"'
