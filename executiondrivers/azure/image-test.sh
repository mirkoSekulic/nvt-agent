#!/usr/bin/env bash
set -euo pipefail

IMAGE="${NVT_AZURE_DRIVER_IMAGE:-nvt-azure-execution-driver:test}"
[[ "$(docker image inspect --format '{{.Config.User}}' "${IMAGE}")" == "65532:65532" ]]
[[ "$(docker image inspect --format '{{json .Config.Entrypoint}}' "${IMAGE}")" == '["/usr/local/bin/nvt-azure-driver"]' ]]
if docker image inspect --format '{{json .Config.Env}}' "${IMAGE}" | grep -Eq 'AZURE_|nvt_(eg1|ri1|rc1)_'; then
  echo "Azure image configuration contains authority material" >&2
  exit 1
fi
workdir="$(mktemp -d)"
container="$(docker create "${IMAGE}")"
trap 'docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf "${workdir}"' EXIT
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
