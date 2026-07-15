#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

SHA=943d5ba111111111111111111111111111111111
mkdir -p "${WORKDIR}/chart"
printf 'version: 0.2.0\n' >"${WORKDIR}/chart/Chart.yaml"
metadata="$(bash "${ROOT}/.github/scripts/release-metadata.sh" "${WORKDIR}/chart" "${SHA}")"
grep -qx 'VERSION=0.2.0' <<<"${metadata}"
grep -qx 'SHORT_SHA=943d5ba' <<<"${metadata}"
grep -qx 'RELEASE_TAG=0.2.0-943d5ba' <<<"${metadata}"

mkdir -p "${WORKDIR}/invalid"
printf 'version: latest\n' >"${WORKDIR}/invalid/Chart.yaml"
if bash "${ROOT}/.github/scripts/release-metadata.sh" "${WORKDIR}/invalid" "${SHA}" >/dev/null 2>&1; then
  echo "malformed chart version was accepted" >&2
  exit 1
fi

mkdir -p "${WORKDIR}/bin" "${WORKDIR}/manifests"
cat >"${WORKDIR}/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
set -euo pipefail
printf 'docker %s\n' "$*" >>"${DOCKER_LOG}"
case "$1 $2" in
  "manifest inspect")
    ref="$3"
    if [[ ! -f "${MANIFEST_DIR}/${ref//\//_}" ]]; then
      echo "manifest unknown" >&2
      exit 1
    fi
    ;;
  "image inspect")
    format="$4"
    if [[ "${format}" == *revision* ]]; then printf '%s\n' "${FAKE_REVISION}";
    elif [[ "${format}" == *source* ]]; then printf '%s\n' "${FAKE_SOURCE}";
    else printf '%s\n' "${FAKE_VERSION}"; fi
    ;;
  "pull --quiet") ;;
  "build --label") ;;
  "push "*)
    ref="$2"
    : >"${MANIFEST_DIR}/${ref//\//_}"
    ;;
  *) echo "unexpected docker invocation: $*" >&2; exit 1 ;;
esac
DOCKER
chmod +x "${WORKDIR}/bin/docker"
export PATH="${WORKDIR}/bin:${PATH}"
export DOCKER_LOG="${WORKDIR}/docker.log"
export MANIFEST_DIR="${WORKDIR}/manifests"
export FAKE_REVISION="${SHA}"
export FAKE_SOURCE=https://github.com/mirkoSekulic/nvt-agent
export FAKE_VERSION=0.2.0-943d5ba

bash "${ROOT}/.github/scripts/release-images.sh" mirkoSekulic "${FAKE_VERSION}" "${SHA}" "${FAKE_SOURCE}"
[[ "$(grep -c '^docker build ' "${DOCKER_LOG}")" == "7" ]]
[[ "$(grep -c '^docker push ' "${DOCKER_LOG}")" == "7" ]]
if grep -q 'nvt-smoke-echo' "${DOCKER_LOG}"; then
  echo "fixture image entered the production release" >&2
  exit 1
fi

: >"${DOCKER_LOG}"
bash "${ROOT}/.github/scripts/release-images.sh" mirkoSekulic "${FAKE_VERSION}" "${SHA}" "${FAKE_SOURCE}"
if grep -Eq '^docker (build|push) ' "${DOCKER_LOG}"; then
  echo "exact partial-release artifacts were republished" >&2
  exit 1
fi

export FAKE_REVISION=1111111111111111111111111111111111111111
if bash "${ROOT}/.github/scripts/release-images.sh" mirkoSekulic "${FAKE_VERSION}" "${SHA}" "${FAKE_SOURCE}" >/dev/null 2>"${WORKDIR}/conflict.err"; then
  echo "conflicting existing image was accepted" >&2
  exit 1
fi
grep -q 'conflicting immutable image tag' "${WORKDIR}/conflict.err"

echo "coordinated release script test passed"
