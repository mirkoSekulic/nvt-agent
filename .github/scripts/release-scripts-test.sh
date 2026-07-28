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
    if [[ "${REQUIRE_ANONYMOUS:-0}" == "1" ]]; then
      [[ -n "${DOCKER_CONFIG:-}" && "${DOCKER_CONFIG}" != "${AUTHENTICATED_DOCKER_CONFIG}" ]]
      grep -qx '{"auths":{}}' "${DOCKER_CONFIG}/config.json"
    fi
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
  "build --label")
    ref=""
    previous=""
    for argument in "$@"; do
      if [[ "${previous}" == "--tag" ]]; then
        ref="${argument}"
        break
      fi
      previous="${argument}"
    done
    [[ -n "${ref}" ]]
    if [[ -n "${FAIL_BUILD_MATCH:-}" && "${ref}" == *"${FAIL_BUILD_MATCH}"* ]]; then
      echo "injected image build failure" >&2
      exit 1
    fi
    if [[ "${REQUIRE_PARALLEL:-0}" == "1" ]]; then
      marker="${PARALLEL_DIR}/${ref//[\/:]/_}"
      : >"${marker}"
      for _ in $(seq 1 100); do
        active="$(find "${PARALLEL_DIR}" -type f ! -name witnessed | wc -l | tr -d ' ')"
        if [[ "${active}" -ge "${EXPECTED_PARALLEL}" ]]; then
          : >"${PARALLEL_DIR}/witnessed"
        fi
        [[ -f "${PARALLEL_DIR}/witnessed" ]] && break
        sleep 0.01
      done
      [[ -f "${PARALLEL_DIR}/witnessed" ]]
      rm -f "${marker}"
    fi
    ;;
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
export PARALLEL_DIR="${WORKDIR}/parallel"
export EXPECTED_PARALLEL=4
export REQUIRE_PARALLEL=1
mkdir -p "${PARALLEL_DIR}"

bash "${ROOT}/.github/scripts/release-images.sh" mirkoSekulic "${FAKE_VERSION}" "${SHA}" "${FAKE_SOURCE}"
[[ -f "${PARALLEL_DIR}/witnessed" ]]
[[ "$(grep -c '^docker build ' "${DOCKER_LOG}")" == "9" ]]
[[ "$(grep -c '^docker push ' "${DOCKER_LOG}")" == "9" ]]
if grep -q 'nvt-qemu-execution-driver' "${DOCKER_LOG}"; then
  echo "test-only QEMU reference driver entered the production release" >&2
  exit 1
fi
if grep -q 'nvt-smoke-echo' "${DOCKER_LOG}"; then
  echo "fixture image entered the production release" >&2
  exit 1
fi
unset REQUIRE_PARALLEL

: >"${DOCKER_LOG}"
bash "${ROOT}/.github/scripts/release-images.sh" mirkoSekulic "${FAKE_VERSION}" "${SHA}" "${FAKE_SOURCE}"
if grep -Eq '^docker (build|push) ' "${DOCKER_LOG}"; then
  echo "metadata-matching partial-release artifacts were republished" >&2
  exit 1
fi

# A failed worker fails the release only after its peer workers are reaped.
# Their successful pushes form a safe partial publication; a rerun verifies
# and skips those exact tags, then publishes only the missing images.
export FAKE_VERSION=0.2.1-943d5ba
export FAIL_BUILD_MATCH=nvt-egressd
: >"${DOCKER_LOG}"
if bash "${ROOT}/.github/scripts/release-images.sh" mirkoSekulic "${FAKE_VERSION}" "${SHA}" "${FAKE_SOURCE}" >"${WORKDIR}/worker.out" 2>"${WORKDIR}/worker.err"; then
  echo "parallel image worker failure was accepted" >&2
  exit 1
fi
grep -q 'coordinated image worker failed' "${WORKDIR}/worker.err"
[[ "$(grep -c '^docker push ' "${DOCKER_LOG}")" == "3" ]]

unset FAIL_BUILD_MATCH
: >"${DOCKER_LOG}"
bash "${ROOT}/.github/scripts/release-images.sh" mirkoSekulic "${FAKE_VERSION}" "${SHA}" "${FAKE_SOURCE}"
[[ "$(grep -c '^docker build ' "${DOCKER_LOG}")" == "6" ]]
[[ "$(grep -c '^docker push ' "${DOCKER_LOG}")" == "6" ]]
: >"${DOCKER_LOG}"
bash "${ROOT}/.github/scripts/release-images.sh" mirkoSekulic "${FAKE_VERSION}" "${SHA}" "${FAKE_SOURCE}"
if grep -Eq '^docker (build|push) ' "${DOCKER_LOG}"; then
  echo "recovered partial-release artifacts were republished" >&2
  exit 1
fi

if NVT_RELEASE_IMAGE_PARALLELISM=0 bash "${ROOT}/.github/scripts/release-images.sh" mirkoSekulic "${FAKE_VERSION}" "${SHA}" "${FAKE_SOURCE}" >/dev/null 2>&1; then
  echo "invalid release image parallelism was accepted" >&2
  exit 1
fi
if NVT_RELEASE_IMAGE_FILTER=nvt-qemu-execution-driver \
  bash "${ROOT}/.github/scripts/release-images.sh" mirkoSekulic "${FAKE_VERSION}" "${SHA}" "${FAKE_SOURCE}" \
  >/dev/null 2>"${WORKDIR}/qemu-filter.err"; then
  echo "test-only QEMU reference driver was accepted as a release image" >&2
  exit 1
fi
grep -q 'unknown coordinated release image' "${WORKDIR}/qemu-filter.err"

export FAKE_VERSION=0.2.0-943d5ba

# Existing package writers are trusted. Matching OCI source/revision/version
# metadata is the recovery boundary; copied labels do not prove byte identity.
# The fake registry deliberately exposes no content digest, and reuse succeeds.
export FAKE_UNOBSERVED_CONTENT=changed-by-trusted-writer

mkdir -p "${WORKDIR}/authenticated-docker"
printf '{"auths":{"ghcr.io":{"auth":"not-a-real-credential"}}}\n' >"${WORKDIR}/authenticated-docker/config.json"
export DOCKER_CONFIG="${WORKDIR}/authenticated-docker"
export AUTHENTICATED_DOCKER_CONFIG="${DOCKER_CONFIG}"
export REQUIRE_ANONYMOUS=1
: >"${DOCKER_LOG}"
NVT_PUBLIC_VERIFY_ATTEMPTS=1 NVT_PUBLIC_VERIFY_DELAY_SECONDS=0 \
  bash "${ROOT}/.github/scripts/verify-public-images.sh" mirkoSekulic "${FAKE_VERSION}"
[[ "$(grep -c '^docker manifest inspect ' "${DOCKER_LOG}")" == "9" ]]
if grep -q 'nvt-qemu-execution-driver' "${DOCKER_LOG}"; then
  echo "test-only QEMU reference driver entered public release verification" >&2
  exit 1
fi

rm -f "${MANIFEST_DIR}/ghcr.io_mirkosekulic_nvt-agent-runtime:${FAKE_VERSION}"
if NVT_PUBLIC_VERIFY_ATTEMPTS=1 NVT_PUBLIC_VERIFY_DELAY_SECONDS=0 \
  bash "${ROOT}/.github/scripts/verify-public-images.sh" mirkoSekulic "${FAKE_VERSION}" >/dev/null 2>"${WORKDIR}/public.err"; then
  echo "missing anonymous image was accepted" >&2
  exit 1
fi
grep -q 'image is not anonymously readable' "${WORKDIR}/public.err"
unset REQUIRE_ANONYMOUS DOCKER_CONFIG

export FAKE_VERSION=0.2.2-943d5ba
: >"${DOCKER_LOG}"
NVT_RELEASE_IMAGE_FILTER=nvt-dind bash "${ROOT}/.github/scripts/release-images.sh" mirkoSekulic "${FAKE_VERSION}" "${SHA}" "${FAKE_SOURCE}"
[[ "$(grep -c '^docker build ' "${DOCKER_LOG}")" == "1" ]]
[[ "$(grep -c '^docker push ' "${DOCKER_LOG}")" == "1" ]]
grep -q 'ghcr.io/mirkosekulic/nvt-dind:' "${DOCKER_LOG}"

export FAKE_REVISION=1111111111111111111111111111111111111111
if bash "${ROOT}/.github/scripts/release-images.sh" mirkoSekulic "${FAKE_VERSION}" "${SHA}" "${FAKE_SOURCE}" >/dev/null 2>"${WORKDIR}/conflict.err"; then
  echo "conflicting existing image was accepted" >&2
  exit 1
fi
grep -q 'conflicting immutable image tag' "${WORKDIR}/conflict.err"

workflow="${ROOT}/.github/workflows/charts.yml"
grep -Fq 'group: nvt-coordinated-release-${{ needs.release_metadata.outputs.version }}-${{ matrix.image }}' "${workflow}"
grep -A10 '^  publish_image:' "${workflow}" | grep -q 'max-parallel: 8'
grep -A30 '^  publish_image:' "${workflow}" | grep -q 'nvt-github-comments-producer'
grep -A30 '^  publish_image:' "${workflow}" | grep -q 'nvt-execution-driver-host'
if grep -A35 '^  publish_image:' "${workflow}" | grep -q 'nvt-qemu-execution-driver'; then
  echo "test-only QEMU reference driver entered the coordinated release matrix" >&2
  exit 1
fi
grep -A6 '^  publish:' "${workflow}" | grep -q 'publish_image'
grep -A6 '^  publish:' "${workflow}" | grep -q 'publish_host_bundle'
grep -q '^  publish_host_bundle:' "${workflow}"
grep -q 'oras-project/setup-oras@1d808f7d7f6995cc68b7bf507bfe5c5446e1dc9d' "${workflow}"
grep -q 'NVT_RELEASE_IMAGE_FILTER: ${{ matrix.image }}' "${workflow}"
anonymous_line="$(grep -n 'name: Verify anonymous image pullability' "${workflow}" | cut -d: -f1)"
chart_line="$(grep -n 'name: Publish the chart last' "${workflow}" | cut -d: -f1)"
[[ "${anonymous_line}" -lt "${chart_line}" ]]

cat >"${WORKDIR}/bin/oras" <<'ORAS'
#!/usr/bin/env bash
set -euo pipefail
printf 'oras %s\n' "$*" >>"${ORAS_LOG}"
state_key() { printf '%s' "$1" | tr '/:@' '____'; }
case "$1 $2" in
  "resolve "*)
    reference="$2"
    state="${ORAS_STATE}/$(state_key "${reference}")"
    if [[ ! -f "${state}" ]]; then
      echo "manifest unknown" >&2
      exit 1
    fi
    cat "${state}"
    ;;
  "cp --from-oci-layout")
    source="$3"
    destination="$4"
    layout="${source%:*}"
    digest="$(jq -r '.manifests[0].digest' "${layout}/index.json")"
    printf '%s\n' "${digest}" >"${ORAS_STATE}/$(state_key "${destination}")"
    ;;
  "manifest fetch")
    config=""
    reference="${@: -1}"
    previous=""
    for argument in "$@"; do
      if [[ "${previous}" == "--registry-config" ]]; then config="${argument}"; fi
      previous="${argument}"
    done
    grep -qx '{"auths":{}}' "${config}"
    tag_reference="${reference%@*}:${FAKE_HOST_BUNDLE_VERSION}"
    state="${ORAS_STATE}/$(state_key "${tag_reference}")"
    [[ -f "${state}" ]]
    [[ "$(cat "${state}")" == "${reference##*@}" ]]
    printf '{}\n'
    ;;
  "pull --registry-config")
    config="$3"
    platform=""
    output=""
    reference="${@: -1}"
    previous=""
    for argument in "$@"; do
      if [[ "${previous}" == "--platform" ]]; then platform="${argument}"; fi
      if [[ "${previous}" == "--output" ]]; then output="${argument}"; fi
      previous="${argument}"
    done
    grep -qx '{"auths":{}}' "${config}"
    [[ "${platform}" == "linux/amd64" ]]
    tag_reference="${reference%@*}:${FAKE_HOST_BUNDLE_VERSION}"
    state="${ORAS_STATE}/$(state_key "${tag_reference}")"
    [[ -f "${state}" ]]
    [[ "$(cat "${state}")" == "${reference##*@}" ]]
    [[ "${FAIL_ORAS_PULL:-0}" != "1" ]]
    mkdir -p "${output}"
    printf 'verified layer\n' >"${output}/nvt-host-bundle.tar.gz"
    ;;
  *)
    echo "unexpected oras invocation: $*" >&2
    exit 1
    ;;
esac
ORAS
chmod +x "${WORKDIR}/bin/oras"
export ORAS_LOG="${WORKDIR}/oras.log"
export ORAS_STATE="${WORKDIR}/oras-state"
export FAKE_HOST_BUNDLE_VERSION="0.2.3-943d5ba"
mkdir -p "${ORAS_STATE}"
: >"${ORAS_LOG}"
export FAIL_ORAS_PULL=1
if NVT_PUBLIC_VERIFY_ATTEMPTS=1 NVT_PUBLIC_VERIFY_DELAY_SECONDS=0 \
  bash "${ROOT}/.github/scripts/release-host-bundle.sh" \
    mirkoSekulic "${FAKE_HOST_BUNDLE_VERSION}" "${SHA}" "${FAKE_SOURCE}" >/dev/null 2>"${WORKDIR}/host-bundle-public.err"; then
  echo "missing anonymous host-bundle platform content was accepted" >&2
  exit 1
fi
grep -q 'platform content is not anonymously readable' "${WORKDIR}/host-bundle-public.err"
unset FAIL_ORAS_PULL
[[ "$(grep -c '^oras cp ' "${ORAS_LOG}")" == "1" ]]
grep -q '^oras manifest fetch ' "${ORAS_LOG}"
grep -q '^oras pull .*--platform linux/amd64 ' "${ORAS_LOG}"

: >"${ORAS_LOG}"
bash "${ROOT}/.github/scripts/release-host-bundle.sh" \
  mirkoSekulic "${FAKE_HOST_BUNDLE_VERSION}" "${SHA}" "${FAKE_SOURCE}"
if grep -q '^oras cp ' "${ORAS_LOG}"; then
  echo "matching host-bundle artifact was republished after public retry" >&2
  exit 1
fi
grep -q '^oras manifest fetch ' "${ORAS_LOG}"
grep -q '^oras pull .*--platform linux/amd64 ' "${ORAS_LOG}"

: >"${ORAS_LOG}"
bash "${ROOT}/.github/scripts/release-host-bundle.sh" \
  mirkoSekulic "${FAKE_HOST_BUNDLE_VERSION}" "${SHA}" "${FAKE_SOURCE}"
if grep -q '^oras cp ' "${ORAS_LOG}"; then
  echo "matching host-bundle artifact was republished" >&2
  exit 1
fi
grep -q '^oras pull .*--platform linux/amd64 ' "${ORAS_LOG}"

reference="ghcr.io/mirkosekulic/nvt-host-bundle:${FAKE_HOST_BUNDLE_VERSION}"
printf 'sha256:%064d\n' 0 >"${ORAS_STATE}/$(printf '%s' "${reference}" | tr '/:@' '____')"
if bash "${ROOT}/.github/scripts/release-host-bundle.sh" \
  mirkoSekulic "${FAKE_HOST_BUNDLE_VERSION}" "${SHA}" "${FAKE_SOURCE}" >/dev/null 2>"${WORKDIR}/host-bundle-conflict.err"; then
  echo "conflicting immutable host-bundle artifact was accepted" >&2
  exit 1
fi
grep -q 'conflicting immutable host-bundle tag' "${WORKDIR}/host-bundle-conflict.err"

echo "coordinated release script test passed"
