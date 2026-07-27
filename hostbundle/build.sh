#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-}"
REVISION="${2:-}"
OUTPUT="${3:-${ROOT}/dist/host-bundle}"
ARCHITECTURE="${NVT_HOST_BUNDLE_ARCH:-amd64}"
if [[ "${OUTPUT}" != /* ]]; then
  OUTPUT="${ROOT}/${OUTPUT}"
fi

if [[ ! "${VERSION}" =~ ^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$ ]] ||
   [[ ! "${REVISION}" =~ ^[0-9a-f]{40}$ ]] ||
   [[ ! "${ARCHITECTURE}" =~ ^(amd64|arm64)$ ]] ||
   [[ -z "${OUTPUT}" || "${OUTPUT}" == "/" ]]; then
  echo "usage: $0 <coordinated-version> <full-revision> [output-directory]" >&2
  exit 2
fi

if [[ -e "${OUTPUT}" ]]; then
  if [[ ! -d "${OUTPUT}" ]] || [[ -n "$(find "${OUTPUT}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "host-bundle output directory must be empty" >&2
    exit 2
  fi
fi
mkdir -p "${OUTPUT}/bin"

build_static() {
  local package="$1"
  local destination="$2"
  (
    cd "${ROOT}/hostbundle"
    CGO_ENABLED=0 GOOS=linux GOARCH="${ARCHITECTURE}" \
      go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
      -o "${destination}" "${package}"
  )
}

build_static ./cmd/nvt-host-bootstrap "${OUTPUT}/bin/nvt-host-bootstrap"
build_static ./cmd/nvt-guest-supervisor "${OUTPUT}/bin/nvt-guest-supervisor"
build_static ./cmd/nvt-guest-session-fixture "${OUTPUT}/bin/nvt-guest-session-fixture"

(
  cd "${ROOT}/hostbundle"
  go run ./cmd/nvt-host-bundle-builder \
    --version "${VERSION}" \
    --build-id "${REVISION}" \
    --arch "${ARCHITECTURE}" \
    --archive "${OUTPUT}/nvt-host-bundle-linux-${ARCHITECTURE}.tar.gz" \
    --layout "${OUTPUT}/oci" \
    --tag "${VERSION}" \
    --source "${NVT_HOST_BUNDLE_SOURCE_URL:-https://github.com/mirkoSekulic/nvt-agent}" \
    --supervisor "${OUTPUT}/bin/nvt-guest-supervisor" \
    --bootstrap "${OUTPUT}/bin/nvt-host-bootstrap" \
    --session-fixture "${OUTPUT}/bin/nvt-guest-session-fixture" \
    --agentd "${ROOT}/runtime/agentd/agentd.py" \
    --agentdctl "${ROOT}/runtime/agentd/agentdctl.py" \
    --service "${ROOT}/hostbundle/files/nvt-agent-guest.service" \
    --config "${ROOT}/hostbundle/files/guest.json" >"${OUTPUT}/digest.txt"
)

printf 'Built NVT host bundle %s for linux/%s at %s\n' "${VERSION}" "${ARCHITECTURE}" "${OUTPUT}"
