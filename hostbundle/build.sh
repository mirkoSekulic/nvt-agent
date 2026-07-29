#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERSION="${1:-}"
REVISION="${2:-}"
OUTPUT="${3:-${ROOT}/dist/host-bundle}"
ARCHITECTURE="${NVT_HOST_BUNDLE_ARCH:-amd64}"

clean_absolute_path() {
  local input="$1"
  local component count index
  local -a raw_components=()
  local -a clean_components=()
  [[ "${input}" == /* ]] || return 1
  [[ "${input}" != *$'\n'* && "${input}" != *$'\r'* ]] || return 1
  IFS='/' read -r -a raw_components <<<"${input#/}"
  for component in "${raw_components[@]}"; do
    case "${component}" in
      ""|.) continue ;;
      ..)
        count="${#clean_components[@]}"
        (( count > 0 )) || return 1
        unset "clean_components[$((count - 1))]"
        ;;
      *) clean_components+=("${component}") ;;
    esac
  done
  if (( ${#clean_components[@]} == 0 )); then
    printf '/\n'
    return
  fi
  printf '/%s' "${clean_components[0]}"
  for ((index = 1; index < ${#clean_components[@]}; index++)); do
    printf '/%s' "${clean_components[index]}"
  done
  printf '\n'
}

if [[ "${OUTPUT}" != /* ]]; then
  OUTPUT="${ROOT}/${OUTPUT}"
fi
if ! OUTPUT="$(clean_absolute_path "${OUTPUT}")"; then
  echo "host-bundle output path is unsafe" >&2
  exit 2
fi

if [[ ! "${VERSION}" =~ ^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$ ]] ||
   [[ ! "${REVISION}" =~ ^[0-9a-f]{40}$ ]] ||
   [[ ! "${ARCHITECTURE}" =~ ^(amd64|arm64)$ ]] ||
   [[ -z "${OUTPUT}" || "${OUTPUT}" == "/" ]]; then
  echo "usage: $0 <coordinated-version> <full-revision> [output-directory]" >&2
  exit 2
fi

if [[ -e "${OUTPUT}" || -L "${OUTPUT}" ]]; then
  if [[ -L "${OUTPUT}" ]] || [[ ! -d "${OUTPUT}" ]] || [[ -n "$(find "${OUTPUT}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
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
build_static ./cmd/nvt-guest-identityd "${OUTPUT}/bin/nvt-guest-identityd"
build_static ./cmd/nvt-guest-sessiond "${OUTPUT}/bin/nvt-guest-sessiond"
build_static ./cmd/nvt-guest-egressd "${OUTPUT}/bin/nvt-guest-egressd"
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
    --identity-daemon "${OUTPUT}/bin/nvt-guest-identityd" \
    --session-daemon "${OUTPUT}/bin/nvt-guest-sessiond" \
    --egress-daemon "${OUTPUT}/bin/nvt-guest-egressd" \
    --bootstrap "${OUTPUT}/bin/nvt-host-bootstrap" \
    --session-fixture "${OUTPUT}/bin/nvt-guest-session-fixture" \
    --agentd "${ROOT}/runtime/agentd/agentd.py" \
    --agentdctl "${ROOT}/runtime/agentd/agentdctl.py" \
    --service "${ROOT}/hostbundle/files/nvt-agent-guest.service" \
    --identity-service "${ROOT}/hostbundle/files/nvt-guest-identity.service" \
    --session-service "${ROOT}/hostbundle/files/nvt-guest-session.service" \
    --egress-service "${ROOT}/hostbundle/files/nvt-guest-egress.service" \
    --config "${ROOT}/hostbundle/files/guest.json" \
    --identity-config "${ROOT}/hostbundle/files/identity.json" \
    --session-config "${ROOT}/hostbundle/files/session.json" \
    --workspace-session-config "${ROOT}/hostbundle/files/session-workspace.json" \
    --egress-config "${ROOT}/hostbundle/files/native-egress.json" >"${OUTPUT}/digest.txt"
)

printf 'Built NVT host bundle %s for linux/%s at %s\n' "${VERSION}" "${ARCHITECTURE}" "${OUTPUT}"
