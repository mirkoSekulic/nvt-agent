#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ "$#" != "4" ]]; then
  echo "usage: $0 <registry-owner> <release-tag> <revision> <source-url>" >&2
  exit 2
fi

owner="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
release_tag="$2"
revision="$(printf '%s' "$3" | tr '[:upper:]' '[:lower:]')"
source_url="$4"
if [[ ! "${owner}" =~ ^[a-z0-9][a-z0-9-]*$ ]] ||
   [[ ! "${release_tag}" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] ||
   [[ ! "${revision}" =~ ^[0-9a-f]{40}$ ]] ||
   [[ ! "${source_url}" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "invalid coordinated host-bundle metadata" >&2
  exit 2
fi
command -v oras >/dev/null || { echo "oras is required" >&2; exit 2; }

output="$(mktemp -d)"
anonymous="$(mktemp -d)"
trap 'rm -rf "${output}" "${anonymous}"' EXIT
printf '{"auths":{}}\n' >"${anonymous}/config.json"

NVT_HOST_BUNDLE_SOURCE_URL="${source_url}" \
  bash "${ROOT}/hostbundle/build.sh" "${release_tag}" "${revision}" "${output}"
expected="$(tr -d '\n' <"${output}/digest.txt")"
[[ "${expected}" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "built host-bundle digest is invalid" >&2; exit 2; }
reference="ghcr.io/${owner}/nvt-host-bundle:${release_tag}"

set +e
found="$(oras resolve "${reference}" 2>"${output}/resolve.err")"
status=$?
set -e
if [[ "${status}" == "0" ]]; then
  if [[ "${found}" != "${expected}" ]]; then
    echo "conflicting immutable host-bundle tag" >&2
    exit 2
  fi
  echo "Verified coordinated host bundle ${reference}@${expected}."
else
  if ! grep -Eqi 'not found|manifest unknown|404' "${output}/resolve.err"; then
    echo "could not determine immutable host-bundle state" >&2
    exit 2
  fi
  oras cp --from-oci-layout "${output}/oci:${release_tag}" "${reference}"
fi

found="$(oras resolve "${reference}")"
[[ "${found}" == "${expected}" ]] || { echo "published host-bundle digest does not match" >&2; exit 2; }

verified=0
for _ in $(seq 1 "${NVT_PUBLIC_VERIFY_ATTEMPTS:-10}"); do
  if ORAS_AUTH_FILE="${anonymous}/config.json" oras manifest fetch --registry-config "${anonymous}/config.json" "ghcr.io/${owner}/nvt-host-bundle@${expected}" >/dev/null 2>&1; then
    verified=1
    break
  fi
  sleep "${NVT_PUBLIC_VERIFY_DELAY_SECONDS:-2}"
done
[[ "${verified}" == "1" ]] || { echo "host bundle is not anonymously readable" >&2; exit 2; }

echo "Verified public coordinated host bundle ${reference}@${expected}."
