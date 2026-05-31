#!/usr/bin/env bash
set -euo pipefail

SOURCE="${CODEX_AUTH_SOURCE:-${SOURCE:-${HOME}/.codex}}"
NAMESPACE="${NAMESPACE:-nvt}"
SECRET="${CODEX_AUTH_SECRET:-${SECRET:-codex-auth}}"
CLUSTER="${CLUSTER:-nvt-smoke}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-kind-${CLUSTER}}"
KUBECTL="${KUBECTL:-kubectl}"
REQUIRED_FILES=(auth.json config.toml installation_id)
FILTER_TMPDIR=""
FILTER_TMPDIR_CREATED=0

cleanup() {
  if [[ "${FILTER_TMPDIR_CREATED}" == "1" && -n "${FILTER_TMPDIR}" ]]; then
    rm -rf "${FILTER_TMPDIR}"
  fi
}
trap cleanup EXIT

if [[ ! -d "${SOURCE}" ]]; then
  printf '[operator-codex-auth-secret] ERROR: CODEX_AUTH_SOURCE/SOURCE must be an existing directory: %s\n' "${SOURCE}" >&2
  exit 1
fi

FILTER_TMPDIR="$(mktemp -d)"
FILTER_TMPDIR_CREATED=1

for file in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "${SOURCE}/${file}" ]]; then
    printf '[operator-codex-auth-secret] ERROR: required Codex auth file is missing: %s/%s\n' "${SOURCE}" "${file}" >&2
    exit 1
  fi
  cp -p "${SOURCE}/${file}" "${FILTER_TMPDIR}/${file}"
done

printf '[operator-codex-auth-secret] applying Secret %s/%s from filtered Codex auth files in %s on context %s\n' \
  "${NAMESPACE}" "${SECRET}" "${SOURCE}" "${KUBECTL_CONTEXT}"

"${KUBECTL}" --context "${KUBECTL_CONTEXT}" \
  create secret generic "${SECRET}" \
  --from-file="${FILTER_TMPDIR}" \
  --dry-run=client \
  -o yaml |
  "${KUBECTL}" --context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" apply -f -
