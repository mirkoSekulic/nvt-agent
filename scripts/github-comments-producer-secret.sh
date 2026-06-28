#!/usr/bin/env bash
set -euo pipefail

GITHUB_APP_PRIVATE_KEY_FILE="${GITHUB_APP_PRIVATE_KEY_FILE:-}"
NAMESPACE="${NAMESPACE:-nvt}"
PRODUCER_GITHUB_APP_SECRET="${PRODUCER_GITHUB_APP_SECRET:-nvt-github-app}"
PRODUCER_GITHUB_APP_KEY="${PRODUCER_GITHUB_APP_KEY:-private-key.pem}"
CLUSTER="${CLUSTER:-nvt-smoke}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-kind-${CLUSTER}}"
KUBECTL="${KUBECTL:-kubectl}"

if [[ -z "${GITHUB_APP_PRIVATE_KEY_FILE}" ]]; then
  printf '[github-comments-producer-secret] ERROR: GITHUB_APP_PRIVATE_KEY_FILE is required\n' >&2
  printf 'usage: make github-comments-producer-secret GITHUB_APP_PRIVATE_KEY_FILE=/path/to/private-key.pem [NAMESPACE=nvt] [CLUSTER=nvt-smoke]\n' >&2
  exit 1
fi

if [[ ! -f "${GITHUB_APP_PRIVATE_KEY_FILE}" ]]; then
  printf '[github-comments-producer-secret] ERROR: GITHUB_APP_PRIVATE_KEY_FILE must be an existing regular file: %s\n' "${GITHUB_APP_PRIVATE_KEY_FILE}" >&2
  exit 1
fi

printf '[github-comments-producer-secret] applying Secret %s/%s key %s from %s on context %s\n' \
  "${NAMESPACE}" "${PRODUCER_GITHUB_APP_SECRET}" "${PRODUCER_GITHUB_APP_KEY}" "${GITHUB_APP_PRIVATE_KEY_FILE}" "${KUBECTL_CONTEXT}"

"${KUBECTL}" --context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" \
  create secret generic "${PRODUCER_GITHUB_APP_SECRET}" \
  --from-file="${PRODUCER_GITHUB_APP_KEY}=${GITHUB_APP_PRIVATE_KEY_FILE}" \
  --dry-run=client \
  -o yaml |
  "${KUBECTL}" --context "${KUBECTL_CONTEXT}" apply -f -
