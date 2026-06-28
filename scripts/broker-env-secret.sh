#!/usr/bin/env bash
set -euo pipefail

BROKER_ENV_FILE="${BROKER_ENV_FILE-.broker/env}"
BROKER_ENV_SECRET="${BROKER_ENV_SECRET:-nvt-broker-env}"
NAMESPACE="${NAMESPACE:-nvt}"
CLUSTER="${CLUSTER:-nvt-smoke}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-kind-${CLUSTER}}"
KUBECTL="${KUBECTL:-kubectl}"

if [[ -z "${BROKER_ENV_FILE}" ]]; then
  printf '[broker-env-secret] ERROR: BROKER_ENV_FILE is required\n' >&2
  printf 'usage: make broker-env-secret BROKER_ENV_FILE=.broker/env [NAMESPACE=nvt] [CLUSTER=nvt-smoke]\n' >&2
  exit 1
fi

if [[ ! -f "${BROKER_ENV_FILE}" ]]; then
  printf '[broker-env-secret] ERROR: BROKER_ENV_FILE must be an existing regular file: %s\n' "${BROKER_ENV_FILE}" >&2
  exit 1
fi

printf '[broker-env-secret] applying Secret %s/%s from env file %s on context %s\n' \
  "${NAMESPACE}" "${BROKER_ENV_SECRET}" "${BROKER_ENV_FILE}" "${KUBECTL_CONTEXT}"

"${KUBECTL}" --context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" \
  create secret generic "${BROKER_ENV_SECRET}" \
  --from-env-file="${BROKER_ENV_FILE}" \
  --dry-run=client \
  -o yaml |
  "${KUBECTL}" --context "${KUBECTL_CONTEXT}" apply -f -
