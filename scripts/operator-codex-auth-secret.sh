#!/usr/bin/env bash
set -euo pipefail

SOURCE="${SOURCE:-${HOME}/.codex}"
NAMESPACE="${NAMESPACE:-nvt}"
SECRET="${SECRET:-codex-auth}"
CLUSTER="${CLUSTER:-nvt-smoke}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-kind-${CLUSTER}}"

if [[ ! -d "${SOURCE}" ]]; then
  printf '[operator-codex-auth-secret] ERROR: SOURCE must be an existing directory: %s\n' "${SOURCE}" >&2
  exit 1
fi

printf '[operator-codex-auth-secret] applying Secret %s/%s from %s on context %s\n' \
  "${NAMESPACE}" "${SECRET}" "${SOURCE}" "${KUBECTL_CONTEXT}"

kubectl --context "${KUBECTL_CONTEXT}" \
  create secret generic "${SECRET}" \
  --from-file="${SOURCE}" \
  --dry-run=client \
  -o yaml |
  kubectl --context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" apply -f -
