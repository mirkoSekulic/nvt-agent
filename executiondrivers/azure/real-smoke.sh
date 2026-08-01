#!/usr/bin/env bash
set -euo pipefail

: "${NVT_AZURE_SMOKE_MANIFEST:?set the path to a non-secret AgentRun manifest}"
: "${NVT_AZURE_SMOKE_NAMESPACE:?set the prepared NVT namespace}"
: "${NVT_AZURE_SMOKE_AGENTRUN:?set the AgentRun name in that manifest}"

if grep -Eiq 'nvt_(eg1|ri1|rc1)_|client[_-]?secret|private[_-]?key|enrollment[_-]?token' "${NVT_AZURE_SMOKE_MANIFEST}"; then
  echo "refusing a smoke manifest that appears to contain secret material" >&2
  exit 1
fi

cleanup() {
  kubectl -n "${NVT_AZURE_SMOKE_NAMESPACE}" delete -f "${NVT_AZURE_SMOKE_MANIFEST}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

kubectl -n "${NVT_AZURE_SMOKE_NAMESPACE}" apply -f "${NVT_AZURE_SMOKE_MANIFEST}"
kubectl -n "${NVT_AZURE_SMOKE_NAMESPACE}" wait --for=jsonpath='{.status.phase}'=Running \
  "agentrun/${NVT_AZURE_SMOKE_AGENTRUN}" --timeout=20m
if kubectl -n "${NVT_AZURE_SMOKE_NAMESPACE}" get "agentrun/${NVT_AZURE_SMOKE_AGENTRUN}" -o json \
  | grep -Eq 'nvt_(eg1|ri1|rc1)_'; then
  echo "AgentRun status contains credential material" >&2
  exit 1
fi
kubectl -n "${NVT_AZURE_SMOKE_NAMESPACE}" delete -f "${NVT_AZURE_SMOKE_MANIFEST}" --wait=false
kubectl -n "${NVT_AZURE_SMOKE_NAMESPACE}" wait --for=delete \
  "agentrun/${NVT_AZURE_SMOKE_AGENTRUN}" --timeout=20m
trap - EXIT
