#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHART="${ROOT}/charts/nvt"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT
RENDER="${WORKDIR}/portal.yaml"
OAUTH_RENDER="${WORKDIR}/portal-oauth.yaml"

helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" >"${RENDER}"

for kind in ServiceAccount Role RoleBinding ConfigMap Deployment Service NetworkPolicy; do
  grep -A8 -F "kind: ${kind}" "${RENDER}" | grep -Fq 'name: nvt-credential-portal'
done
PORTAL_ROLE="${WORKDIR}/role.yaml"
awk 'candidate && /^---$/{if(wanted){printf "%s",doc; exit} candidate=0; wanted=0; doc=""} /^kind: Role$/{candidate=1; wanted=0; doc=$0 ORS; next} candidate{doc=doc $0 ORS} candidate && /^  name: nvt-credential-portal$/{wanted=1}' "${RENDER}" >"${PORTAL_ROLE}"
grep -Fq 'verbs: ["patch"]' "${PORTAL_ROLE}"
if grep -Eq 'verbs:.*(get|list|create|delete)' "${PORTAL_ROLE}"; then
  echo "credential portal RBAC grants a forbidden Secret verb" >&2
  exit 1
fi
grep -Fq 'resourceNames:' "${RENDER}"
grep -Fq -- '- "nvt-portal-seed"' "${RENDER}"
grep -Fq 'image: "ghcr.io/mirkosekulic/nvt-credential-portal:0.8.53"' "${RENDER}"
grep -Fq -- '--credential-portal-url=/agents/credentials' "${RENDER}"
grep -Fq 'readOnlyRootFilesystem: true' "${RENDER}"
grep -Fq 'automountServiceAccountToken: false' "${RENDER}"
grep -Fq 'enableServiceLinks: false' "${RENDER}"
grep -Fq 'medium: Memory' "${RENDER}"
grep -Fq 'mountPath: /tmp' "${RENDER}"
grep -Fq '"maxConcurrent": 2' "${RENDER}"
grep -Fq '"maxSessions": 64' "${RENDER}"
grep -Fq '"experimentalCodexDeviceAuth": true' "${RENDER}"
grep -Fq '"enabled": false' "${RENDER}"

python3 - "${RENDER}" <<'PY'
import sys

import yaml

documents = [document for document in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")) if document]
deployment = next(
    document
    for document in documents
    if document.get("kind") == "Deployment" and document["metadata"]["name"] == "nvt-credential-portal"
)
pod = deployment["spec"]["template"]["spec"]
containers = {container["name"]: container for container in pod["containers"]}
portal = containers["credential-portal"]
runner = containers["credential-runner"]

assert pod["automountServiceAccountToken"] is False
assert pod["enableServiceLinks"] is False
assert portal["securityContext"]["runAsUser"] != runner["securityContext"]["runAsUser"]
assert any(mount["name"] == "kube-api-access" for mount in portal["volumeMounts"])
assert not any(mount["name"] == "kube-api-access" for mount in runner["volumeMounts"])
assert any(argument == "runner" for argument in runner["args"])
assert not runner.get("env")
assert not runner.get("envFrom")

projected = next(volume for volume in pod["volumes"] if volume["name"] == "kube-api-access")
assert any("serviceAccountToken" in source for source in projected["projected"]["sources"])
assert not any(
    mount["name"] == "config" or mount["mountPath"] == "/etc/nvt-credential-portal"
    for mount in runner["volumeMounts"]
)
PY

helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set-string credentialPortal.auth.mode=oauth2 \
  --set-string credentialPortal.auth.oauth2.credentials.existingSecret=nvt-portal-oauth2 \
  --set-string credentialPortal.auth.oauth2.issuer=https://identity.example.test \
  --set-string credentialPortal.auth.oauth2.authorizationURL=https://identity.example.test/authorize \
  --set-string credentialPortal.auth.oauth2.tokenURL=https://identity.example.test/token \
  --set-string credentialPortal.auth.oauth2.identity.endpoint=https://api.identity.example.test/user \
  --set-string credentialPortal.auth.oauth2.identity.allowedHosts[0]=api.identity.example.test \
  --set-string credentialPortal.auth.oauth2.identity.subjectPath=id \
  >"${OAUTH_RENDER}"
grep -Fq 'name: NVT_CREDENTIAL_PORTAL_CLIENT_ID' "${OAUTH_RENDER}"
grep -Fq 'name: "nvt-portal-oauth2"' "${OAUTH_RENDER}"
grep -Fq '"mode": "oauth2"' "${OAUTH_RENDER}"

for forbidden in access-token refresh-token authorization-code credential-value; do
  if grep -Fq "${forbidden}" "${RENDER}"; then
    echo "rendered portal manifest contains forbidden credential material marker" >&2
    exit 1
  fi
done

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set-string credentialPortal.slots[0].secretName=other-secret >/dev/null 2>"${WORKDIR}/destination.txt"; then
  echo "expected mismatched portal seed destination to fail" >&2
  exit 1
fi
grep -Fq 'must identify a broker provider and target broker.persistence.seedSecretName' "${WORKDIR}/destination.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set-string credentialPortal.slots[0].adapter=auto-detect >/dev/null 2>"${WORKDIR}/adapter.txt"; then
  echo "expected inferred portal adapter to fail" >&2
  exit 1
fi
grep -Fq 'adapter is unsupported' "${WORKDIR}/adapter.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set-string credentialPortal.slots[1].dataKey=codex-auth.json >/dev/null 2>"${WORKDIR}/duplicate-destination.txt"; then
  echo "expected duplicate portal Secret destination to fail" >&2
  exit 1
fi
grep -Fq 'Secret destination is already assigned to another slot' "${WORKDIR}/duplicate-destination.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set credentialPortal.enrollment.maxConcurrent=9 >/dev/null 2>"${WORKDIR}/concurrency.txt"; then
  echo "expected unsafe portal concurrency to fail" >&2
  exit 1
fi
grep -Fq 'enrollment session limits are invalid' "${WORKDIR}/concurrency.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set credentialPortal.enrollment.timeoutSeconds=3601 >/dev/null 2>"${WORKDIR}/timeout.txt"; then
  echo "expected portal enrollment longer than its login session to fail" >&2
  exit 1
fi
grep -Fq 'enrollment timeout must be' "${WORKDIR}/timeout.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set credentialPortal.enrollment.experimentalCodexDeviceAuth=false >/dev/null 2>"${WORKDIR}/codex-device.txt"; then
  echo "expected an ungated experimental Codex device slot to fail" >&2
  exit 1
fi
grep -Fq 'requires enrollment.experimentalCodexDeviceAuth=true' "${WORKDIR}/codex-device.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set credentialPortal.enabled=false >"${WORKDIR}/disabled.yaml"; then :; fi
if grep -Fq 'nvt-credential-portal' "${WORKDIR}/disabled.yaml"; then
  echo "disabled portal rendered workload resources" >&2
  exit 1
fi
