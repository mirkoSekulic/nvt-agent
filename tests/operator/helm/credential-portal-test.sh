#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHART="${ROOT}/charts/nvt"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT
RENDER="${WORKDIR}/portal.yaml"
OAUTH_RENDER="${WORKDIR}/portal-oauth.yaml"
DYNAMIC_RENDER="${WORKDIR}/portal-dynamic.yaml"
DYNAMIC_ROTATED_RENDER="${WORKDIR}/portal-dynamic-rotated.yaml"

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
grep -Fq 'image: "ghcr.io/mirkosekulic/nvt-credential-portal:0.8.65"' "${RENDER}"
grep -Fq -- '--credential-portal-url=/agents/credentials' "${RENDER}"
grep -Fq 'readOnlyRootFilesystem: true' "${RENDER}"
grep -Fq 'automountServiceAccountToken: false' "${RENDER}"
grep -Fq 'enableServiceLinks: false' "${RENDER}"
grep -Fq 'readinessProbe: {httpGet: {path: /readyz, port: http}}' "${RENDER}"
grep -Fq 'medium: Memory' "${RENDER}"
grep -Fq 'mountPath: /tmp' "${RENDER}"
grep -Fq '"maxConcurrent": 2' "${RENDER}"
grep -Fq '"maxSessions": 64' "${RENDER}"
grep -Fq '"experimentalCodexDeviceAuth": true' "${RENDER}"
grep -Fq '"enabled": false' "${RENDER}"
grep -Fq '"array": "memberships[]"' "${RENDER}"
grep -Fq '"valuePath": "$"' "${RENDER}"
grep -Fq '"maxPages": 5' "${RENDER}"
grep -Fq '"mode": "link"' "${RENDER}"
grep -Fq '"timeoutSeconds": 5' "${RENDER}"
grep -Fq '"eligibilityClaimSource": "access_token"' "${RENDER}"
grep -Fq '"accessTokenAudience": "nvt-eligibility-api"' "${RENDER}"

python3 - "${RENDER}" <<'PY'
import json
import sys

import yaml

documents = [document for document in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")) if document]
config_map = next(
    document
    for document in documents
    if document.get("kind") == "ConfigMap" and document["metadata"]["name"] == "nvt-credential-portal"
)
config = json.loads(config_map["data"]["config.json"])
assert "dynamic" not in config
deployment = next(
    document
    for document in documents
    if document.get("kind") == "Deployment" and document["metadata"]["name"] == "nvt-credential-portal"
)
broker_deployment = next(
    document
    for document in documents
    if document.get("kind") == "Deployment" and document["metadata"]["name"] == "nvt-broker"
)
rotation_annotation = "nvt.io/dynamic-account-assertion-rotation-epoch"
assert rotation_annotation not in deployment["spec"]["template"]["metadata"]["annotations"]
assert rotation_annotation not in broker_deployment["spec"]["template"]["metadata"]["annotations"]
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

helm template nvt "${CHART}" -n nvt \
  -f "${ROOT}/tests/operator/helm/credential-portal-dynamic-values.yaml" >"${DYNAMIC_RENDER}"

python3 - "${DYNAMIC_RENDER}" <<'PY'
import json
import sys

import yaml

documents = [document for document in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")) if document]
portal_documents = [
    document for document in documents
    if document.get("metadata", {}).get("name") == "nvt-credential-portal"
]
kinds = {document["kind"] for document in portal_documents}
assert {"ServiceAccount", "ConfigMap", "Deployment", "Service", "NetworkPolicy"} <= kinds
assert "Role" not in kinds
assert "RoleBinding" not in kinds

config_map = next(document for document in portal_documents if document["kind"] == "ConfigMap")
config = json.loads(config_map["data"]["config.json"])
assert config["dynamic"]["enabled"] is True
assert config["dynamic"]["broker"] == {
    "assertionKeyFile": "/var/run/nvt-broker/auth/assertion-key",
    "assertionTTLSeconds": 60,
    "caFile": "/var/run/nvt-broker/ca/ca.crt",
    "eligibilityLeaseSeconds": 3600,
    "maxResponseBytes": 65536,
    "requestTimeoutSeconds": 10,
    "url": "https://nvt-broker:7347",
}
assert config["dynamic"]["templateSwitch"] == {
    "coordinatorURL": "http://nvt-operator:8082",
    "enabled": True,
    "maxResponseBytes": 4096,
    "requestTimeoutSeconds": 10,
}
assert config["dynamic"]["templates"] == [
    {"adapter": "codex-oauth-file", "label": "Approved one", "name": "approved-one"},
    {"adapter": "claude-oauth-file", "label": "Approved two", "name": "approved-two"},
]
assert config.get("slots") is None

deployment = next(document for document in portal_documents if document["kind"] == "Deployment")
broker_deployment = next(
    document for document in documents
    if document.get("kind") == "Deployment" and document["metadata"]["name"] == "nvt-broker"
)
operator_deployment = next(
    document for document in documents
    if document.get("kind") == "Deployment" and document["metadata"]["name"] == "nvt-operator"
)
pod = deployment["spec"]["template"]["spec"]
containers = {container["name"]: container for container in pod["containers"]}
portal = containers["credential-portal"]
runner = containers["credential-runner"]
portal_mounts = {mount["name"] for mount in portal["volumeMounts"]}
runner_mounts = {mount["name"] for mount in runner["volumeMounts"]}
volume_names = {volume["name"] for volume in pod["volumes"]}

assert pod["automountServiceAccountToken"] is False
assert "kube-api-access" not in volume_names
assert {"broker-ca", "broker-assertion-auth"} <= portal_mounts
assert not ({"config", "broker-ca", "broker-assertion-auth", "kube-api-access"} & runner_mounts)
assert not runner.get("env")
assert not runner.get("envFrom")
assert all(
    env.get("name") not in {"NVT_DYNAMIC_ACCOUNT_ASSERTION_KEY", "NVT_BROKER_CA"}
    for env in portal.get("env", [])
)
assert not any("serviceAccountToken" in source for volume in pod["volumes"] for source in volume.get("projected", {}).get("sources", []))
portal_epoch = deployment["spec"]["template"]["metadata"]["annotations"][
    "nvt.io/dynamic-account-assertion-rotation-epoch"
]
broker_epoch = broker_deployment["spec"]["template"]["metadata"]["annotations"][
    "nvt.io/dynamic-account-assertion-rotation-epoch"
]
assert portal_epoch == broker_epoch == "epoch-1"
assert operator_deployment["spec"]["template"]["metadata"]["annotations"][
    "nvt.io/dynamic-account-assertion-rotation-epoch"
] == "epoch-1"
operator_pod = operator_deployment["spec"]["template"]["spec"]
operator_volume = next(volume for volume in operator_pod["volumes"] if volume["name"] == "principal-account-client")
operator_items = [
    item["path"]
    for source in operator_volume["projected"]["sources"]
    for item in source.get("secret", {}).get("items", [])
]
assert "coordination-key" in operator_items
assert "coordination-key" not in str(pod)

serialized = open(sys.argv[1], encoding="utf-8").read()
for needle in (
    "DYNAMIC-PORTAL-CREDENTIAL-NEEDLE",
    "refresh-token-needle",
    "credential_base64",
    "provider_instance_id",
):
    assert needle not in serialized
PY

helm template nvt "${CHART}" -n nvt \
  -f "${ROOT}/tests/operator/helm/credential-portal-dynamic-values.yaml" \
  --set-string broker.dynamicAccountAssertionRotationEpoch=epoch-2 >"${DYNAMIC_ROTATED_RENDER}"
python3 - "${DYNAMIC_RENDER}" "${DYNAMIC_ROTATED_RENDER}" <<'PY'
import sys

import yaml

annotation = "nvt.io/dynamic-account-assertion-rotation-epoch"

def epochs(path):
    documents = [document for document in yaml.safe_load_all(open(path, encoding="utf-8")) if document]
    deployments = {
        document["metadata"]["name"]: document
        for document in documents
        if document.get("kind") == "Deployment"
        and document.get("metadata", {}).get("name") in {"nvt-broker", "nvt-credential-portal", "nvt-operator"}
    }
    return {
        name: deployment["spec"]["template"]["metadata"]["annotations"][annotation]
        for name, deployment in deployments.items()
    }

before = epochs(sys.argv[1])
after = epochs(sys.argv[2])
assert before == {"nvt-broker": "epoch-1", "nvt-credential-portal": "epoch-1", "nvt-operator": "epoch-1"}
assert after == {"nvt-broker": "epoch-2", "nvt-credential-portal": "epoch-2", "nvt-operator": "epoch-2"}
assert all(after[name] != before[name] for name in before)
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
  --set-string 'credentialPortal.auth.eligibility.rules[0].claimPath=groups[]' >/dev/null 2>"${WORKDIR}/ambiguous-eligibility.txt"; then
  echo "expected ambiguous portal eligibility predicate to fail" >&2
  exit 1
fi
grep -Fq 'must define exactly one eligibility predicate' "${WORKDIR}/ambiguous-eligibility.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set credentialPortal.auth.eligibility.rules[0].owner=false >/dev/null 2>"${WORKDIR}/portal-owner-false.txt"; then
  echo "expected portal eligibility owner:false to fail" >&2
  exit 1
fi
grep -Fq 'owner is not an eligibility predicate' "${WORKDIR}/portal-owner-false.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set credentialPortal.auth.claimEnrichment.limits.maxArrayItems=257 >/dev/null 2>"${WORKDIR}/unsafe-eligibility-limit.txt"; then
  echo "expected unsafe portal enrichment limit to fail" >&2
  exit 1
fi
grep -Fq 'limits.maxArrayItems exceeds safe bounds' "${WORKDIR}/unsafe-eligibility-limit.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set-string credentialPortal.auth.claimEnrichment.sources[0].pagination.mode=cursor >/dev/null 2>"${WORKDIR}/invalid-pagination-mode.txt"; then
  echo "credential portal rendered unsupported claim pagination" >&2
  exit 1
fi
grep -Fq 'pagination must use link mode with maxPages between 2 and 10' "${WORKDIR}/invalid-pagination-mode.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set credentialPortal.auth.claimEnrichment.sources[0].pagination.maxPages=11 >/dev/null 2>"${WORKDIR}/invalid-pagination-pages.txt"; then
  echo "credential portal rendered excessive claim pages" >&2
  exit 1
fi
grep -Fq 'pagination must use link mode with maxPages between 2 and 10' "${WORKDIR}/invalid-pagination-pages.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set-string credentialPortal.auth.claimEnrichment.sources[0].valuePath=state >/dev/null 2>"${WORKDIR}/invalid-pagination-path.txt"; then
  echo "credential portal rendered paginated non-root valuePath" >&2
  exit 1
fi
grep -Fq 'valuePath must be $ when pagination is configured' "${WORKDIR}/invalid-pagination-path.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set-string credentialPortal.auth.claimEnrichment.sources[0].endpoint=https://other.identity.example/v1/memberships >/dev/null 2>"${WORKDIR}/disallowed-eligibility-host.txt"; then
  echo "expected disallowed portal enrichment host to fail" >&2
  exit 1
fi
grep -Fq 'endpoint host is not allowed' "${WORKDIR}/disallowed-eligibility-host.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set-string 'credentialPortal.auth.eligibility.rules[0].where.array=pid[]' >/dev/null 2>"${WORKDIR}/sensitive-where-array.txt"; then
  echo "expected sensitive where.array to fail" >&2
  exit 1
fi
grep -Fq 'where.array must be a non-sensitive JSON path' "${WORKDIR}/sensitive-where-array.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set-string 'credentialPortal.auth.eligibility.rules[0].where.all[0].claimPath=a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q' >/dev/null 2>"${WORKDIR}/eligibility-path-segments.txt"; then
  echo "expected an eligibility path with more than 16 segments to fail" >&2
  exit 1
fi
grep -Fq 'claimPath must contain at most 16 segments' "${WORKDIR}/eligibility-path-segments.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set-string credentialPortal.auth.claimEnrichment.allowedHosts[1]=claims.identity.example >/dev/null 2>"${WORKDIR}/duplicate-enrichment-host.txt"; then
  echo "expected a duplicate claim-enrichment host to fail" >&2
  exit 1
fi
grep -Fq 'allowedHosts[1] is duplicated' "${WORKDIR}/duplicate-enrichment-host.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set-string credentialPortal.auth.claimEnrichment.sources[1].endpoint=https://claims.identity.example/v1/other \
  --set-string credentialPortal.auth.claimEnrichment.sources[1].outputClaim=memberships \
  --set-string credentialPortal.auth.claimEnrichment.sources[1].valuePath=state >/dev/null 2>"${WORKDIR}/duplicate-enrichment-output.txt"; then
  echo "expected a duplicate claim-enrichment output to fail" >&2
  exit 1
fi
grep -Fq 'outputClaim is duplicated' "${WORKDIR}/duplicate-enrichment-output.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set-string credentialPortal.auth.claimEnrichment.allowedHosts[0]=-invalid.example >/dev/null 2>"${WORKDIR}/invalid-enrichment-host.txt"; then
  echo "expected an invalid DNS-label claim-enrichment host to fail" >&2
  exit 1
fi
grep -Fq 'normalized lowercase DNS hostname' "${WORKDIR}/invalid-enrichment-host.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set-string credentialPortal.auth.oidc.eligibilityClaimSource=unverified_jwt >/dev/null 2>"${WORKDIR}/invalid-oidc-claim-source.txt"; then
  echo "expected an invalid portal OIDC eligibility claim source to fail" >&2
  exit 1
fi
grep -Fq 'eligibilityClaimSource must be id_token, access_token, or userinfo' "${WORKDIR}/invalid-oidc-claim-source.txt"

# Duplicate scalar values and printable legacy IDs remain compatible with the
# pre-existing gateway admission syntax when they stay within safety bounds.
helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set-string 'credentialPortal.auth.eligibility.rules[0].id=Approved party legacy rule' \
  --set-string 'credentialPortal.auth.eligibility.rules[0].where.all[0].values[1]=0192:123456789' >/dev/null

expect_dynamic_failure() {
  local name="$1"
  local message="$2"
  shift 2
  if helm template nvt "${CHART}" -n nvt \
    -f "${ROOT}/tests/operator/helm/credential-portal-dynamic-values.yaml" \
    "$@" >/dev/null 2>"${WORKDIR}/${name}.txt"; then
    echo "expected dynamic credential portal ${name} validation to fail" >&2
    exit 1
  fi
  grep -Fq "${message}" "${WORKDIR}/${name}.txt"
}

expect_dynamic_failure static-slot \
  'static slots and dynamic templates are mutually exclusive' \
  --set-string credentialPortal.slots[0].name=forbidden-static-slot
expect_dynamic_failure missing-eligibility \
  'requires an explicit eligibility policy' \
  --set credentialPortal.auth.eligibility=null
expect_dynamic_failure path-prefix \
  'publicURL must use the /agents/credentials path prefix' \
  --set-string credentialPortal.publicURL=https://agents.example.test/other
expect_dynamic_failure broker-tls \
  'broker.url must be an HTTPS origin without a path' \
  --set-string credentialPortal.dynamic.broker.url=http://nvt-broker:7347
expect_dynamic_failure broker-network-policy \
  'broker port must be allowed by networkPolicy.egressTCPPorts' \
  --set credentialPortal.networkPolicy.egressTCPPorts='{443}'
expect_dynamic_failure broker-auth-secret \
  'broker authentication must reference the broker dynamic assertion key' \
  --set-string credentialPortal.dynamic.broker.authentication.existingSecret=wrong-secret
expect_dynamic_failure missing-rotation-epoch \
  'requires broker.dynamicAccountAssertionRotationEpoch' \
  --set-string broker.dynamicAccountAssertionRotationEpoch=
expect_dynamic_failure invalid-rotation-epoch \
  'bounded non-secret rotation identifier' \
  --set-string broker.dynamicAccountAssertionRotationEpoch='not valid'
expect_dynamic_failure broker-assertion-window \
  'assertion TTL must not exceed the broker assertion window' \
  --set broker.config.dynamic-accounts.authentication.max-assertion-seconds=30
expect_dynamic_failure eligibility-session-window \
  'dynamic broker bounds are invalid' \
  --set credentialPortal.dynamic.broker.eligibilityLeaseSeconds=3601
expect_dynamic_failure broker-eligibility-window \
  'eligibility lease must not exceed the broker eligibility window' \
  --set broker.config.dynamic-accounts.authentication.max-eligibility-lease-seconds=3599
expect_dynamic_failure unknown-template \
  'is not an approved broker credential template' \
  --set-string credentialPortal.dynamic.templates[0].name=not-approved
expect_dynamic_failure adapter-drift \
  'adapter does not match the broker credential template' \
  --set-string credentialPortal.dynamic.templates[0].adapter=claude-oauth-file
expect_dynamic_failure broker-disabled \
  'requires broker.config.dynamic-accounts.enabled=true' \
  --set broker.config.dynamic-accounts.enabled=false
expect_dynamic_failure output-limit \
  'must not exceed the broker 768 KiB credential limit' \
  --set credentialPortal.enrollment.maxOutputBytes=786433
expect_dynamic_failure recovery-output-limit \
  'maxUploadBytes must not exceed the broker 768 KiB credential limit' \
  --set credentialPortal.maxUploadBytes=786433
expect_dynamic_failure switch-coordinator-url \
  'template switch coordinator must be a canonical internal HTTP origin' \
  --set-string credentialPortal.dynamic.templateSwitch.coordinatorURL=https://nvt-operator:8082
expect_dynamic_failure switch-coordinator-network-policy \
  'template switch coordinator port must be allowed by networkPolicy.egressTCPPorts' \
  --set credentialPortal.networkPolicy.egressTCPPorts='{443,7347}'
expect_dynamic_failure switch-operator-disabled \
  'requires broker and operator coordination' \
  --set operator.principalAccounts.templateSwitching.enabled=false
expect_dynamic_failure switch-broker-disabled \
  'requires broker dynamic template-switching.enabled=true' \
  --set broker.config.dynamic-accounts.template-switching.enabled=false
expect_dynamic_failure switch-shared-auth-key \
  'distinct' \
  --set-string broker.config.dynamic-accounts.template-switching.operator-hmac-key-env=NVT_DYNAMIC_ACCOUNT_ASSERTION_KEY \
  --set-string operator.principalAccounts.templateSwitching.authentication.key=NVT_DYNAMIC_ACCOUNT_ASSERTION_KEY
expect_dynamic_failure switch-operator-replicas \
  'operator.replicas must be 1' \
  --set operator.replicas=2

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set-string credentialPortal.dynamic.broker.url=https://nvt-broker:7347 \
  >/dev/null 2>"${WORKDIR}/dormant-dynamic.txt"; then
  echo "expected disabled dynamic credential portal configuration to fail" >&2
  exit 1
fi
grep -Fq 'disabled credentialPortal.dynamic must not carry broker or template configuration' \
  "${WORKDIR}/dormant-dynamic.txt"

if helm template nvt "${CHART}" -n nvt -f "${ROOT}/tests/operator/helm/credential-portal-values.yaml" \
  --set credentialPortal.enabled=false >"${WORKDIR}/disabled.yaml"; then :; fi
if grep -Fq 'nvt-credential-portal' "${WORKDIR}/disabled.yaml"; then
  echo "disabled portal rendered workload resources" >&2
  exit 1
fi
