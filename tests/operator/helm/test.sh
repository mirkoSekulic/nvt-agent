#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHART="${ROOT}/charts/nvt"
PRODUCER_CHART="${ROOT}/charts/nvt-github-comments-producer"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

DEFAULT_RENDER="${WORKDIR}/default.yaml"
GATEWAY_RENDER="${WORKDIR}/gateway.yaml"
GATEWAY_OIDC_RENDER="${WORKDIR}/gateway-oidc.yaml"
GATEWAY_OIDC_MISSING_SECRET_FAILURE="${WORKDIR}/gateway-oidc-missing-secret-failure.txt"
BROKER_DISABLED_RENDER="${WORKDIR}/broker-disabled.yaml"
BROKER_SECRET_RENDER="${WORKDIR}/broker-secret.yaml"
BROKER_PERSISTENCE_RENDER="${WORKDIR}/broker-persistence.yaml"
BROKER_EXISTING_CLAIM_RENDER="${WORKDIR}/broker-existing-claim.yaml"
BROKER_SEED_RENDER="${WORKDIR}/broker-seed.yaml"
BROKER_SEED_WITHOUT_PERSISTENCE_FAILURE="${WORKDIR}/broker-seed-without-persistence-failure.txt"
NAMESPACE_OVERRIDE_RENDER="${WORKDIR}/namespace-override.yaml"
NAMESPACE_CREATE_RENDER="${WORKDIR}/namespace-create.yaml"
REPLICA_FAILURE="${WORKDIR}/replica-failure.txt"
PRODUCER_RENDER="${WORKDIR}/producer.yaml"
PRODUCER_DIRECT_RENDER="${WORKDIR}/producer-direct.yaml"
PRODUCER_EXISTING_CLAIM_RENDER="${WORKDIR}/producer-existing-claim.yaml"
PRODUCER_EMPTYDIR_RENDER="${WORKDIR}/producer-emptydir.yaml"
PRODUCER_EXISTING_SA_RENDER="${WORKDIR}/producer-existing-sa.yaml"
PRODUCER_CROSS_NAMESPACE_RENDER="${WORKDIR}/producer-cross-namespace.yaml"
PRODUCER_NULL_TTL_RENDER="${WORKDIR}/producer-null-ttl.yaml"
PRODUCER_EMPTY_TTL_RENDER="${WORKDIR}/producer-empty-ttl.yaml"

helm template nvt "${CHART}" -n custom-ns > "${DEFAULT_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set gateway.enabled=true --set gateway.port=8091 > "${GATEWAY_RENDER}"
helm template nvt "${CHART}" -n custom-ns \
  --set gateway.enabled=true \
  --set gateway.publicURL=https://agents.altinn.studio \
  --set gateway.auth.mode=oidc \
  --set gateway.auth.session.existingSecret=nvt-agent-gateway-session \
  --set gateway.auth.session.cookieDomain=.agents.altinn.studio \
  --set gateway.auth.oidc.issuerURL=https://issuer.example.test \
  --set gateway.auth.oidc.clientID=nvt-agent-gateway \
  --set gateway.auth.oidc.clientSecret.existingSecret=nvt-agent-gateway-oidc \
  --set gateway.auth.oidc.callbackPath=/oauth2/custom-callback \
  --set gateway.auth.oidc.acrValues=Level4 \
  --set gateway.auth.oidc.validIssuer=https://issuer.example.test \
  --set gateway.auth.oidc.extraAuthParams.prompt=login \
  --set-string 'gateway.auth.oidc.authorizationDetails={"type":"openid_credential"}' \
  > "${GATEWAY_OIDC_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set broker.enabled=false > "${BROKER_DISABLED_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set broker.envSecretName=nvt-broker-env > "${BROKER_SECRET_RENDER}"
helm template nvt "${CHART}" -n custom-ns \
  --set broker.persistence.enabled=true \
  --set broker.persistence.size=2Gi \
  --set broker.persistence.storageClassName=fast-state \
  > "${BROKER_PERSISTENCE_RENDER}"
helm template nvt "${CHART}" -n custom-ns \
  --set broker.persistence.enabled=true \
  --set broker.persistence.existingClaim=existing-broker-state \
  > "${BROKER_EXISTING_CLAIM_RENDER}"
helm template nvt "${CHART}" -n custom-ns \
  --set broker.persistence.enabled=true \
  --set broker.persistence.seedSecretName=codex-auth \
  --set broker.persistence.seedTargetDir=codex \
  > "${BROKER_SEED_RENDER}"
helm template nvt "${CHART}" --set namespace.name=nvt > "${NAMESPACE_OVERRIDE_RENDER}"
helm template nvt "${CHART}" --set namespace.create=true --set namespace.name=nvt > "${NAMESPACE_CREATE_RENDER}"
helm template nvt-github-comments-producer "${PRODUCER_CHART}" -n custom-ns > "${PRODUCER_RENDER}"
helm template nvt-github-comments-producer "${PRODUCER_CHART}" -n custom-ns --set submission.mode=direct > "${PRODUCER_DIRECT_RENDER}"
helm template nvt-github-comments-producer "${PRODUCER_CHART}" -n custom-ns --set persistence.existingClaim=existing-state > "${PRODUCER_EXISTING_CLAIM_RENDER}"
helm template nvt-github-comments-producer "${PRODUCER_CHART}" -n custom-ns --set persistence.enabled=false > "${PRODUCER_EMPTYDIR_RENDER}"
helm template nvt-github-comments-producer "${PRODUCER_CHART}" -n custom-ns --set serviceAccount.create=false --set serviceAccount.name=existing-sa --set rbac.create=false > "${PRODUCER_EXISTING_SA_RENDER}"
helm template nvt-github-comments-producer "${PRODUCER_CHART}" -n producer-ns --set agentRun.namespace=nvt > "${PRODUCER_CROSS_NAMESPACE_RENDER}"
helm template nvt-github-comments-producer "${PRODUCER_CHART}" -n custom-ns --set agentRun.ttl=null > "${PRODUCER_NULL_TTL_RENDER}"
helm template nvt-github-comments-producer "${PRODUCER_CHART}" -n custom-ns --set agentRun.ttl.completedTTLSeconds=null --set agentRun.ttl.failedTTLSeconds=null --set agentRun.ttl.runRetentionSeconds=null > "${PRODUCER_EMPTY_TTL_RENDER}"
bash -n "${ROOT}/scripts/operator-codex-auth-secret.sh"
bash -n "${ROOT}/scripts/github-comments-producer-secret.sh"
bash -n "${ROOT}/scripts/broker-env-secret.sh"
bash "${ROOT}/tests/operator/codex-auth-secret/test.sh"
bash "${ROOT}/tests/operator/github-comments-producer-secret/test.sh"
bash "${ROOT}/tests/operator/broker-env-secret/test.sh"
bash -n "${ROOT}/tests/operator/kind/smoke-scheduler-job.sh"
bash -n "${ROOT}/tests/operator/kind/smoke-scheduler-job-test.sh"
bash -n "${ROOT}/tests/operator/kind/producer-kind-targets-test.sh"
bash "${ROOT}/tests/operator/kind/smoke-scheduler-job-test.sh"
bash "${ROOT}/tests/operator/kind/producer-kind-targets-test.sh"

has_resource() {
  local file="$1"
  local kind="$2"
  local name="$3"

  awk -v want_kind="${kind}" -v want_name="${name}" '
    function reset_doc() {
      kind = ""
      name = ""
      in_metadata = 0
    }
    function check_doc() {
      if (kind == want_kind && name == want_name) {
        found = 1
      }
    }
    BEGIN {
      reset_doc()
    }
    /^---[[:space:]]*$/ {
      check_doc()
      reset_doc()
      next
    }
    /^kind:[[:space:]]*/ {
      kind = $2
      next
    }
    /^metadata:[[:space:]]*$/ {
      in_metadata = 1
      next
    }
    in_metadata && /^[[:space:]]{2}name:[[:space:]]*/ {
      name = $2
      gsub(/^"|"$/, "", name)
      in_metadata = 0
      next
    }
    /^[^[:space:]]/ && $0 !~ /^metadata:/ {
      in_metadata = 0
    }
    END {
      check_doc()
      exit(found ? 0 : 1)
    }
  ' "${file}"
}

missing_resource() {
  local file="$1"
  local kind="$2"
  local name="$3"

  if has_resource "${file}" "${kind}" "${name}"; then
    echo "unexpected ${kind}/${name} in ${file}" >&2
    exit 1
  fi
}

require_resource() {
  local file="$1"
  local kind="$2"
  local name="$3"

  if ! has_resource "${file}" "${kind}" "${name}"; then
    echo "missing ${kind}/${name} in ${file}" >&2
    exit 1
  fi
}

require_resource_namespace() {
  local file="$1"
  local kind="$2"
  local name="$3"
  local namespace="$4"

  awk -v want_kind="${kind}" -v want_name="${name}" -v want_namespace="${namespace}" '
    function reset_doc() {
      kind = ""
      name = ""
      namespace = ""
      in_metadata = 0
    }
    function check_doc() {
      if (kind == want_kind && name == want_name && namespace == want_namespace) {
        found = 1
      }
    }
    BEGIN {
      reset_doc()
    }
    /^---[[:space:]]*$/ {
      check_doc()
      reset_doc()
      next
    }
    /^kind:[[:space:]]*/ {
      kind = $2
      next
    }
    /^metadata:[[:space:]]*$/ {
      in_metadata = 1
      next
    }
    in_metadata && /^[[:space:]]{2}name:[[:space:]]*/ {
      name = $2
      gsub(/^"|"$/, "", name)
      next
    }
    in_metadata && /^[[:space:]]{2}namespace:[[:space:]]*/ {
      namespace = $2
      gsub(/^"|"$/, "", namespace)
      next
    }
    /^[^[:space:]]/ && $0 !~ /^metadata:/ {
      in_metadata = 0
    }
    END {
      check_doc()
      exit(found ? 0 : 1)
    }
  ' "${file}" || {
    echo "missing ${kind}/${name} in namespace ${namespace} in ${file}" >&2
    exit 1
  }
}

require_file() {
  local file="$1"

  if [[ ! -s "${file}" ]]; then
    echo "missing required file ${file}" >&2
    exit 1
  fi
}

require_rolebinding_subject_namespace() {
  local file="$1"
  local name="$2"
  local namespace="$3"

  awk -v want_name="${name}" -v want_namespace="${namespace}" '
    function reset_doc() {
      kind = ""
      name = ""
      in_metadata = 0
      in_subject = 0
    }
    function check_doc() {
      if (kind == "RoleBinding" && name == want_name && subject_namespace == want_namespace) {
        found = 1
      }
    }
    BEGIN {
      reset_doc()
    }
    /^---[[:space:]]*$/ {
      check_doc()
      reset_doc()
      next
    }
    /^kind:[[:space:]]*/ {
      kind = $2
      next
    }
    /^metadata:[[:space:]]*$/ {
      in_metadata = 1
      next
    }
    in_metadata && /^[[:space:]]{2}name:[[:space:]]*/ {
      name = $2
      gsub(/^"|"$/, "", name)
      next
    }
    /^subjects:[[:space:]]*$/ {
      in_subject = 1
      next
    }
    in_subject && /^[[:space:]]{4}namespace:[[:space:]]*/ {
      subject_namespace = $2
      gsub(/^"|"$/, "", subject_namespace)
      next
    }
    /^[^[:space:]]/ && $0 !~ /^(metadata|subjects):/ {
      in_metadata = 0
      in_subject = 0
    }
    END {
      check_doc()
      exit(found ? 0 : 1)
    }
  ' "${file}" || {
    echo "missing RoleBinding/${name} subject namespace ${namespace} in ${file}" >&2
    exit 1
  }
}

require_resource "${DEFAULT_RENDER}" Deployment nvt-broker
require_resource "${DEFAULT_RENDER}" Service nvt-broker
require_resource "${DEFAULT_RENDER}" ConfigMap nvt-broker-config
require_resource "${DEFAULT_RENDER}" ConfigMap nvt-broker-agents
require_resource_namespace "${DEFAULT_RENDER}" Deployment nvt-broker custom-ns
require_resource_namespace "${DEFAULT_RENDER}" Service nvt-broker custom-ns
require_resource_namespace "${DEFAULT_RENDER}" ConfigMap nvt-broker-config custom-ns
require_resource_namespace "${DEFAULT_RENDER}" ConfigMap nvt-broker-agents custom-ns

require_resource "${DEFAULT_RENDER}" Deployment nvt-operator
require_resource "${DEFAULT_RENDER}" ServiceAccount nvt-operator
require_resource "${DEFAULT_RENDER}" Role nvt-operator
require_resource "${DEFAULT_RENDER}" RoleBinding nvt-operator
require_resource "${DEFAULT_RENDER}" Service nvt-operator
require_resource "${DEFAULT_RENDER}" AgentSchedule default
require_resource_namespace "${DEFAULT_RENDER}" Deployment nvt-operator custom-ns
require_resource_namespace "${DEFAULT_RENDER}" ServiceAccount nvt-operator custom-ns
require_resource_namespace "${DEFAULT_RENDER}" Role nvt-operator custom-ns
require_resource_namespace "${DEFAULT_RENDER}" RoleBinding nvt-operator custom-ns
require_resource_namespace "${DEFAULT_RENDER}" Service nvt-operator custom-ns
require_resource_namespace "${DEFAULT_RENDER}" AgentSchedule default custom-ns
missing_resource "${DEFAULT_RENDER}" Namespace nvt
missing_resource "${DEFAULT_RENDER}" Deployment nvt-agent-gateway
missing_resource "${DEFAULT_RENDER}" Service nvt-agent-gateway
missing_resource "${DEFAULT_RENDER}" Role nvt-agent-gateway

require_resource "${GATEWAY_RENDER}" Deployment nvt-agent-gateway
require_resource "${GATEWAY_RENDER}" Service nvt-agent-gateway
require_resource "${GATEWAY_RENDER}" ServiceAccount nvt-agent-gateway
require_resource "${GATEWAY_RENDER}" Role nvt-agent-gateway
require_resource "${GATEWAY_RENDER}" RoleBinding nvt-agent-gateway
require_resource_namespace "${GATEWAY_RENDER}" Deployment nvt-agent-gateway custom-ns
require_resource_namespace "${GATEWAY_RENDER}" Service nvt-agent-gateway custom-ns
grep -q 'type: ClusterIP' "${GATEWAY_RENDER}"
grep -q -- '--base-domain=agents.localhost' "${GATEWAY_RENDER}"
grep -q -- '--listen-addr=:8091' "${GATEWAY_RENDER}"
grep -q 'containerPort: 8091' "${GATEWAY_RENDER}"
grep -q 'targetPort: 8091' "${GATEWAY_RENDER}"
grep -q 'path: /healthz' "${GATEWAY_RENDER}"
grep -q 'port: 8091' "${GATEWAY_RENDER}"
grep -q 'nvt.dev' "${GATEWAY_RENDER}"
grep -q 'agentruns' "${GATEWAY_RENDER}"
grep -q 'pods' "${GATEWAY_RENDER}"
grep -q 'name: NVT_GATEWAY_AUTH_MODE' "${GATEWAY_RENDER}"
grep -q 'value: "none"' "${GATEWAY_RENDER}"
if grep -q 'secretKeyRef:' "${GATEWAY_RENDER}"; then
  echo "gateway auth.mode=none must not render auth Secret refs" >&2
  exit 1
fi

grep -q 'name: NVT_GATEWAY_AUTH_MODE' "${GATEWAY_OIDC_RENDER}"
grep -q 'value: "oidc"' "${GATEWAY_OIDC_RENDER}"
grep -q 'name: "nvt-agent-gateway-session"' "${GATEWAY_OIDC_RENDER}"
grep -q 'key: "session-secret"' "${GATEWAY_OIDC_RENDER}"
grep -q 'name: "nvt-agent-gateway-oidc"' "${GATEWAY_OIDC_RENDER}"
grep -q 'key: "client-secret"' "${GATEWAY_OIDC_RENDER}"
grep -q 'name: NVT_GATEWAY_SESSION_COOKIE_DOMAIN' "${GATEWAY_OIDC_RENDER}"
grep -q 'value: ".agents.altinn.studio"' "${GATEWAY_OIDC_RENDER}"
grep -q 'name: NVT_GATEWAY_OIDC_CALLBACK_PATH' "${GATEWAY_OIDC_RENDER}"
grep -q 'value: "/oauth2/custom-callback"' "${GATEWAY_OIDC_RENDER}"
grep -q 'name: NVT_GATEWAY_OIDC_EXTRA_AUTH_PARAMS' "${GATEWAY_OIDC_RENDER}"
grep -q 'prompt' "${GATEWAY_OIDC_RENDER}"
grep -q 'name: NVT_GATEWAY_OIDC_AUTHORIZATION_DETAILS' "${GATEWAY_OIDC_RENDER}"
grep -q 'openid_credential' "${GATEWAY_OIDC_RENDER}"
grep -q -- '--public-url=https://agents.altinn.studio' "${GATEWAY_OIDC_RENDER}"

if helm template nvt "${CHART}" -n custom-ns \
  --set gateway.enabled=true \
  --set gateway.auth.mode=oidc \
  --set gateway.auth.oidc.issuerURL=https://issuer.example.test \
  --set gateway.auth.oidc.clientID=nvt-agent-gateway \
  > /dev/null 2> "${GATEWAY_OIDC_MISSING_SECRET_FAILURE}"; then
  echo "expected gateway oidc missing Secret config to fail rendering" >&2
  exit 1
fi
grep -q "gateway.auth.session.existingSecret is required when gateway.auth.mode=oidc" "${GATEWAY_OIDC_MISSING_SECRET_FAILURE}"

require_file "${CHART}/crds/nvt.dev_agentruns.yaml"
require_file "${CHART}/crds/nvt.dev_agentschedules.yaml"
cmp -s "${ROOT}/operator/config/crd/bases/nvt.dev_agentruns.yaml" "${CHART}/crds/nvt.dev_agentruns.yaml"
cmp -s "${ROOT}/operator/config/crd/bases/nvt.dev_agentschedules.yaml" "${CHART}/crds/nvt.dev_agentschedules.yaml"

if grep -Eq '^kind:[[:space:]]*Secret$' "${DEFAULT_RENDER}"; then
  echo "chart must not render Kubernetes Secrets by default" >&2
  exit 1
fi

missing_resource "${BROKER_DISABLED_RENDER}" Deployment nvt-broker
missing_resource "${BROKER_DISABLED_RENDER}" Service nvt-broker
missing_resource "${BROKER_DISABLED_RENDER}" ConfigMap nvt-broker-config
missing_resource "${BROKER_DISABLED_RENDER}" ConfigMap nvt-broker-agents
require_resource "${BROKER_DISABLED_RENDER}" Deployment nvt-operator
require_resource "${BROKER_DISABLED_RENDER}" Service nvt-operator

if grep -Eq '^kind:[[:space:]]*Secret$' "${BROKER_SECRET_RENDER}"; then
  echo "chart must reference existing broker Secret without creating one" >&2
  exit 1
fi
grep -q 'secretRef:' "${BROKER_SECRET_RENDER}"
grep -q 'name: "nvt-broker-env"' "${BROKER_SECRET_RENDER}"

missing_resource "${DEFAULT_RENDER}" PersistentVolumeClaim nvt-broker-state
grep -q 'emptyDir: {}' "${DEFAULT_RENDER}"

require_resource "${BROKER_PERSISTENCE_RENDER}" PersistentVolumeClaim nvt-broker-state
require_resource_namespace "${BROKER_PERSISTENCE_RENDER}" PersistentVolumeClaim nvt-broker-state custom-ns
grep -q 'claimName: "nvt-broker-state"' "${BROKER_PERSISTENCE_RENDER}"
grep -q 'storage: "2Gi"' "${BROKER_PERSISTENCE_RENDER}"
grep -q 'storageClassName: "fast-state"' "${BROKER_PERSISTENCE_RENDER}"
if grep -q 'emptyDir: {}' "${BROKER_PERSISTENCE_RENDER}"; then
  echo "broker persistence must not render emptyDir" >&2
  exit 1
fi

missing_resource "${BROKER_EXISTING_CLAIM_RENDER}" PersistentVolumeClaim nvt-broker-state
grep -q 'claimName: "existing-broker-state"' "${BROKER_EXISTING_CLAIM_RENDER}"

require_resource "${BROKER_SEED_RENDER}" PersistentVolumeClaim nvt-broker-state
grep -q 'name: seed-broker-state' "${BROKER_SEED_RENDER}"
grep -q 'secretName: "codex-auth"' "${BROKER_SEED_RENDER}"
grep -q 'target="/state/codex"' "${BROKER_SEED_RENDER}"
grep -q 'already exists and is non-empty; leaving existing state unchanged' "${BROKER_SEED_RENDER}"
grep -q 'cp "${path}" "${target}/$(basename "${path}")"' "${BROKER_SEED_RENDER}"

if helm template nvt "${CHART}" -n custom-ns \
  --set broker.persistence.seedSecretName=codex-auth \
  > /dev/null 2> "${BROKER_SEED_WITHOUT_PERSISTENCE_FAILURE}"; then
  echo "expected broker persistence seed without persistence to fail rendering" >&2
  exit 1
fi
grep -q "broker.persistence.seedSecretName requires broker.persistence.enabled=true" "${BROKER_SEED_WITHOUT_PERSISTENCE_FAILURE}"

require_resource_namespace "${NAMESPACE_OVERRIDE_RENDER}" Deployment nvt-operator nvt
require_resource_namespace "${NAMESPACE_OVERRIDE_RENDER}" AgentSchedule default nvt
require_resource "${NAMESPACE_CREATE_RENDER}" Namespace nvt
require_resource_namespace "${NAMESPACE_CREATE_RENDER}" Deployment nvt-operator nvt

if helm template nvt "${CHART}" --set operator.replicas=2 > /dev/null 2> "${REPLICA_FAILURE}"; then
  echo "expected operator.replicas=2 to fail rendering" >&2
  exit 1
fi
grep -q "operator.replicas must be 1 in this POC because schedule admission locking is process-local" "${REPLICA_FAILURE}"

require_resource "${PRODUCER_RENDER}" Deployment nvt-github-comments-producer
require_resource "${PRODUCER_RENDER}" ConfigMap nvt-github-comments-producer
require_resource "${PRODUCER_RENDER}" ServiceAccount nvt-github-comments-producer
missing_resource "${PRODUCER_RENDER}" Role nvt-github-comments-producer
missing_resource "${PRODUCER_RENDER}" RoleBinding nvt-github-comments-producer
require_resource "${PRODUCER_RENDER}" PersistentVolumeClaim nvt-github-comments-producer-state
require_resource_namespace "${PRODUCER_RENDER}" Deployment nvt-github-comments-producer custom-ns
require_resource_namespace "${PRODUCER_RENDER}" ConfigMap nvt-github-comments-producer custom-ns
require_resource_namespace "${PRODUCER_RENDER}" ServiceAccount nvt-github-comments-producer custom-ns
require_resource_namespace "${PRODUCER_RENDER}" PersistentVolumeClaim nvt-github-comments-producer-state custom-ns
grep -q -- '--config=/etc/nvt-github-comments/config.yaml' "${PRODUCER_RENDER}"
grep -q 'operatorCallbackBaseURL: "http://nvt-operator:8082"' "${PRODUCER_RENDER}"
grep -q 'mode: "scheduleAdmission"' "${PRODUCER_RENDER}"
grep -q 'admissionBaseURL: "http://nvt-operator:8082"' "${PRODUCER_RENDER}"
grep -q 'scheduleNamespace: "custom-ns"' "${PRODUCER_RENDER}"
grep -q 'scheduleName: "default"' "${PRODUCER_RENDER}"
grep -q 'scope: "issue"' "${PRODUCER_RENDER}"
grep -q 'completedTTLSeconds: 300' "${PRODUCER_RENDER}"
grep -q 'failedTTLSeconds: 3600' "${PRODUCER_RENDER}"
grep -q 'runRetentionSeconds: 2592000' "${PRODUCER_RENDER}"
grep -q 'privateKeyPath: "/var/run/secrets/github-app/private-key.pem"' "${PRODUCER_RENDER}"
grep -q 'secretName: "nvt-github-app"' "${PRODUCER_RENDER}"
grep -q 'mountPath: "/var/run/secrets/github-app"' "${PRODUCER_RENDER}"
grep -q 'claimName: nvt-github-comments-producer-state' "${PRODUCER_RENDER}"
grep -q 'resources:' "${PRODUCER_RENDER}"
require_resource "${PRODUCER_DIRECT_RENDER}" Role nvt-github-comments-producer
require_resource "${PRODUCER_DIRECT_RENDER}" RoleBinding nvt-github-comments-producer
grep -q 'mode: "direct"' "${PRODUCER_DIRECT_RENDER}"
grep -q 'agentruns' "${PRODUCER_DIRECT_RENDER}"
grep -q 'create' "${PRODUCER_DIRECT_RENDER}"
if grep -Eq 'privateKey:|privateKeyBase64:|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' "${PRODUCER_RENDER}"; then
  echo "producer chart must not render GitHub App private key material" >&2
  exit 1
fi
if grep -Eq '(^|[[:space:]]+)-[[:space:]]+(update|delete)$' "${PRODUCER_RENDER}"; then
  echo "producer RBAC must not grant update/delete on AgentRuns" >&2
  exit 1
fi
if grep -q 'ttl:' "${PRODUCER_NULL_TTL_RENDER}"; then
  echo "producer chart must omit ttl when agentRun.ttl is null" >&2
  exit 1
fi
if grep -q 'ttl:' "${PRODUCER_EMPTY_TTL_RENDER}"; then
  echo "producer chart must omit ttl when all ttl fields are null" >&2
  exit 1
fi

missing_resource "${PRODUCER_EXISTING_CLAIM_RENDER}" PersistentVolumeClaim nvt-github-comments-producer-state
grep -q 'claimName: existing-state' "${PRODUCER_EXISTING_CLAIM_RENDER}"

missing_resource "${PRODUCER_EMPTYDIR_RENDER}" PersistentVolumeClaim nvt-github-comments-producer-state
grep -q 'emptyDir: {}' "${PRODUCER_EMPTYDIR_RENDER}"

missing_resource "${PRODUCER_EXISTING_SA_RENDER}" ServiceAccount nvt-github-comments-producer
missing_resource "${PRODUCER_EXISTING_SA_RENDER}" Role nvt-github-comments-producer
missing_resource "${PRODUCER_EXISTING_SA_RENDER}" RoleBinding nvt-github-comments-producer
grep -q 'serviceAccountName: existing-sa' "${PRODUCER_EXISTING_SA_RENDER}"

require_resource_namespace "${PRODUCER_CROSS_NAMESPACE_RENDER}" Deployment nvt-github-comments-producer producer-ns
require_resource_namespace "${PRODUCER_CROSS_NAMESPACE_RENDER}" ConfigMap nvt-github-comments-producer producer-ns
require_resource_namespace "${PRODUCER_CROSS_NAMESPACE_RENDER}" PersistentVolumeClaim nvt-github-comments-producer-state producer-ns
require_resource_namespace "${PRODUCER_CROSS_NAMESPACE_RENDER}" ServiceAccount nvt-github-comments-producer producer-ns
grep -q 'namespace: "nvt"' "${PRODUCER_CROSS_NAMESPACE_RENDER}"
grep -q 'scheduleNamespace: "nvt"' "${PRODUCER_CROSS_NAMESPACE_RENDER}"

echo "helm render test passed"
