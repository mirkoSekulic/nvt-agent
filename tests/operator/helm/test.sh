#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHART="${ROOT}/charts/nvt"
PRODUCER_CHART="${ROOT}/charts/nvt-github-comments-producer"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

DEFAULT_RENDER="${WORKDIR}/default.yaml"
BROKER_DISABLED_RENDER="${WORKDIR}/broker-disabled.yaml"
BROKER_SECRET_RENDER="${WORKDIR}/broker-secret.yaml"
NAMESPACE_OVERRIDE_RENDER="${WORKDIR}/namespace-override.yaml"
NAMESPACE_CREATE_RENDER="${WORKDIR}/namespace-create.yaml"
REPLICA_FAILURE="${WORKDIR}/replica-failure.txt"
PRODUCER_RENDER="${WORKDIR}/producer.yaml"
PRODUCER_EXISTING_CLAIM_RENDER="${WORKDIR}/producer-existing-claim.yaml"
PRODUCER_EMPTYDIR_RENDER="${WORKDIR}/producer-emptydir.yaml"
PRODUCER_EXISTING_SA_RENDER="${WORKDIR}/producer-existing-sa.yaml"
PRODUCER_CROSS_NAMESPACE_RENDER="${WORKDIR}/producer-cross-namespace.yaml"

helm template nvt "${CHART}" -n custom-ns > "${DEFAULT_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set broker.enabled=false > "${BROKER_DISABLED_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set broker.envSecretName=nvt-broker-env > "${BROKER_SECRET_RENDER}"
helm template nvt "${CHART}" --set namespace.name=nvt > "${NAMESPACE_OVERRIDE_RENDER}"
helm template nvt "${CHART}" --set namespace.create=true --set namespace.name=nvt > "${NAMESPACE_CREATE_RENDER}"
helm template nvt-github-comments-producer "${PRODUCER_CHART}" -n custom-ns > "${PRODUCER_RENDER}"
helm template nvt-github-comments-producer "${PRODUCER_CHART}" -n custom-ns --set persistence.existingClaim=existing-state > "${PRODUCER_EXISTING_CLAIM_RENDER}"
helm template nvt-github-comments-producer "${PRODUCER_CHART}" -n custom-ns --set persistence.enabled=false > "${PRODUCER_EMPTYDIR_RENDER}"
helm template nvt-github-comments-producer "${PRODUCER_CHART}" -n custom-ns --set serviceAccount.create=false --set serviceAccount.name=existing-sa --set rbac.create=false > "${PRODUCER_EXISTING_SA_RENDER}"
helm template nvt-github-comments-producer "${PRODUCER_CHART}" -n producer-ns --set agentRun.namespace=nvt > "${PRODUCER_CROSS_NAMESPACE_RENDER}"
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
require_resource "${PRODUCER_RENDER}" Role nvt-github-comments-producer
require_resource "${PRODUCER_RENDER}" RoleBinding nvt-github-comments-producer
require_resource "${PRODUCER_RENDER}" PersistentVolumeClaim nvt-github-comments-producer-state
require_resource_namespace "${PRODUCER_RENDER}" Deployment nvt-github-comments-producer custom-ns
require_resource_namespace "${PRODUCER_RENDER}" ConfigMap nvt-github-comments-producer custom-ns
require_resource_namespace "${PRODUCER_RENDER}" ServiceAccount nvt-github-comments-producer custom-ns
require_resource_namespace "${PRODUCER_RENDER}" Role nvt-github-comments-producer custom-ns
require_resource_namespace "${PRODUCER_RENDER}" RoleBinding nvt-github-comments-producer custom-ns
require_resource_namespace "${PRODUCER_RENDER}" PersistentVolumeClaim nvt-github-comments-producer-state custom-ns
grep -q -- '--config=/etc/nvt-github-comments/config.yaml' "${PRODUCER_RENDER}"
grep -q 'operatorCallbackBaseURL: "http://nvt-operator:8082"' "${PRODUCER_RENDER}"
grep -q 'privateKeyPath: "/var/run/secrets/github-app/private-key.pem"' "${PRODUCER_RENDER}"
grep -q 'secretName: "nvt-github-app"' "${PRODUCER_RENDER}"
grep -q 'mountPath: "/var/run/secrets/github-app"' "${PRODUCER_RENDER}"
grep -q 'claimName: nvt-github-comments-producer-state' "${PRODUCER_RENDER}"
grep -q 'resources:' "${PRODUCER_RENDER}"
grep -q 'agentruns' "${PRODUCER_RENDER}"
grep -q 'create' "${PRODUCER_RENDER}"
if grep -Eq 'privateKey:|privateKeyBase64:|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' "${PRODUCER_RENDER}"; then
  echo "producer chart must not render GitHub App private key material" >&2
  exit 1
fi
if grep -Eq '(^|[[:space:]]+)-[[:space:]]+(update|delete)$' "${PRODUCER_RENDER}"; then
  echo "producer RBAC must not grant update/delete on AgentRuns" >&2
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
require_resource_namespace "${PRODUCER_CROSS_NAMESPACE_RENDER}" Role nvt-github-comments-producer nvt
require_resource_namespace "${PRODUCER_CROSS_NAMESPACE_RENDER}" RoleBinding nvt-github-comments-producer nvt
require_rolebinding_subject_namespace "${PRODUCER_CROSS_NAMESPACE_RENDER}" nvt-github-comments-producer producer-ns
grep -q 'namespace: "nvt"' "${PRODUCER_CROSS_NAMESPACE_RENDER}"

echo "helm render test passed"
