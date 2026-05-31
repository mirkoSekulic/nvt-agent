#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHART="${ROOT}/charts/nvt"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

DEFAULT_RENDER="${WORKDIR}/default.yaml"
BROKER_DISABLED_RENDER="${WORKDIR}/broker-disabled.yaml"
BROKER_SECRET_RENDER="${WORKDIR}/broker-secret.yaml"
NAMESPACE_CREATE_RENDER="${WORKDIR}/namespace-create.yaml"

helm template nvt "${CHART}" > "${DEFAULT_RENDER}"
helm template nvt "${CHART}" --set broker.enabled=false > "${BROKER_DISABLED_RENDER}"
helm template nvt "${CHART}" --set broker.envSecretName=nvt-broker-env > "${BROKER_SECRET_RENDER}"
helm template nvt "${CHART}" --set namespace.create=true > "${NAMESPACE_CREATE_RENDER}"

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

require_resource "${DEFAULT_RENDER}" Deployment nvt-broker
require_resource "${DEFAULT_RENDER}" Service nvt-broker
require_resource "${DEFAULT_RENDER}" ConfigMap nvt-broker-config
require_resource "${DEFAULT_RENDER}" ConfigMap nvt-broker-agents
require_resource_namespace "${DEFAULT_RENDER}" Deployment nvt-broker nvt
require_resource_namespace "${DEFAULT_RENDER}" Service nvt-broker nvt
require_resource_namespace "${DEFAULT_RENDER}" ConfigMap nvt-broker-config nvt
require_resource_namespace "${DEFAULT_RENDER}" ConfigMap nvt-broker-agents nvt

require_resource "${DEFAULT_RENDER}" Deployment nvt-operator
require_resource "${DEFAULT_RENDER}" ServiceAccount nvt-operator
require_resource "${DEFAULT_RENDER}" Role nvt-operator
require_resource "${DEFAULT_RENDER}" RoleBinding nvt-operator
require_resource "${DEFAULT_RENDER}" Service nvt-operator
require_resource "${DEFAULT_RENDER}" AgentSchedule default
require_resource_namespace "${DEFAULT_RENDER}" Deployment nvt-operator nvt
require_resource_namespace "${DEFAULT_RENDER}" ServiceAccount nvt-operator nvt
require_resource_namespace "${DEFAULT_RENDER}" Role nvt-operator nvt
require_resource_namespace "${DEFAULT_RENDER}" RoleBinding nvt-operator nvt
require_resource_namespace "${DEFAULT_RENDER}" Service nvt-operator nvt
require_resource_namespace "${DEFAULT_RENDER}" AgentSchedule default nvt
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

require_resource "${NAMESPACE_CREATE_RENDER}" Namespace nvt
require_resource_namespace "${NAMESPACE_CREATE_RENDER}" Deployment nvt-operator nvt

echo "helm render test passed"
