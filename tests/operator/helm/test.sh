#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHART="${ROOT}/charts/nvt"
CHART_VERSION="$(awk -F ': *' '/^version:/ { gsub(/"/, "", $2); print $2; exit }' "${CHART}/Chart.yaml")"
CHART_APP_VERSION="$(awk -F ': *' '/^appVersion:/ { gsub(/"/, "", $2); print $2; exit }' "${CHART}/Chart.yaml")"
if [[ "${CHART_VERSION}" != "0.8.11" || "${CHART_APP_VERSION}" != "0.8.11" ]]; then
  echo "expected coordinated chart version and appVersion 0.8.11, got ${CHART_VERSION}/${CHART_APP_VERSION}" >&2
  exit 1
fi
if [[ "$(grep -Fc 'crds: CreateReplace' "${CHART}/README.md")" -lt 2 ]]; then
  echo "expected Flux install and upgrade CRD CreateReplace guidance" >&2
  exit 1
fi
grep -Fq 'helm show crds oci://ghcr.io/mirkosekulic/helm/nvt --version 0.8.11' "${CHART}/README.md"
grep -Fq 'kubectl apply --server-side -f -' "${CHART}/README.md"
TEST_RELEASE_TAG="${CHART_VERSION}-943d5ba"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

DEFAULT_RENDER="${WORKDIR}/default.yaml"
PROFILE_RENDER="${WORKDIR}/profile.yaml"
SCHEDULE_DEFAULT_IMAGE_RENDER="${WORKDIR}/schedule-default-image.yaml"
SCHEDULE_EMPTY_IMAGE_RENDER="${WORKDIR}/schedule-empty-image.yaml"
SCHEDULE_OVERRIDE_IMAGE_RENDER="${WORKDIR}/schedule-override-image.yaml"
SCHEDULE_LEGACY_RENDER="${WORKDIR}/schedule-legacy.yaml"
PACKAGED_SCHEDULE_RENDER="${WORKDIR}/packaged-schedule.yaml"
EGRESS_POLICY_RENDER="${WORKDIR}/egress-policy.yaml"
GATEWAY_RENDER="${WORKDIR}/gateway.yaml"
GATEWAY_OIDC_RENDER="${WORKDIR}/gateway-oidc.yaml"
GATEWAY_OIDC_MISSING_SECRET_FAILURE="${WORKDIR}/gateway-oidc-missing-secret-failure.txt"
GATEWAY_OIDC_REPLICAS_FAILURE="${WORKDIR}/gateway-oidc-replicas-failure.txt"
GATEWAY_OAUTH2_RENDER="${WORKDIR}/gateway-oauth2.yaml"
GATEWAY_ADMISSION_RENDER="${WORKDIR}/gateway-admission.yaml"
GATEWAY_EMPTY_ADMISSION_RENDER="${WORKDIR}/gateway-empty-admission.yaml"
GATEWAY_ADMISSION_FAILURE="${WORKDIR}/gateway-admission-failure.txt"
GATEWAY_OAUTH2_MISSING_SECRET_FAILURE="${WORKDIR}/gateway-oauth2-missing-secret-failure.txt"
GATEWAY_PATH_RENDER="${WORKDIR}/gateway-path.yaml"
GATEWAY_PATH_FAILURE="${WORKDIR}/gateway-path-failure.txt"
BROKER_DISABLED_RENDER="${WORKDIR}/broker-disabled.yaml"
BROKER_SECRET_RENDER="${WORKDIR}/broker-secret.yaml"
BROKER_TLS_DISABLED_RENDER="${WORKDIR}/broker-tls-disabled.yaml"
BROKER_TLS_EXISTING_RENDER="${WORKDIR}/broker-tls-existing.yaml"
BROKER_PERSISTENCE_RENDER="${WORKDIR}/broker-persistence.yaml"
BROKER_EXISTING_CLAIM_RENDER="${WORKDIR}/broker-existing-claim.yaml"
BROKER_SEED_RENDER="${WORKDIR}/broker-seed.yaml"
BROKER_SEED_WITHOUT_PERSISTENCE_FAILURE="${WORKDIR}/broker-seed-without-persistence-failure.txt"
BROKER_SEED_TARGET_FAILURE="${WORKDIR}/broker-seed-target-failure.txt"
NAMESPACE_OVERRIDE_RENDER="${WORKDIR}/namespace-override.yaml"
NAMESPACE_CREATE_RENDER="${WORKDIR}/namespace-create.yaml"
REPLICA_FAILURE="${WORKDIR}/replica-failure.txt"
PRODUCER_RENDER="${WORKDIR}/producer.yaml"
PRODUCER_DIRECT_RENDER="${WORKDIR}/producer-direct.yaml"
PRODUCER_PROFILED_RENDER="${WORKDIR}/producer-profiled.yaml"
PRODUCER_PROFILED_EXPIRATION_FAILURE="${WORKDIR}/producer-profiled-expiration-failure.txt"
PRODUCER_EXISTING_CLAIM_RENDER="${WORKDIR}/producer-existing-claim.yaml"
PRODUCER_EMPTYDIR_RENDER="${WORKDIR}/producer-emptydir.yaml"
PRODUCER_EXISTING_SA_RENDER="${WORKDIR}/producer-existing-sa.yaml"
PRODUCER_CROSS_NAMESPACE_RENDER="${WORKDIR}/producer-cross-namespace.yaml"
PRODUCER_NULL_TTL_RENDER="${WORKDIR}/producer-null-ttl.yaml"
PRODUCER_EMPTY_TTL_RENDER="${WORKDIR}/producer-empty-ttl.yaml"
PRODUCER_PERSISTENT_RENDER="${WORKDIR}/producer-persistent.yaml"
PRODUCER_PERSISTENT_MISSING_SIZE_FAILURE="${WORKDIR}/producer-persistent-missing-size-failure.txt"
PRODUCER_EPHEMERAL_STORAGE_FAILURE="${WORKDIR}/producer-ephemeral-storage-failure.txt"
ALL_IMAGES_RENDER="${WORKDIR}/all-images.yaml"
PACKAGED_RELEASE_RENDER="${WORKDIR}/packaged-release.yaml"
SOURCE_GLOBAL_TAG_RENDER="${WORKDIR}/source-global-tag.yaml"
COMPONENT_TAG_RENDER="${WORKDIR}/component-tag.yaml"
LEGACY_IMAGE_FAILURE="${WORKDIR}/legacy-image-failure.txt"
OAUTH2_ARGS=(
  --set gateway.auth.oauth2.credentials.existingSecret=nvt-agent-gateway-oauth2
  --set gateway.auth.oauth2.credentials.clientIDKey=oauth2-client-id
  --set gateway.auth.oauth2.credentials.clientSecretKey=oauth2-client-secret
  --set gateway.auth.oauth2.issuer=https://identity.example.test
  --set gateway.auth.oauth2.authorizationURL=https://identity.example.test/authorize
  --set gateway.auth.oauth2.tokenURL=https://identity.example.test/token
  --set gateway.auth.oauth2.identity.endpoint=https://api.identity.example.test/user
  --set gateway.auth.oauth2.identity.allowedHosts[0]=api.identity.example.test
  --set gateway.auth.oauth2.identity.subjectPath=id
  --set gateway.auth.oauth2.identity.displayNamePath=login
)

helm template nvt "${CHART}" -n custom-ns > "${DEFAULT_RENDER}"
helm template nvt "${CHART}" -n custom-ns -f "${ROOT}/tests/operator/helm/profile-values.yaml" > "${PROFILE_RENDER}"
helm template nvt "${CHART}" -n custom-ns -s templates/agentschedule.yaml \
  --set agentSchedule.template.workspace.mode=Ephemeral > "${SCHEDULE_DEFAULT_IMAGE_RENDER}"
helm template nvt "${CHART}" -n custom-ns -s templates/agentschedule.yaml \
  --set agentSchedule.template.workspace.mode=Ephemeral \
  --set-string agentSchedule.template.image= > "${SCHEDULE_EMPTY_IMAGE_RENDER}"
helm template nvt "${CHART}" -n custom-ns -s templates/agentschedule.yaml \
  --set-string agentSchedule.template.image=registry.example/runtime:override > "${SCHEDULE_OVERRIDE_IMAGE_RENDER}"
helm template nvt "${CHART}" -n custom-ns -s templates/agentschedule.yaml > "${SCHEDULE_LEGACY_RENDER}"
helm template nvt "${CHART}" -n custom-ns \
  --set 'egress.allowedTCPPorts={80,8443}' \
  --set 'egress.denyCIDRs={10.240.0.0/16,fd00:1234::/48}' \
  > "${EGRESS_POLICY_RENDER}"
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
  --set gateway.auth.oidc.extraAuthParams.authorization_details='[{"type":"ansattporten:altinn:resource"}]' \
  --set gateway.auth.authorization.claimSource=userinfo \
  --set gateway.auth.authorization.rules[0].id=break-glass-admins \
  --set gateway.auth.authorization.rules[0].effect=allow \
  --set gateway.auth.authorization.rules[0].claimPath='groups[]' \
  --set gateway.auth.authorization.rules[0].values[0]=nvt-agent-admins \
  --set-string 'gateway.auth.oidc.authorizationDetails={"type":"openid_credential"}' \
  > "${GATEWAY_OIDC_RENDER}"
helm template nvt "${CHART}" -n custom-ns \
  --set gateway.enabled=true \
  --set gateway.publicURL=https://agents.example.com \
  --set gateway.auth.mode=oauth2 \
  "${OAUTH2_ARGS[@]}" \
  --set gateway.auth.session.existingSecret=nvt-agent-gateway-session \
  --set gateway.auth.oauth2.credentials.existingSecret=nvt-agent-gateway-oauth2 \
  --set gateway.auth.oauth2.credentials.clientIDKey=oauth2-client-id \
  --set gateway.auth.oauth2.credentials.clientSecretKey=oauth2-client-secret \
  --set gateway.auth.authorization.rules[0].id=agent-owner \
  --set gateway.auth.authorization.rules[0].effect=allow \
  --set gateway.auth.authorization.rules[0].owner=true \
  > "${GATEWAY_OAUTH2_RENDER}"
helm template nvt "${CHART}" -n custom-ns \
  --set gateway.enabled=true \
  --set gateway.auth.mode=oauth2 \
  "${OAUTH2_ARGS[@]}" \
  --set gateway.auth.session.existingSecret=nvt-agent-gateway-session \
  --set gateway.auth.session.maxAgeSeconds=3600 \
  --set gateway.auth.oauth2.credentials.existingSecret=nvt-agent-gateway-oauth2 \
  --set gateway.auth.oauth2.issuer=https://github.com \
  --set gateway.auth.oauth2.authorizationURL=https://github.com/login/oauth/authorize \
  --set gateway.auth.oauth2.tokenURL=https://github.com/login/oauth/access_token \
  --set gateway.auth.oauth2.identity.endpoint=https://api.github.com/user \
  --set gateway.auth.oauth2.identity.allowedHosts[0]=api.github.com \
  --set gateway.auth.claimEnrichment.allowedHosts[0]=api.github.com \
  --set gateway.auth.claimEnrichment.sources[0].endpoint=https://api.github.com/user/memberships/orgs/Altinn \
  --set gateway.auth.claimEnrichment.sources[0].outputClaim=organization_membership \
  --set gateway.auth.claimEnrichment.sources[0].valuePath=state \
  --set gateway.auth.admission.default=deny \
  --set gateway.auth.admission.rules[0].id=allowed-organization \
  --set gateway.auth.admission.rules[0].effect=allow \
  --set gateway.auth.admission.rules[0].claimPath=organization_membership \
  --set gateway.auth.admission.rules[0].values[0]=active \
  --set gateway.auth.authorization.rules[0].id=agent-owner \
  --set gateway.auth.authorization.rules[0].effect=allow \
  --set gateway.auth.authorization.rules[0].owner=true \
  > "${GATEWAY_ADMISSION_RENDER}"
helm template nvt "${CHART}" -n custom-ns \
  --set gateway.enabled=true \
  --set gateway.auth.mode=oauth2 \
  "${OAUTH2_ARGS[@]}" \
  --set gateway.auth.session.existingSecret=nvt-agent-gateway-session \
  --set gateway.auth.oauth2.credentials.existingSecret=nvt-agent-gateway-oauth2 \
  --set-json 'gateway.auth.admission={}' \
  > "${GATEWAY_EMPTY_ADMISSION_RENDER}"
helm template nvt "${CHART}" -n custom-ns \
  --set gateway.enabled=true \
  --set gateway.routing.mode=path \
  --set gateway.publicURL=https://staging.altinn.studio/agents \
  --set gateway.baseDomain= \
  > "${GATEWAY_PATH_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set broker.enabled=false > "${BROKER_DISABLED_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set broker.envSecretName=nvt-broker-env > "${BROKER_SECRET_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set broker.tls.enabled=false > "${BROKER_TLS_DISABLED_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set broker.tls.existingSecret=corp-broker-tls > "${BROKER_TLS_EXISTING_RENDER}"
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
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true > "${PRODUCER_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true --set producer.submission.mode=direct > "${PRODUCER_DIRECT_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true \
  --set producer.submission.admissionMode=profiled \
  --set producer.submission.tokenExpirationSeconds=1800 \
  > "${PRODUCER_PROFILED_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true --set producer.persistence.existingClaim=existing-state > "${PRODUCER_EXISTING_CLAIM_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true --set producer.persistence.enabled=false > "${PRODUCER_EMPTYDIR_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true --set producer.serviceAccount.create=false --set producer.serviceAccount.name=existing-sa --set producer.rbac.create=false > "${PRODUCER_EXISTING_SA_RENDER}"
helm template nvt "${CHART}" -n producer-ns --set producer.enabled=true --set producer.agentRun.namespace=nvt > "${PRODUCER_CROSS_NAMESPACE_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true --set producer.agentRun.ttl=null > "${PRODUCER_NULL_TTL_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true --set producer.agentRun.ttl.completedTTLSeconds=null --set producer.agentRun.ttl.failedTTLSeconds=null --set producer.agentRun.ttl.runRetentionSeconds=null > "${PRODUCER_EMPTY_TTL_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true \
  --set producer.agentRun.workspaceMode=Persistent \
  --set-string producer.agentRun.workspaceSize=20Gi \
  --set producer.agentRun.workspaceStorageClassName=managed-csi \
  > "${PRODUCER_PERSISTENT_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true --set gateway.enabled=true > "${ALL_IMAGES_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true --set gateway.enabled=true \
  --set-string global.imageTag="${TEST_RELEASE_TAG}" >"${SOURCE_GLOBAL_TAG_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set-string global.imageTag="${TEST_RELEASE_TAG}" \
  --set-string operator.image.tag=operator-override >"${COMPONENT_TAG_RENDER}"
helm package "${CHART}" --app-version "${TEST_RELEASE_TAG}" --destination "${WORKDIR}" >/dev/null
helm template nvt "${WORKDIR}/nvt-${CHART_VERSION}.tgz" -n custom-ns --set producer.enabled=true --set gateway.enabled=true > "${PACKAGED_RELEASE_RENDER}"
helm template nvt "${WORKDIR}/nvt-${CHART_VERSION}.tgz" -n custom-ns -s templates/agentschedule.yaml \
  --set agentSchedule.template.workspace.mode=Ephemeral > "${PACKAGED_SCHEDULE_RENDER}"
bash -n "${ROOT}/scripts/operator-codex-auth-secret.sh"
bash -n "${ROOT}/scripts/github-comments-producer-secret.sh"
bash -n "${ROOT}/scripts/broker-env-secret.sh"
bash "${ROOT}/tests/operator/codex-auth-secret/test.sh"
bash "${ROOT}/tests/operator/github-comments-producer-secret/test.sh"
bash "${ROOT}/tests/operator/broker-env-secret/test.sh"
bash -n "${ROOT}/tests/operator/kind/smoke-scheduler-job.sh"
bash -n "${ROOT}/tests/operator/kind/smoke-scheduler-job-test.sh"
bash -n "${ROOT}/tests/operator/kind/kind-command.sh"
bash -n "${ROOT}/tests/operator/kind/producer-kind-targets-test.sh"
bash "${ROOT}/tests/operator/kind/smoke-scheduler-job-test.sh"
bash "${ROOT}/tests/operator/kind/producer-kind-targets-test.sh"

grep -q 'value: "80,8443"' "${EGRESS_POLICY_RENDER}" || {
  echo "chart did not render configured external TCP ports" >&2
  exit 1
}
grep -q 'value: "10.240.0.0/16,fd00:1234::/48"' "${EGRESS_POLICY_RENDER}" || {
  echo "chart did not render configured IPv4/IPv6 deployment exclusions" >&2
  exit 1
}

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

require_deployment_strategy() {
  local file="$1"
  local name="$2"
  local strategy="$3"

  awk -v want_name="${name}" -v want_strategy="${strategy}" '
    function reset_doc() {
      kind = ""
      name = ""
      in_metadata = 0
      in_strategy = 0
      strategy = ""
    }
    function check_doc() {
      if (kind == "Deployment" && name == want_name && strategy == want_strategy) {
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
    /^spec:[[:space:]]*$/ && kind == "Deployment" {
      in_metadata = 0
      next
    }
    /^[[:space:]]{2}strategy:[[:space:]]*$/ && kind == "Deployment" {
      in_strategy = 1
      next
    }
    in_strategy && /^[[:space:]]{4}type:[[:space:]]*/ {
      strategy = $2
      gsub(/^"|"$/, "", strategy)
      in_strategy = 0
      next
    }
    /^[^[:space:]]/ && $0 !~ /^(metadata|spec):/ {
      in_metadata = 0
      in_strategy = 0
    }
    END {
      check_doc()
      exit(found ? 0 : 1)
    }
  ' "${file}" || {
    echo "missing Deployment/${name} strategy type ${strategy} in ${file}" >&2
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
require_deployment_strategy "${DEFAULT_RENDER}" nvt-broker Recreate

require_resource "${DEFAULT_RENDER}" Deployment nvt-operator
require_resource "${DEFAULT_RENDER}" ServiceAccount nvt-operator
require_resource "${DEFAULT_RENDER}" Role nvt-operator
require_resource "${DEFAULT_RENDER}" RoleBinding nvt-operator
require_resource "${DEFAULT_RENDER}" Service nvt-operator
require_resource "${DEFAULT_RENDER}" AgentSchedule default
require_resource "${DEFAULT_RENDER}" ClusterRole nvt-tokenreview
require_resource "${DEFAULT_RENDER}" ClusterRoleBinding nvt-tokenreview
require_resource_namespace "${DEFAULT_RENDER}" Deployment nvt-operator custom-ns
require_resource_namespace "${DEFAULT_RENDER}" ServiceAccount nvt-operator custom-ns
require_resource_namespace "${DEFAULT_RENDER}" Role nvt-operator custom-ns
require_resource_namespace "${DEFAULT_RENDER}" RoleBinding nvt-operator custom-ns
require_resource_namespace "${DEFAULT_RENDER}" Service nvt-operator custom-ns
grep -q 'resources: \["persistentvolumeclaims"\]' "${DEFAULT_RENDER}"
require_resource_namespace "${DEFAULT_RENDER}" AgentSchedule default custom-ns
missing_resource "${DEFAULT_RENDER}" Namespace nvt
missing_resource "${DEFAULT_RENDER}" Deployment nvt-agent-gateway
missing_resource "${DEFAULT_RENDER}" Service nvt-agent-gateway
missing_resource "${DEFAULT_RENDER}" Role nvt-agent-gateway
missing_resource "${DEFAULT_RENDER}" Deployment nvt-github-comments-producer
missing_resource "${DEFAULT_RENDER}" ConfigMap nvt-github-comments-producer

for image in \
  nvt-agent-runtime \
  nvt-broker \
  nvt-egressd \
  nvt-captured \
  nvt-operator \
  nvt-agent-gateway \
  nvt-github-comments-producer; do
  grep -q "ghcr.io/mirkosekulic/${image}:${CHART_APP_VERSION}" "${ALL_IMAGES_RENDER}" || {
    echo "coordinated default image missing from render: ${image}" >&2
    exit 1
  }
done
grep -q 'ghcr.io/mirkosekulic/nvt-operator:operator-override' "${COMPONENT_TAG_RENDER}"
for image in \
  nvt-agent-runtime \
  nvt-broker \
  nvt-egressd \
  nvt-captured \
  nvt-operator \
  nvt-agent-gateway \
  nvt-github-comments-producer; do
  grep -q "ghcr.io/mirkosekulic/${image}:${TEST_RELEASE_TAG}" "${SOURCE_GLOBAL_TAG_RENDER}" || {
    echo "global.imageTag did not coordinate source-chart image: ${image}" >&2
    exit 1
  }
done
for image in \
  nvt-agent-runtime \
  nvt-broker \
  nvt-egressd \
  nvt-captured \
  nvt-operator \
  nvt-agent-gateway \
  nvt-github-comments-producer; do
  grep -q "ghcr.io/mirkosekulic/${image}:${TEST_RELEASE_TAG}" "${PACKAGED_RELEASE_RENDER}" || {
    echo "published chart appVersion did not coordinate image: ${image}" >&2
    exit 1
  }
done
if grep -Eq 'image:.*:latest|image:[[:space:]]*"?nvt-' "${ALL_IMAGES_RENDER}"; then
  echo "coordinated chart rendered a latest or local-only deployment image" >&2
  exit 1
fi
if helm template nvt "${CHART}" -n custom-ns \
  --set-string operator.image=nvt-operator:latest \
  > /dev/null 2>"${LEGACY_IMAGE_FAILURE}"; then
  echo "legacy scalar image value was accepted" >&2
  exit 1
fi
grep -q 'operator.image must use the 0.2 repository/tag/pullPolicy map; migrate 0.1 scalar image values before upgrading' "${LEGACY_IMAGE_FAILURE}"

grep -q 'name: default-codex' "${PROFILE_RENDER}"
grep -q 'provider: codex-main' "${PROFILE_RENDER}"
grep -q 'onNoMatch: useDefault' "${PROFILE_RENDER}"
grep -q 'system:serviceaccount:custom-ns:producer' "${PROFILE_RENDER}"
grep -q 'runtimeClassName: kata-vm-isolation' "${PROFILE_RENDER}"
grep -A6 'resources:' "${PROFILE_RENDER}" | grep -q 'cpu: "2"'
grep -A6 'resources:' "${PROFILE_RENDER}" | grep -q 'memory: 8Gi'
grep -A5 'tolerations:' "${PROFILE_RENDER}" | grep -q 'key: purpose'
grep -A5 'tolerations:' "${PROFILE_RENDER}" | grep -q 'operator: Equal'
grep -A5 'tolerations:' "${PROFILE_RENDER}" | grep -q 'value: nvt-agent'
grep -A5 'tolerations:' "${PROFILE_RENDER}" | grep -q 'effect: NoSchedule'
grep -A3 'preparations:' "${PROFILE_RENDER}" | grep -q 'operation: identity'
grep -q "image: ghcr.io/mirkosekulic/nvt-agent-runtime:${CHART_APP_VERSION}" "${SCHEDULE_DEFAULT_IMAGE_RENDER}"
grep -q "image: ghcr.io/mirkosekulic/nvt-agent-runtime:${CHART_APP_VERSION}" "${SCHEDULE_EMPTY_IMAGE_RENDER}"
grep -q 'image: registry.example/runtime:override' "${SCHEDULE_OVERRIDE_IMAGE_RENDER}"
for render in "${SCHEDULE_DEFAULT_IMAGE_RENDER}" "${SCHEDULE_EMPTY_IMAGE_RENDER}" "${SCHEDULE_OVERRIDE_IMAGE_RENDER}"; do
  if [[ "$(grep -c '^[[:space:]]\{4\}image:' "${render}")" != "1" ]]; then
    echo "AgentSchedule template must render exactly one image in ${render}" >&2
    exit 1
  fi
done
if grep -q 'ghcr.io/mirkosekulic/nvt-agent-runtime:' "${SCHEDULE_OVERRIDE_IMAGE_RENDER}"; then
  echo "explicit AgentSchedule template image was not preserved" >&2
  exit 1
fi
if grep -q '^[[:space:]]*template:' "${SCHEDULE_LEGACY_RENDER}"; then
  echo "empty legacy AgentSchedule template must remain omitted" >&2
  exit 1
fi
grep -q "image: ghcr.io/mirkosekulic/nvt-agent-runtime:${TEST_RELEASE_TAG}" "${PACKAGED_SCHEDULE_RENDER}"

require_resource "${GATEWAY_RENDER}" Deployment nvt-agent-gateway
require_resource "${GATEWAY_RENDER}" Service nvt-agent-gateway
require_resource "${GATEWAY_RENDER}" ServiceAccount nvt-agent-gateway
require_resource "${GATEWAY_RENDER}" Role nvt-agent-gateway
require_resource "${GATEWAY_RENDER}" RoleBinding nvt-agent-gateway
require_resource_namespace "${GATEWAY_RENDER}" Deployment nvt-agent-gateway custom-ns
require_resource_namespace "${GATEWAY_RENDER}" Service nvt-agent-gateway custom-ns
grep -q 'type: ClusterIP' "${GATEWAY_RENDER}"
grep -q -- '--base-domain=agents.localhost' "${GATEWAY_RENDER}"
grep -q -- '--routing-mode=subdomain' "${GATEWAY_RENDER}"
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

require_resource "${GATEWAY_PATH_RENDER}" Deployment nvt-agent-gateway
require_resource "${GATEWAY_PATH_RENDER}" Service nvt-agent-gateway
grep -q -- '--routing-mode=path' "${GATEWAY_PATH_RENDER}"
grep -q -- '--public-url=https://staging.altinn.studio/agents' "${GATEWAY_PATH_RENDER}"
grep -q 'type: ClusterIP' "${GATEWAY_PATH_RENDER}"
if grep -q 'httpHeaders:' "${GATEWAY_PATH_RENDER}"; then
  echo "gateway path mode probes must not require a synthetic Host header" >&2
  exit 1
fi
if [ "$(grep -c 'path: /healthz' "${GATEWAY_PATH_RENDER}")" -lt 2 ]; then
  echo "gateway path mode liveness and readiness must use /healthz" >&2
  exit 1
fi
for invalid_args in \
  '--set gateway.auth.mode=github' \
  '--set gateway.routing.mode=unknown' \
  '--set gateway.routing.mode=path' \
  '--set gateway.routing.mode=path --set gateway.publicURL=http://agents.altinn.studio' \
  '--set gateway.routing.mode=path --set gateway.publicURL=https://agents.altinn.studio/base/' \
  '--set gateway.routing.mode=path --set gateway.publicURL=https://agents.altinn.studio/base//nested' \
  '--set gateway.routing.mode=path --set gateway.publicURL=https://agents.altinn.studio/%61gents' \
  '--set gateway.routing.mode=path --set gateway.publicURL=https://agents.altinn.studio/agents?next=bad' \
  '--set gateway.routing.mode=path --set gateway.publicURL=https://agents.altinn.studio --set gateway.auth.session.cookieDomain=.altinn.studio' \
  '--set gateway.routing.mode=path --set gateway.publicURL=https://agents.altinn.studio --set gateway.auth.oidc.callbackPath=/callback' \
  '--set gateway.routing.mode=path --set gateway.publicURL=https://agents.altinn.studio --set gateway.auth.oauth2.callbackPath=/oauth2/../callback' \
  '--set gateway.routing.mode=path --set gateway.publicURL=https://agents.altinn.studio --set gateway.auth.oidc.callbackPath=/oauth2%2Fcallback' \
  '--set gateway.routing.mode=path --set gateway.publicURL=https://agents.altinn.studio --set gateway.auth.oauth2.callbackPath=/oauth2/%63allback'; do
  if helm template nvt "${CHART}" -n custom-ns --set gateway.enabled=true ${invalid_args} > /dev/null 2> "${GATEWAY_PATH_FAILURE}"; then
    echo "expected invalid gateway routing config to fail: ${invalid_args}" >&2
    exit 1
  fi
done

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
grep -q 'name: NVT_GATEWAY_AUTHORIZATION' "${GATEWAY_OIDC_RENDER}"
grep -q 'claimSource' "${GATEWAY_OIDC_RENDER}"
grep -q 'break-glass-admins' "${GATEWAY_OIDC_RENDER}"
grep -q -- '--public-url=https://agents.altinn.studio' "${GATEWAY_OIDC_RENDER}"

if helm template nvt "${CHART}" -n custom-ns \
  --set gateway.enabled=true \
  --set gateway.replicas=2 \
  --set gateway.auth.mode=oidc \
  --set gateway.auth.session.existingSecret=nvt-agent-gateway-session \
  --set gateway.auth.oidc.issuerURL=https://issuer.example.test \
  --set gateway.auth.oidc.clientID=nvt-agent-gateway \
  --set gateway.auth.oidc.clientSecret.existingSecret=nvt-agent-gateway-oidc \
  > "${GATEWAY_OIDC_REPLICAS_FAILURE}" 2>&1; then
  echo "expected gateway oidc replicas>1 config to fail rendering" >&2
  exit 1
fi
grep -q "gateway.replicas must be 1 when gateway authentication is enabled until shared sessions exist" "${GATEWAY_OIDC_REPLICAS_FAILURE}"

if helm template nvt "${CHART}" -n custom-ns \
  --set gateway.enabled=true \
  --set gateway.auth.mode=oidc \
  --set gateway.auth.oidc.issuerURL=https://issuer.example.test \
  --set gateway.auth.oidc.clientID=nvt-agent-gateway \
  > /dev/null 2> "${GATEWAY_OIDC_MISSING_SECRET_FAILURE}"; then
  echo "expected gateway oidc missing Secret config to fail rendering" >&2
  exit 1
fi
grep -q "gateway.auth.session.existingSecret is required when gateway authentication is enabled" "${GATEWAY_OIDC_MISSING_SECRET_FAILURE}"

grep -q 'value: "oauth2"' "${GATEWAY_OAUTH2_RENDER}"
grep -q 'name: NVT_GATEWAY_OAUTH2_CLIENT_ID' "${GATEWAY_OAUTH2_RENDER}"
grep -q 'name: "nvt-agent-gateway-oauth2"' "${GATEWAY_OAUTH2_RENDER}"
grep -q 'key: "oauth2-client-id"' "${GATEWAY_OAUTH2_RENDER}"
grep -q 'name: NVT_GATEWAY_OAUTH2_CLIENT_SECRET' "${GATEWAY_OAUTH2_RENDER}"
grep -q 'key: "oauth2-client-secret"' "${GATEWAY_OAUTH2_RENDER}"
grep -q 'value: "/oauth2/callback"' "${GATEWAY_OAUTH2_RENDER}"
grep -q 'value: "https://identity.example.test"' "${GATEWAY_OAUTH2_RENDER}"
grep -q 'value: "https://identity.example.test/authorize"' "${GATEWAY_OAUTH2_RENDER}"
grep -q 'value: "https://identity.example.test/token"' "${GATEWAY_OAUTH2_RENDER}"
grep -q 'value: "https://api.identity.example.test/user"' "${GATEWAY_OAUTH2_RENDER}"
grep -q 'name: NVT_GATEWAY_OAUTH2_IDENTITY_ALLOWED_HOSTS' "${GATEWAY_OAUTH2_RENDER}"
grep -q 'value: "api.identity.example.test"' "${GATEWAY_OAUTH2_RENDER}"
grep -q 'name: NVT_GATEWAY_OAUTH2_CLIENT_AUTH_METHOD' "${GATEWAY_OAUTH2_RENDER}"
grep -q 'value: "client_secret_post"' "${GATEWAY_OAUTH2_RENDER}"
grep -Fq '\"owner\":true' "${GATEWAY_OAUTH2_RENDER}"
if grep -q 'name: NVT_GATEWAY_ADMISSION' "${GATEWAY_OAUTH2_RENDER}"; then
  echo "unset gateway admission must preserve the existing session behavior" >&2
  exit 1
fi
grep -q 'name: NVT_GATEWAY_CLAIM_ENRICHMENT' "${GATEWAY_OAUTH2_RENDER}"
if grep -Eq 'value:.*(oauth2-client-id|oauth2-client-secret)' "${GATEWAY_OAUTH2_RENDER}"; then
  echo "gateway OAuth2 credentials must only come from Secret refs" >&2
  exit 1
fi
if helm template nvt "${CHART}" -n custom-ns \
  --set gateway.enabled=true \
  --set gateway.auth.mode=oauth2 \
  "${OAUTH2_ARGS[@]}" \
  --set gateway.auth.oauth2.credentials.existingSecret= \
  --set gateway.auth.session.existingSecret=nvt-agent-gateway-session \
  > /dev/null 2> "${GATEWAY_OAUTH2_MISSING_SECRET_FAILURE}"; then
  echo "expected gateway oauth2 missing credential Secret to fail rendering" >&2
  exit 1
fi
grep -q "gateway.auth.oauth2.credentials.existingSecret is required when gateway.auth.mode=oauth2" "${GATEWAY_OAUTH2_MISSING_SECRET_FAILURE}"

for invalid_args in \
  '--set gateway.auth.oauth2.clientAuthMethod=auto' \
  '--set gateway.auth.oauth2.callbackPath=/oauth2/../callback' \
  '--set gateway.auth.oauth2.callbackPath=/oauth2/%63allback' \
  '--set gateway.auth.oauth2.issuer=http://identity.example.test' \
  '--set gateway.auth.oauth2.identity.endpoint=https://user:secret@api.identity.example.test/user' \
  '--set gateway.auth.oauth2.identity.endpoint=https://other.example.test/user' \
  '--set gateway.auth.oauth2.identity.allowedHosts[0]=API.IDENTITY.EXAMPLE.TEST' \
  '--set gateway.auth.oauth2.identity.subjectPath=access_token' \
  '--set gateway.auth.oauth2.identity.subjectPath=identities.*.id'; do
  if helm template nvt "${CHART}" -n custom-ns \
    --set gateway.enabled=true \
    --set gateway.auth.mode=oauth2 \
    "${OAUTH2_ARGS[@]}" \
    --set gateway.auth.session.existingSecret=nvt-agent-gateway-session \
    ${invalid_args} > /dev/null 2> "${GATEWAY_OAUTH2_MISSING_SECRET_FAILURE}"; then
    echo "expected invalid generic OAuth2 config to fail: ${invalid_args}" >&2
    exit 1
  fi
done

grep -q 'name: NVT_GATEWAY_ADMISSION' "${GATEWAY_ADMISSION_RENDER}"
grep -A1 'name: NVT_GATEWAY_SESSION_MAX_AGE_SECONDS' "${GATEWAY_ADMISSION_RENDER}" | grep -q 'value: "3600"'
grep -Fq '\"claimPath\":\"organization_membership\"' "${GATEWAY_ADMISSION_RENDER}"
grep -q 'name: NVT_GATEWAY_CLAIM_ENRICHMENT' "${GATEWAY_ADMISSION_RENDER}"
grep -A1 'name: NVT_GATEWAY_OAUTH2_ISSUER' "${GATEWAY_ADMISSION_RENDER}" | grep -q 'value: "https://github.com"'
grep -A1 'name: NVT_GATEWAY_OAUTH2_IDENTITY_ENDPOINT' "${GATEWAY_ADMISSION_RENDER}" | grep -q 'value: "https://api.github.com/user"'
grep -Fq '\"allowedHosts\":[\"api.github.com\"]' "${GATEWAY_ADMISSION_RENDER}"
grep -Fq '\"endpoint\":\"https://api.github.com/user/memberships/orgs/Altinn\"' "${GATEWAY_ADMISSION_RENDER}"
grep -Fq '\"owner\":true' "${GATEWAY_ADMISSION_RENDER}"
grep -q 'name: NVT_GATEWAY_ADMISSION' "${GATEWAY_EMPTY_ADMISSION_RENDER}"
grep -q 'value: "{}"' "${GATEWAY_EMPTY_ADMISSION_RENDER}"

for invalid_args in \
  '--set gateway.auth.admission.rules[0].id=owner --set gateway.auth.admission.rules[0].effect=allow --set gateway.auth.admission.rules[0].owner=true' \
  '--set gateway.auth.claimEnrichment.allowedHosts[0]=api.example.com --set gateway.auth.claimEnrichment.sources[0].endpoint=http://api.example.com/member --set gateway.auth.claimEnrichment.sources[0].outputClaim=membership --set gateway.auth.claimEnrichment.sources[0].valuePath=state'; do
  if helm template nvt "${CHART}" -n custom-ns \
    --set gateway.enabled=true \
    --set gateway.auth.mode=oauth2 \
  "${OAUTH2_ARGS[@]}" \
    --set gateway.auth.session.existingSecret=nvt-agent-gateway-session \
    --set gateway.auth.oauth2.credentials.existingSecret=nvt-agent-gateway-oauth2 \
    ${invalid_args} > /dev/null 2> "${GATEWAY_ADMISSION_FAILURE}"; then
    echo "expected invalid gateway admission/enrichment config to fail: ${invalid_args}" >&2
    exit 1
  fi
done

if helm template nvt "${CHART}" -n custom-ns \
  --set gateway.enabled=true \
  --set gateway.auth.mode=none \
  --set gateway.auth.admission.default=deny \
  > /dev/null 2> "${GATEWAY_ADMISSION_FAILURE}"; then
  echo "expected gateway admission with auth.mode=none to fail" >&2
  exit 1
fi
grep -q 'gateway.auth.admission and gateway.auth.claimEnrichment require authentication' "${GATEWAY_ADMISSION_FAILURE}"

if helm template nvt "${CHART}" -n custom-ns \
  --set gateway.enabled=true \
  --set gateway.auth.mode=none \
  --set-json 'gateway.auth.admission={}' \
  > /dev/null 2> "${GATEWAY_ADMISSION_FAILURE}"; then
  echo "expected empty gateway admission with auth.mode=none to fail" >&2
  exit 1
fi
grep -q 'gateway.auth.admission and gateway.auth.claimEnrichment require authentication' "${GATEWAY_ADMISSION_FAILURE}"

require_file "${CHART}/crds/nvt.dev_agentruns.yaml"
require_file "${CHART}/crds/nvt.dev_agentschedules.yaml"
cmp -s "${ROOT}/operator/config/crd/bases/nvt.dev_agentruns.yaml" "${CHART}/crds/nvt.dev_agentruns.yaml"
cmp -s "${ROOT}/operator/config/crd/bases/nvt.dev_agentschedules.yaml" "${CHART}/crds/nvt.dev_agentschedules.yaml"
grep -A10 'preparations:' "${CHART}/crds/nvt.dev_agentruns.yaml" | grep -q -- '- identity'
grep -A10 'preparations:' "${CHART}/crds/nvt.dev_agentschedules.yaml" | grep -q -- '- identity'

rendered_secret_names() {
  local file="$1"
  awk '
    function reset_doc() {
      kind = ""
      name = ""
      in_metadata = 0
    }
    function emit_doc() {
      if (kind == "Secret" && name != "") {
        print name
      }
    }
    BEGIN {
      reset_doc()
    }
    /^---[[:space:]]*$/ {
      emit_doc()
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
      emit_doc()
    }
  ' "${file}" | sort -u
}

# The generated broker TLS Secret is the single Secret the chart may render:
# credential material must never pass through chart templates, but the broker
# serving cert is chart-generated (self-signed) by design.
default_secret_names="$(rendered_secret_names "${DEFAULT_RENDER}")"
if [[ "${default_secret_names}" != "nvt-broker-tls" ]]; then
  echo "chart must render exactly Secret nvt-broker-tls by default, got: ${default_secret_names:-none}" >&2
  exit 1
fi
grep -q 'tls.crt: ' "${DEFAULT_RENDER}"
grep -q 'tls.key: ' "${DEFAULT_RENDER}"
grep -q 'ca.crt: ' "${DEFAULT_RENDER}"
grep -q 'name: NVT_BROKER_TLS_CERT' "${DEFAULT_RENDER}"
grep -q 'value: /tls/tls.crt' "${DEFAULT_RENDER}"
grep -q 'name: NVT_BROKER_TLS_KEY' "${DEFAULT_RENDER}"
grep -q 'value: /tls/tls.key' "${DEFAULT_RENDER}"
grep -q 'secretName: "nvt-broker-tls"' "${DEFAULT_RENDER}"
grep -q 'name: NVT_BROKER_URL' "${DEFAULT_RENDER}"
grep -q 'value: "https://nvt-broker:7347"' "${DEFAULT_RENDER}"
grep -q 'name: NVT_BROKER_CA_SECRET' "${DEFAULT_RENDER}"
grep -q 'checksum/broker-tls: ' "${DEFAULT_RENDER}"

# checksum/broker-config rolls the broker Deployment when broker.config changes.
# The broker loads providers once at startup and does not hot-reload them, so a
# provider change that did not roll the Deployment would leave the old config
# running (the real Codex proof false failure).
grep -q 'checksum/broker-config: ' "${DEFAULT_RENDER}"
broker_config_checksum() {
  grep 'checksum/broker-config: ' "$1" | head -1 | awk '{print $2}' | tr -d '"'
}
BROKER_CONFIG_CHANGED_RENDER="${WORKDIR}/broker-config-changed.yaml"
helm template nvt "${CHART}" -n custom-ns \
  --set 'broker.config.providers[0].name=changed-provider' \
  --set 'broker.config.providers[0].plugin=token' > "${BROKER_CONFIG_CHANGED_RENDER}"
if [[ "$(broker_config_checksum "${DEFAULT_RENDER}")" == "$(broker_config_checksum "${BROKER_CONFIG_CHANGED_RENDER}")" ]]; then
  echo "checksum/broker-config must change when broker.config.providers changes" >&2
  exit 1
fi

# Revocation depends on the broker hot-reloading the agents ConfigMap on
# mtime change. A subPath mount freezes the projected file forever and would
# silently kill revocation, so the broker config volume must never be
# subPath-mounted (protocol/injection.md revocation contract).
BROKER_DEPLOYMENT_RENDER="${WORKDIR}/broker-deployment.yaml"
helm template nvt "${CHART}" -n custom-ns -s templates/broker-deployment.yaml > "${BROKER_DEPLOYMENT_RENDER}"
grep -q 'mountPath: /config' "${BROKER_DEPLOYMENT_RENDER}"
if grep -q 'subPath' "${BROKER_DEPLOYMENT_RENDER}"; then
  echo "broker Deployment must not subPath-mount any volume; it freezes the agents ConfigMap and kills revocation" >&2
  exit 1
fi

# defaultEgressMode knob: rendered into the operator env, default direct.
grep -q 'name: NVT_DEFAULT_EGRESS_MODE' "${DEFAULT_RENDER}"
grep -q 'value: "direct"' "${DEFAULT_RENDER}"

# allowInsecureUpstreams opt-in: absent by default, rendered only when set.
if grep -q 'NVT_ALLOW_INSECURE_UPSTREAMS' "${DEFAULT_RENDER}"; then
  echo "NVT_ALLOW_INSECURE_UPSTREAMS must not render by default" >&2
  exit 1
fi
INSECURE_UPSTREAMS_RENDER="${WORKDIR}/insecure-upstreams.yaml"
helm template nvt "${CHART}" -n custom-ns --set egress.allowInsecureUpstreams=true > "${INSECURE_UPSTREAMS_RENDER}"
grep -q 'name: NVT_ALLOW_INSECURE_UPSTREAMS' "${INSECURE_UPSTREAMS_RENDER}"
DEFAULT_MEDIATED_RENDER="${WORKDIR}/default-egress-mediated.yaml"
helm template nvt "${CHART}" -n custom-ns --set egress.defaultMode=mediated > "${DEFAULT_MEDIATED_RENDER}"
grep -q 'name: NVT_DEFAULT_EGRESS_MODE' "${DEFAULT_MEDIATED_RENDER}"
grep -q 'value: "mediated"' "${DEFAULT_MEDIATED_RENDER}"

sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

broker_tls_checksum() {
  grep 'checksum/broker-tls: ' "$1" | head -1 | awk '{print $2}' | tr -d '"'
}

# The checksum annotation must hash the same material the Secret template
# renders: without lookup (helm template) the cert regenerates per render, so
# the checksum must match the rendered data and differ between renders —
# otherwise a `helm template | kubectl apply` rotation applies a new Secret
# while the running broker keeps serving the old cert.
rendered_tls_crt="$(grep '^  tls.crt: ' "${DEFAULT_RENDER}" | head -1 | awk '{print $2}')"
rendered_tls_key="$(grep '^  tls.key: ' "${DEFAULT_RENDER}" | head -1 | awk '{print $2}')"
rendered_ca_crt="$(grep '^  ca.crt: ' "${DEFAULT_RENDER}" | head -1 | awk '{print $2}')"
expected_checksum="$(printf '{"ca.crt":"%s","tls.crt":"%s","tls.key":"%s"}' \
  "${rendered_ca_crt}" "${rendered_tls_crt}" "${rendered_tls_key}" | sha256_hex)"
if [[ "$(broker_tls_checksum "${DEFAULT_RENDER}")" != "${expected_checksum}" ]]; then
  echo "broker TLS checksum does not match the rendered Secret material" >&2
  exit 1
fi
DEFAULT_RERENDER="${WORKDIR}/default-rerender.yaml"
helm template nvt "${CHART}" -n custom-ns > "${DEFAULT_RERENDER}"
if [[ "$(broker_tls_checksum "${DEFAULT_RENDER}")" == "$(broker_tls_checksum "${DEFAULT_RERENDER}")" ]]; then
  echo "broker TLS checksum must change when the generated Secret material changes" >&2
  exit 1
fi

missing_resource "${BROKER_TLS_DISABLED_RENDER}" Secret nvt-broker-tls
if grep -Eq '^kind:[[:space:]]*Secret$' "${BROKER_TLS_DISABLED_RENDER}"; then
  echo "chart must not render Kubernetes Secrets with broker TLS disabled" >&2
  exit 1
fi
if grep -Eq 'NVT_BROKER_TLS_CERT|NVT_BROKER_CA_SECRET|NVT_BROKER_URL' "${BROKER_TLS_DISABLED_RENDER}"; then
  echo "broker TLS disabled must not render TLS env" >&2
  exit 1
fi
if grep -q 'checksum/broker-tls' "${BROKER_TLS_DISABLED_RENDER}"; then
  echo "broker TLS disabled must not render the TLS checksum annotation" >&2
  exit 1
fi

if [[ -n "$(rendered_secret_names "${BROKER_TLS_EXISTING_RENDER}")" ]]; then
  echo "broker.tls.existingSecret must not render a generated Secret" >&2
  exit 1
fi
grep -q 'secretName: "corp-broker-tls"' "${BROKER_TLS_EXISTING_RENDER}"
grep -q 'value: "corp-broker-tls"' "${BROKER_TLS_EXISTING_RENDER}"
grep -q 'checksum/broker-tls: ' "${BROKER_TLS_EXISTING_RENDER}"

missing_resource "${BROKER_DISABLED_RENDER}" Secret nvt-broker-tls
if grep -q 'NVT_BROKER_CA_SECRET' "${BROKER_DISABLED_RENDER}"; then
  echo "broker disabled must not render operator broker TLS env" >&2
  exit 1
fi

missing_resource "${BROKER_DISABLED_RENDER}" Deployment nvt-broker
missing_resource "${BROKER_DISABLED_RENDER}" Service nvt-broker
missing_resource "${BROKER_DISABLED_RENDER}" ConfigMap nvt-broker-config
missing_resource "${BROKER_DISABLED_RENDER}" ConfigMap nvt-broker-agents
require_resource "${BROKER_DISABLED_RENDER}" Deployment nvt-operator
require_resource "${BROKER_DISABLED_RENDER}" Service nvt-operator

if [[ "$(rendered_secret_names "${BROKER_SECRET_RENDER}")" != "nvt-broker-tls" ]]; then
  echo "chart must reference existing broker env Secret without creating one" >&2
  exit 1
fi
grep -q 'secretRef:' "${BROKER_SECRET_RENDER}"
grep -q 'name: "nvt-broker-env"' "${BROKER_SECRET_RENDER}"

missing_resource "${DEFAULT_RENDER}" PersistentVolumeClaim nvt-broker-state
grep -q 'emptyDir: {}' "${DEFAULT_RENDER}"
if grep -q 'seed_supervisor.py\|NVT_BROKER_SEED_DIR\|name: broker-state-seed' "${DEFAULT_RENDER}"; then
  echo "default broker rendering must preserve the unsupervised local/ephemeral path" >&2
  exit 1
fi

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
grep -q 'secretName: "codex-auth"' "${BROKER_SEED_RENDER}"
grep -q '/opt/nvt-broker/broker/seed_supervisor.py' "${BROKER_SEED_RENDER}"
grep -q 'name: NVT_BROKER_SEED_DIR' "${BROKER_SEED_RENDER}"
grep -q 'name: NVT_BROKER_SEED_TARGET_DIR' "${BROKER_SEED_RENDER}"
grep -q 'value: "codex"' "${BROKER_SEED_RENDER}"
grep -q 'defaultMode: 0400' "${BROKER_SEED_RENDER}"
grep -q 'readinessProbe:' "${BROKER_SEED_RENDER}"
grep -q 'path: /ready' "${BROKER_SEED_RENDER}"
grep -q 'scheme: HTTPS' "${BROKER_SEED_RENDER}"
if grep -q 'name: seed-broker-state' "${BROKER_SEED_RENDER}"; then
  echo "broker seed reconciliation must not remain a one-shot init container" >&2
  exit 1
fi

if helm template nvt "${CHART}" -n custom-ns \
  --set broker.persistence.seedSecretName=codex-auth \
  > /dev/null 2> "${BROKER_SEED_WITHOUT_PERSISTENCE_FAILURE}"; then
  echo "expected broker persistence seed without persistence to fail rendering" >&2
  exit 1
fi
grep -q "broker.persistence.seedSecretName requires broker.persistence.enabled=true" "${BROKER_SEED_WITHOUT_PERSISTENCE_FAILURE}"

if helm template nvt "${CHART}" -n custom-ns \
  --set broker.persistence.enabled=true \
  --set broker.persistence.seedSecretName=codex-auth \
  --set-string broker.persistence.seedTargetDir=../escape \
  > /dev/null 2> "${BROKER_SEED_TARGET_FAILURE}"; then
  echo "expected unsafe broker seed target to fail rendering" >&2
  exit 1
fi
grep -q "broker.persistence.seedTargetDir must be a normalized relative path without traversal" "${BROKER_SEED_TARGET_FAILURE}"

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
grep -q 'admissionMode: "legacy"' "${PRODUCER_RENDER}"
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
grep -q 'workspaceMode: "Ephemeral"' "${PRODUCER_RENDER}"
if grep -Eq 'workspace(Size|StorageClassName):' "${PRODUCER_RENDER}"; then
  echo "ephemeral producer config must omit persistent workspace fields" >&2
  exit 1
fi
grep -q 'workspaceMode: "Persistent"' "${PRODUCER_PERSISTENT_RENDER}"
grep -q 'workspaceSize: "20Gi"' "${PRODUCER_PERSISTENT_RENDER}"
grep -q 'workspaceStorageClassName: "managed-csi"' "${PRODUCER_PERSISTENT_RENDER}"
if helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true \
  --set producer.agentRun.workspaceMode=Persistent \
  > /dev/null 2> "${PRODUCER_PERSISTENT_MISSING_SIZE_FAILURE}"; then
  echo "expected Persistent producer workspace without size to fail rendering" >&2
  exit 1
fi
grep -q 'producer.agentRun.workspaceSize is required when workspaceMode is Persistent' "${PRODUCER_PERSISTENT_MISSING_SIZE_FAILURE}"
if helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true \
  --set-string producer.agentRun.workspaceSize=20Gi \
  > /dev/null 2> "${PRODUCER_EPHEMERAL_STORAGE_FAILURE}"; then
  echo "expected Ephemeral producer workspace with size to fail rendering" >&2
  exit 1
fi
grep -q 'producer.agentRun.workspaceSize and workspaceStorageClassName require workspaceMode Persistent' "${PRODUCER_EPHEMERAL_STORAGE_FAILURE}"
grep -q 'resources:' "${PRODUCER_RENDER}"
grep -q 'automountServiceAccountToken: false' "${PRODUCER_RENDER}"
if grep -q 'operator-admission-token' "${PRODUCER_RENDER}"; then
  echo "legacy producer mode must not project an operator admission token" >&2
  exit 1
fi
require_resource "${PRODUCER_DIRECT_RENDER}" Role nvt-github-comments-producer
require_resource "${PRODUCER_DIRECT_RENDER}" RoleBinding nvt-github-comments-producer
grep -q 'mode: "direct"' "${PRODUCER_DIRECT_RENDER}"
grep -q 'agentruns' "${PRODUCER_DIRECT_RENDER}"
grep -q 'create' "${PRODUCER_DIRECT_RENDER}"
if grep -q 'automountServiceAccountToken: false' "${PRODUCER_DIRECT_RENDER}"; then
  echo "direct producer mode requires the default Kubernetes client token" >&2
  exit 1
fi
grep -q 'admissionMode: "profiled"' "${PRODUCER_PROFILED_RENDER}"
grep -q 'admissionTokenFile: "/var/run/secrets/nvt-operator/token"' "${PRODUCER_PROFILED_RENDER}"
grep -q 'automountServiceAccountToken: false' "${PRODUCER_PROFILED_RENDER}"
grep -q 'mountPath: "/var/run/secrets/nvt-operator"' "${PRODUCER_PROFILED_RENDER}"
grep -q 'audience: nvt-operator' "${PRODUCER_PROFILED_RENDER}"
grep -q 'expirationSeconds: 1800' "${PRODUCER_PROFILED_RENDER}"
grep -q 'path: "token"' "${PRODUCER_PROFILED_RENDER}"
grep -q 'defaultMode: 0440' "${PRODUCER_PROFILED_RENDER}"
if helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true \
  --set producer.submission.admissionMode=profiled \
  --set producer.submission.tokenExpirationSeconds=599 \
  > /dev/null 2> "${PRODUCER_PROFILED_EXPIRATION_FAILURE}"; then
  echo "expected too-short projected token expiration to fail rendering" >&2
  exit 1
fi
grep -q 'producer.submission.tokenExpirationSeconds must be between 600 and 86400' "${PRODUCER_PROFILED_EXPIRATION_FAILURE}"
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
