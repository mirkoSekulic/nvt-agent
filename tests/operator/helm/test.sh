#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHART="${ROOT}/charts/nvt"
CHART_VERSION="$(awk -F ': *' '/^version:/ { gsub(/"/, "", $2); print $2; exit }' "${CHART}/Chart.yaml")"
CHART_APP_VERSION="$(awk -F ': *' '/^appVersion:/ { gsub(/"/, "", $2); print $2; exit }' "${CHART}/Chart.yaml")"
if [[ "${CHART_VERSION}" != "0.8.56" || "${CHART_APP_VERSION}" != "0.8.56" ]]; then
  echo "expected coordinated chart version and appVersion 0.8.56, got ${CHART_VERSION}/${CHART_APP_VERSION}" >&2
  exit 1
fi
if [[ "$(grep -Fc 'crds: CreateReplace' "${CHART}/README.md")" -lt 2 ]]; then
  echo "expected Flux install and upgrade CRD CreateReplace guidance" >&2
  exit 1
fi
grep -Fq 'helm show crds oci://ghcr.io/mirkosekulic/helm/nvt --version 0.8.56' "${CHART}/README.md"
grep -Fq 'ghcr.io/mirkosekulic/nvt-host-bundle:<appVersion>' "${CHART}/README.md"
grep -Fq 'repository: https://ghcr.io/mirkosekulic/nvt-host-bundle' "${CHART}/README.md"
grep -Fq 'digest: sha256:<64-hex>' "${CHART}/README.md"
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
GATEWAY_NATIVE_SESSION_RENDER="${WORKDIR}/gateway-native-session.yaml"
GATEWAY_NATIVE_SESSION_FAILURE="${WORKDIR}/gateway-native-session-failure.txt"
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
BRANDING_RENDER="${WORKDIR}/branding.yaml"
BRANDING_FAILURE="${WORKDIR}/branding-failure.txt"
BROKER_DISABLED_RENDER="${WORKDIR}/broker-disabled.yaml"
BROKER_SECRET_RENDER="${WORKDIR}/broker-secret.yaml"
BROKER_TLS_DISABLED_RENDER="${WORKDIR}/broker-tls-disabled.yaml"
BROKER_TLS_EXISTING_RENDER="${WORKDIR}/broker-tls-existing.yaml"
BROKER_PERSISTENCE_RENDER="${WORKDIR}/broker-persistence.yaml"
BROKER_EXISTING_CLAIM_RENDER="${WORKDIR}/broker-existing-claim.yaml"
BROKER_SEED_RENDER="${WORKDIR}/broker-seed.yaml"
BROKER_SEED_WITHOUT_PERSISTENCE_FAILURE="${WORKDIR}/broker-seed-without-persistence-failure.txt"
BROKER_SEED_TARGET_FAILURE="${WORKDIR}/broker-seed-target-failure.txt"
BROKER_ENROLLMENT_RENDER="${WORKDIR}/broker-enrollment.yaml"
BROKER_ENROLLMENT_FAILURE="${WORKDIR}/broker-enrollment-failure.txt"
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
EXECUTION_DRIVERS_RENDER="${WORKDIR}/execution-drivers.yaml"
EXECUTION_DRIVER_EXISTING_STORAGE_RENDER="${WORKDIR}/execution-driver-existing-storage.yaml"
EXECUTION_DRIVER_ENROLLMENT_RENDER="${WORKDIR}/execution-driver-enrollment.yaml"
EXECUTION_DRIVER_LONG_NAME_RENDER="${WORKDIR}/execution-driver-long-name.yaml"
EXECUTION_DRIVER_FAILURE="${WORKDIR}/execution-driver-failure.txt"
NATIVE_EGRESS_RELAY_RENDER="${WORKDIR}/native-egress-relay.yaml"
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
if grep -q 'NVT_EXECUTION_DRIVER_STATE_DIR\|name: driver-state\|component: execution-driver-host' "${DEFAULT_RENDER}"; then
  echo "default rendering unexpectedly added execution-driver storage/workloads" >&2
  exit 1
fi
helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" > "${EXECUTION_DRIVERS_RENDER}"
helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set-string executionDrivers.registrations[0].storage.size= \
  --set-string executionDrivers.registrations[0].storage.storageClassName= \
  --set-string executionDrivers.registrations[0].storage.existingClaim=existing-driver-state \
  > "${EXECUTION_DRIVER_EXISTING_STORAGE_RENDER}"
helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set executionDrivers.guestEnrollment.enabled=true \
  --set 'executionDrivers.guestEnrollment.registrations={fake-east}' \
  --set-string executionDrivers.guestEnrollment.brokerURL=https://nvt-broker.custom-ns.svc:7347 \
  --set-string executionDrivers.guestEnrollment.serverName=nvt-broker.custom-ns.svc \
  --set-string executionDrivers.guestEnrollment.ca.existingSecret=nvt-broker-tls \
  --set-string executionDrivers.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment-orchestrator \
  --set-string executionDrivers.guestEnrollment.orchestratorAuth.tokenKey=control-token \
  > "${EXECUTION_DRIVER_ENROLLMENT_RENDER}"
helm template nvt "${CHART}" -n custom-ns -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set nativeEgressRelay.enabled=true \
  --set-string nativeEgressRelay.rolloutRevision=credentials-1 \
  --set egress.networkPolicyCapable=true \
  --set broker.persistence.enabled=true \
  --set broker.guestEnrollment.enabled=true \
  --set-string broker.guestEnrollment.exchangeURL=https://nvt-broker.custom-ns.svc.cluster.local:7347/v1/guest-enrollment/exchange \
  --set-string broker.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment-orchestrator \
  --set executionDrivers.guestEnrollment.enabled=true \
  --set 'executionDrivers.guestEnrollment.registrations={fake-east}' \
  --set-string executionDrivers.guestEnrollment.brokerURL=https://nvt-broker.custom-ns.svc.cluster.local:7347 \
  --set-string executionDrivers.guestEnrollment.serverName=nvt-broker.custom-ns.svc.cluster.local \
  --set-string executionDrivers.guestEnrollment.ca.existingSecret=nvt-broker-tls \
  --set-string executionDrivers.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment-orchestrator \
  --set-string nativeEgressRelay.brokerURL=https://nvt-broker.custom-ns.svc.cluster.local:7347 \
  --set-string nativeEgressRelay.brokerServerName=nvt-broker.custom-ns.svc.cluster.local \
  --set-string nativeEgressRelay.credentials.existingSecret=nvt-native-egress-relay-credentials \
  --set-string nativeEgressRelay.brokerCA.existingSecret=nvt-broker-tls \
  --set-string nativeEgressRelay.data.ingressCIDRs[0]=10.40.0.0/16 \
  --set-string nativeEgressRelay.attachment.requiredDestinations[0].purpose=bootstrap \
  --set-string nativeEgressRelay.attachment.requiredDestinations[0].host=nvt-broker.custom-ns.svc.cluster.local \
  --set nativeEgressRelay.attachment.requiredDestinations[0].port=7347 \
  --set-string nativeEgressRelay.attachment.requiredDestinations[1].purpose=control \
  --set-string nativeEgressRelay.attachment.requiredDestinations[1].host=nvt-gateway.custom-ns.svc.cluster.local \
  --set nativeEgressRelay.attachment.requiredDestinations[1].port=7443 \
  > "${NATIVE_EGRESS_RELAY_RENDER}"
if helm template nvt "${CHART}" -n custom-ns -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set nativeEgressRelay.enabled=true \
  --set-string nativeEgressRelay.rolloutRevision=credentials-1 \
  --set egress.networkPolicyCapable=true \
  --set broker.persistence.enabled=true \
  --set broker.guestEnrollment.enabled=true \
  --set-string broker.guestEnrollment.exchangeURL=https://nvt-broker.custom-ns.svc.cluster.local:7347/v1/guest-enrollment/exchange \
  --set-string broker.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment-orchestrator \
  --set executionDrivers.guestEnrollment.enabled=true \
  --set 'executionDrivers.guestEnrollment.registrations={fake-east}' \
  --set-string executionDrivers.guestEnrollment.brokerURL=https://nvt-broker.custom-ns.svc.cluster.local:7347 \
  --set-string executionDrivers.guestEnrollment.serverName=nvt-broker.custom-ns.svc.cluster.local \
  --set-string executionDrivers.guestEnrollment.ca.existingSecret=nvt-broker-tls \
  --set-string executionDrivers.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment-orchestrator \
  --set-string nativeEgressRelay.brokerURL=https://nvt-broker.custom-ns.svc.cluster.local:7347 \
  --set-string nativeEgressRelay.brokerServerName=nvt-broker.custom-ns.svc.cluster.local \
  --set-string nativeEgressRelay.credentials.existingSecret=nvt-native-egress-relay-credentials \
  --set-string nativeEgressRelay.brokerCA.existingSecret=nvt-broker-tls \
  --set-string nativeEgressRelay.data.ingressCIDRs[0]=10.40.0.0/16 \
  --set-string nativeEgressRelay.attachment.relayHost=8.8.8.8 \
  --set-string nativeEgressRelay.attachment.relayServerName=8.8.8.8 \
  --set-string nativeEgressRelay.attachment.requiredDestinations[0].purpose=bootstrap \
  --set-string nativeEgressRelay.attachment.requiredDestinations[0].host=nvt-broker.custom-ns.svc.cluster.local \
  --set nativeEgressRelay.attachment.requiredDestinations[0].port=7347 \
  --set-string nativeEgressRelay.attachment.requiredDestinations[1].purpose=control \
  --set-string nativeEgressRelay.attachment.requiredDestinations[1].host=nvt-gateway.custom-ns.svc.cluster.local \
  --set nativeEgressRelay.attachment.requiredDestinations[1].port=7443 \
  >/dev/null 2>"${WORKDIR}/native-relay-server-name.txt"; then
  echo "expected IP-literal native relay TLS server name to fail" >&2
  exit 1
fi
grep -q 'nativeEgressRelay.attachment.relayServerName must be a canonical DNS name' "${WORKDIR}/native-relay-server-name.txt"
for invalid_relay_host in a..b aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.invalid 999.999.999.999 10.0.0.1; do
  if helm template nvt "${CHART}" -n custom-ns -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
    --set nativeEgressRelay.enabled=true \
    --set-string nativeEgressRelay.rolloutRevision=credentials-1 \
    --set egress.networkPolicyCapable=true \
    --set broker.persistence.enabled=true \
    --set broker.guestEnrollment.enabled=true \
    --set-string broker.guestEnrollment.exchangeURL=https://nvt-broker.custom-ns.svc.cluster.local:7347/v1/guest-enrollment/exchange \
    --set-string broker.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment-orchestrator \
    --set executionDrivers.guestEnrollment.enabled=true \
    --set 'executionDrivers.guestEnrollment.registrations={fake-east}' \
    --set-string executionDrivers.guestEnrollment.brokerURL=https://nvt-broker.custom-ns.svc.cluster.local:7347 \
    --set-string executionDrivers.guestEnrollment.serverName=nvt-broker.custom-ns.svc.cluster.local \
    --set-string executionDrivers.guestEnrollment.ca.existingSecret=nvt-broker-tls \
    --set-string executionDrivers.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment-orchestrator \
    --set-string nativeEgressRelay.brokerURL=https://nvt-broker.custom-ns.svc.cluster.local:7347 \
    --set-string nativeEgressRelay.brokerServerName=nvt-broker.custom-ns.svc.cluster.local \
    --set-string nativeEgressRelay.credentials.existingSecret=nvt-native-egress-relay-credentials \
    --set-string nativeEgressRelay.brokerCA.existingSecret=nvt-broker-tls \
    --set-string nativeEgressRelay.data.ingressCIDRs[0]=10.40.0.0/16 \
    --set-string nativeEgressRelay.attachment.relayHost="${invalid_relay_host}" \
    --set-string nativeEgressRelay.attachment.requiredDestinations[0].purpose=bootstrap \
    --set-string nativeEgressRelay.attachment.requiredDestinations[0].host=nvt-broker.custom-ns.svc.cluster.local \
    --set nativeEgressRelay.attachment.requiredDestinations[0].port=7347 \
    --set-string nativeEgressRelay.attachment.requiredDestinations[1].purpose=control \
    --set-string nativeEgressRelay.attachment.requiredDestinations[1].host=nvt-gateway.custom-ns.svc.cluster.local \
    --set nativeEgressRelay.attachment.requiredDestinations[1].port=7443 \
    >/dev/null 2>"${WORKDIR}/native-relay-host.txt"; then
    echo "expected invalid native relay host to fail: ${invalid_relay_host}" >&2
    exit 1
  fi
  grep -q 'nativeEgressRelay.attachment.relayHost must be a canonical DNS name' "${WORKDIR}/native-relay-host.txt"
done
if helm template nvt "${CHART}" -n custom-ns -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set nativeEgressRelay.enabled=true \
  --set-string nativeEgressRelay.rolloutRevision=credentials-1 \
  --set egress.networkPolicyCapable=true \
  --set broker.persistence.enabled=true \
  --set broker.guestEnrollment.enabled=true \
  --set-string broker.guestEnrollment.exchangeURL=https://nvt-broker.custom-ns.svc.cluster.local:7347/v1/guest-enrollment/exchange \
  --set-string broker.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment-orchestrator \
  --set executionDrivers.guestEnrollment.enabled=true \
  --set 'executionDrivers.guestEnrollment.registrations={fake-east}' \
  --set-string executionDrivers.guestEnrollment.brokerURL=https://nvt-broker.custom-ns.svc.cluster.local:7347 \
  --set-string executionDrivers.guestEnrollment.serverName=nvt-broker.custom-ns.svc.cluster.local \
  --set-string executionDrivers.guestEnrollment.ca.existingSecret=nvt-broker-tls \
  --set-string executionDrivers.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment-orchestrator \
  --set-string nativeEgressRelay.brokerURL=https://nvt-broker.custom-ns.svc.cluster.local:7347 \
  --set-string nativeEgressRelay.brokerServerName=nvt-broker.custom-ns.svc.cluster.local \
  --set-string nativeEgressRelay.credentials.existingSecret=nvt-native-egress-relay-credentials \
  --set-string nativeEgressRelay.brokerCA.existingSecret=nvt-broker-tls \
  >/dev/null 2>"${WORKDIR}/native-relay-attachment.txt"; then
  echo "expected native relay without an attachment allowlist to fail" >&2
  exit 1
fi
grep -q 'nativeEgressRelay.attachment.requiredDestinations must contain 2 to 16 exact endpoints' "${WORKDIR}/native-relay-attachment.txt"
if helm template nvt "${CHART}" -n custom-ns --set nativeEgressRelay.enabled=true --set-string nativeEgressRelay.rolloutRevision=test-1 >/dev/null 2>"${WORKDIR}/native-relay-missing.txt"; then
  echo "expected native relay without trusted dependencies to fail" >&2
  exit 1
fi
grep -q 'nativeEgressRelay.enabled requires executionDrivers.guestEnrollment.enabled=true' "${WORKDIR}/native-relay-missing.txt"
if helm template nvt "${CHART}" -n custom-ns --set nativeEgressRelay.enabled=true --set-string nativeEgressRelay.rolloutRevision=INVALID >/dev/null 2>"${WORKDIR}/native-relay-rollout.txt"; then
  echo "expected invalid native relay rollout revision to fail" >&2
  exit 1
fi
grep -q 'nativeEgressRelay.rolloutRevision must be a non-empty canonical rollout epoch' "${WORKDIR}/native-relay-rollout.txt"
if helm template nvt "${CHART}" -n custom-ns \
  --set nativeEgressRelay.enabled=true \
  --set-string nativeEgressRelay.rolloutRevision=test-1 \
  --set-string nativeEgressRelay.initImage.tag=1.36.1 \
  --set-string nativeEgressRelay.initImage.digest= \
  >/dev/null 2>"${WORKDIR}/native-relay-init-image.txt"; then
  echo "expected unpinned native relay init image to fail" >&2
  exit 1
fi
grep -q 'nativeEgressRelay.initImage must use a non-empty repository and canonical sha256 digest' "${WORKDIR}/native-relay-init-image.txt"
if helm template nvt "${CHART}" -n custom-ns -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set nativeEgressRelay.enabled=true --set nativeEgressRelay.replicas=2 >/dev/null 2>"${WORKDIR}/native-relay-replicas.txt"; then
  echo "expected multi-replica native relay to fail" >&2
  exit 1
fi
grep -q 'nativeEgressRelay.replicas must be exactly 1' "${WORKDIR}/native-relay-replicas.txt"
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
  --set gateway.nativeSession.enabled=true \
  --set gateway.nativeSession.port=7443 \
  --set-string gateway.nativeSession.tls.existingSecret=nvt-gateway-native-session-tls \
  --set-string gateway.nativeSession.tls.certificateKey=server.crt \
  --set-string gateway.nativeSession.tls.privateKeyKey=server.key \
  --set-string gateway.nativeSession.brokerURL=https://nvt-broker.custom-ns.svc.cluster.local:7347 \
  --set-string gateway.nativeSession.serverName=nvt-broker.custom-ns.svc.cluster.local \
  --set-string gateway.nativeSession.ca.existingSecret=nvt-broker-tls \
  --set-string gateway.nativeSession.ca.key=ca.crt \
  --set gateway.nativeSession.authenticationTimeoutSeconds=7 \
  --set gateway.nativeSession.revalidationIntervalSeconds=45 \
  --set gateway.nativeWorkspace.enabled=true \
  --set gateway.nativeWorkspace.port=7444 \
  > "${GATEWAY_NATIVE_SESSION_RENDER}"
helm template nvt "${CHART}" -n custom-ns \
  --set gateway.enabled=true \
  --set branding.existingConfigMap=company-agent-branding \
  > "${BRANDING_RENDER}"
for invalid_branding_name in Invalid_Name foo.-bar; do
  if helm template nvt "${CHART}" -n custom-ns \
    --set-string branding.existingConfigMap="${invalid_branding_name}" \
    > /dev/null 2> "${BRANDING_FAILURE}"; then
    echo "expected invalid branding ConfigMap name to fail rendering: ${invalid_branding_name}" >&2
    exit 1
  fi
  grep -q 'branding.existingConfigMap must be a valid Kubernetes ConfigMap name' "${BRANDING_FAILURE}"
done
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
helm template nvt "${CHART}" -n custom-ns \
  --set broker.persistence.enabled=true \
  --set broker.guestEnrollment.enabled=true \
  --set-string broker.guestEnrollment.exchangeURL=https://broker.example.test/v1/guest-enrollment/exchange \
  --set broker.guestEnrollment.orchestratorAuth.existingSecret=nvt-guest-enrollment-orchestrator \
  --set broker.guestEnrollment.orchestratorAuth.tokenKey=control-plane-token \
  > "${BROKER_ENROLLMENT_RENDER}"
helm template nvt "${CHART}" --set namespace.name=nvt > "${NAMESPACE_OVERRIDE_RENDER}"
helm template nvt "${CHART}" --set namespace.create=true --set namespace.name=nvt > "${NAMESPACE_CREATE_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true > "${PRODUCER_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true --set producer.submission.mode=direct > "${PRODUCER_DIRECT_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true \
  --set producer.submission.admissionMode=profiled \
  --set producer.submission.workflow=review-pr \
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
  --set-string producer.agentRun.workspaceDockerSize=30Gi \
  --set producer.agentRun.workspaceStorageClassName=managed-csi \
  > "${PRODUCER_PERSISTENT_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true --set gateway.enabled=true > "${ALL_IMAGES_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true --set gateway.enabled=true \
  --set-string global.imageTag="${TEST_RELEASE_TAG}" >"${SOURCE_GLOBAL_TAG_RENDER}"
helm template nvt "${CHART}" -n custom-ns --set-string global.imageTag="${TEST_RELEASE_TAG}" \
  --set-string operator.image.tag=operator-override \
  --set-string dind.image.tag=dind-override >"${COMPONENT_TAG_RENDER}"
helm package "${CHART}" --app-version "${TEST_RELEASE_TAG}" --destination "${WORKDIR}" >/dev/null
helm template nvt "${WORKDIR}/nvt-${CHART_VERSION}.tgz" -n custom-ns --set producer.enabled=true --set gateway.enabled=true > "${PACKAGED_RELEASE_RENDER}"
helm template nvt "${WORKDIR}/nvt-${CHART_VERSION}.tgz" -n custom-ns -s templates/agentschedule.yaml \
  --set agentSchedule.template.workspace.mode=Ephemeral > "${PACKAGED_SCHEDULE_RENDER}"
bash -n "${ROOT}/scripts/operator-codex-auth-secret.sh"
bash -n "${ROOT}/scripts/github-comments-producer-secret.sh"
bash -n "${ROOT}/scripts/broker-env-secret.sh"
bash -n "${ROOT}/scripts/codex-mediated-proof.sh"

# The manual Codex proof never runs in CI, so at least keep its Make wiring
# honest: the target must exist and must invoke the script it names.
make -C "${ROOT}" -n codex-mediated-proof >"${WORKDIR}/codex-mediated-proof.dry" || {
  echo "make codex-mediated-proof does not resolve" >&2
  exit 1
}
grep -q 'bash scripts/codex-mediated-proof.sh' "${WORKDIR}/codex-mediated-proof.dry" || {
  echo "codex-mediated-proof target does not invoke scripts/codex-mediated-proof.sh" >&2
  exit 1
}
for obsolete_target in phase2-codex-gate phase2b-codex-forward-proxy phase6-real-codex-proof; do
  if make -C "${ROOT}" -n "${obsolete_target}" >/dev/null 2>&1; then
    echo "obsolete phase-named Make target still present: ${obsolete_target}" >&2
    exit 1
  fi
done
bash "${ROOT}/tests/operator/codex-auth-secret/test.sh"
bash "${ROOT}/tests/operator/github-comments-producer-secret/test.sh"
bash "${ROOT}/tests/operator/broker-env-secret/test.sh"
bash -n "${ROOT}/tests/operator/kind/smoke-scheduler-job.sh"
bash -n "${ROOT}/tests/operator/kind/smoke-scheduler-job-test.sh"
bash -n "${ROOT}/tests/operator/kind/kind-command.sh"
bash -n "${ROOT}/tests/operator/kind/producer-kind-targets-test.sh"
bash "${ROOT}/tests/operator/kind/smoke-scheduler-job-test.sh"
bash "${ROOT}/tests/operator/kind/producer-kind-targets-test.sh"
bash "${ROOT}/tests/operator/helm/credential-portal-test.sh"

grep -q 'value: "80,8443"' "${EGRESS_POLICY_RENDER}" || {
  echo "chart did not render configured external TCP ports" >&2
  exit 1
}
grep -q 'value: "10.240.0.0/16,fd00:1234::/48"' "${EGRESS_POLICY_RENDER}" || {
  echo "chart did not render configured IPv4/IPv6 deployment exclusions" >&2
  exit 1
}
grep -A1 'name: NVT_DIND_PROTECTED_CIDRS' "${EGRESS_POLICY_RENDER}" | grep -q '10.240.0.0/16 fd00:1234::/48' || {
  echo "chart did not preserve mixed-family protected CIDRs for DinD validation" >&2
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
missing_resource "${DEFAULT_RENDER}" Deployment nvt-credential-portal
missing_resource "${DEFAULT_RENDER}" Service nvt-credential-portal
missing_resource "${DEFAULT_RENDER}" Role nvt-credential-portal
missing_resource "${DEFAULT_RENDER}" Service nvt-agent-gateway
missing_resource "${DEFAULT_RENDER}" Role nvt-agent-gateway
missing_resource "${DEFAULT_RENDER}" Deployment nvt-github-comments-producer
missing_resource "${DEFAULT_RENDER}" ConfigMap nvt-github-comments-producer
missing_resource "${DEFAULT_RENDER}" ConfigMap nvt-execution-driver-registrations
missing_resource "${DEFAULT_RENDER}" Deployment nvt-native-egress-relay
missing_resource "${DEFAULT_RENDER}" Service nvt-native-egress-relay
missing_resource "${DEFAULT_RENDER}" Service nvt-native-egress-relay-control
missing_resource "${DEFAULT_RENDER}" NetworkPolicy nvt-native-egress-relay
missing_resource "${DEFAULT_RENDER}" ConfigMap nvt-native-egress-attachment
if grep -q 'app.kubernetes.io/component: execution-driver-host\|NVT_EXECUTION_DRIVER_REGISTRATIONS_FILE\|NVT_GUEST_ENROLLMENT_CONFIG_FILE\|nvt-execution-driver-host:' "${DEFAULT_RENDER}"; then
  echo "default render unexpectedly creates or wires an execution-driver host" >&2
  exit 1
fi

for resource in \
  "Deployment nvt-native-egress-relay" \
  "Service nvt-native-egress-relay" \
  "Service nvt-native-egress-relay-control" \
  "NetworkPolicy nvt-native-egress-relay" \
  "ConfigMap nvt-native-egress-relay" \
  "ConfigMap nvt-native-egress-attachment" \
  "ConfigMap nvt-native-egress-publication-client"; do
  read -r kind name <<<"${resource}"
  require_resource "${NATIVE_EGRESS_RELAY_RENDER}" "${kind}" "${name}"
done
python3 - "${NATIVE_EGRESS_RELAY_RENDER}" "${CHART_APP_VERSION}" <<'PY'
import sys, yaml
docs = [doc for doc in yaml.safe_load_all(open(sys.argv[1])) if doc]
version = sys.argv[2]
by = {(doc.get("kind"), doc.get("metadata", {}).get("name")): doc for doc in docs}
deployment = by[("Deployment", "nvt-native-egress-relay")]
pod = deployment["spec"]["template"]["spec"]
assert deployment["spec"]["replicas"] == 1
assert deployment["spec"]["strategy"]["type"] == "Recreate"
assert deployment["spec"]["template"]["metadata"]["annotations"]["nvt.dev/native-egress-rollout-revision"] == "credentials-1"
assert pod["securityContext"]["runAsUser"] == 65532
assert pod["containers"][0]["image"].endswith(":" + version)
assert pod["containers"][0]["securityContext"]["capabilities"]["drop"] == ["ALL"]
assert pod["initContainers"][0]["image"] == "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
assert pod["initContainers"][0]["securityContext"]["runAsUser"] == 0
assert pod["initContainers"][0]["securityContext"]["capabilities"] == {"drop": ["ALL"], "add": ["CHOWN"]}
init_script = pod["initContainers"][0]["args"][0]
assert init_script.index("chmod 0600 /owned/*") < init_script.index("chown 65532:65532 /owned/*")
assert pod["volumes"][1]["emptyDir"]["medium"] == "Memory"
operator = by[("Deployment", "nvt-operator")]
assert operator["spec"]["strategy"]["type"] == "Recreate"
assert operator["spec"]["template"]["metadata"]["annotations"]["nvt.dev/native-egress-rollout-revision"] == "credentials-1"
operator_env = operator["spec"]["template"]["spec"]["containers"][0]["env"]
env = {item["name"]: item.get("value") for item in operator_env}
assert env["NVT_NATIVE_EGRESS_PUBLICATION_CONFIG_FILE"] == "/var/run/nvt-native-egress-publication/config.json"
assert env["NVT_NATIVE_EGRESS_ATTACHMENT_CONFIG_FILE"] == "/var/run/nvt-native-egress-attachment/config.json"
attachment = by[("ConfigMap", "nvt-native-egress-attachment")]
attachment_config = __import__("json").loads(attachment["data"]["config.json"])
assert attachment_config["version"] == 1 and attachment_config["generation"] == 1
assert attachment_config["relayHost"] == "nvt-native-egress-relay.custom-ns.svc.cluster.local"
assert attachment_config["relayServerName"] == attachment_config["relayHost"]
assert attachment_config["requiredDestinations"] == [
    {"purpose": "bootstrap", "host": "nvt-broker.custom-ns.svc.cluster.local", "port": 7347},
    {"purpose": "control", "host": "nvt-gateway.custom-ns.svc.cluster.local", "port": 7443},
]
assert attachment_config["redirect"] == {
    "mode": "capture-tcp", "loopback_address": "127.0.0.1",
    "transparent_tcp_port": 15001, "explicit_connect_port": 15002,
}
operator_volumes = {volume["name"]: volume for volume in operator["spec"]["template"]["spec"]["volumes"]}
attachment_sources = operator_volumes["native-egress-attachment"]["projected"]["sources"]
assert attachment_sources[1]["secret"]["items"] == [{"key": "data-ca.crt", "path": "data-ca.crt"}]
for document in docs:
    if document.get("kind") == "Deployment" and document.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/component") == "execution-driver-host":
        encoded = __import__("json").dumps(document)
        assert "nvt-native-egress-relay-credentials" not in encoded
        assert "NVT_NATIVE_EGRESS_ATTACHMENT_CONFIG_FILE" not in encoded
pod_namespace = next(item for item in operator_env if item["name"] == "POD_NAMESPACE")
assert pod_namespace["valueFrom"]["fieldRef"]["fieldPath"] == "metadata.namespace"
role = by[("Role", "nvt-operator")]
assert any("agentruns" in rule.get("resources", []) and "list" in rule.get("verbs", []) for rule in role["rules"])
for document in docs:
    if document.get("kind") == "ClusterRole":
        assert all("agentruns" not in rule.get("resources", []) for rule in document.get("rules", []))
data = by[("Service", "nvt-native-egress-relay")]
control = by[("Service", "nvt-native-egress-relay-control")]
assert [p["name"] for p in data["spec"]["ports"]] == ["data"]
assert [p["name"] for p in control["spec"]["ports"]] == ["control"]
policy = by[("NetworkPolicy", "nvt-native-egress-relay")]
assert policy["spec"]["policyTypes"] == ["Ingress", "Egress"]
assert policy["spec"]["ingress"][0]["from"][0]["podSelector"]["matchLabels"] == {"app.kubernetes.io/name": "nvt-operator"}
assert policy["spec"]["ingress"][1]["from"][0]["ipBlock"]["cidr"] == "10.40.0.0/16"
render = open(sys.argv[1]).read()
assert "control-token" in render
assert "nvt_rc1_" not in render
assert "loopbackAddress" not in attachment["data"]["config.json"]
PY

python3 - "${EXECUTION_DRIVERS_RENDER}" "${CHART_APP_VERSION}" "${DEFAULT_RENDER}" <<'PY'
import json
import sys
import yaml

documents = [item for item in yaml.safe_load_all(open(sys.argv[1])) if item]
version = sys.argv[2]
default_documents = [item for item in yaml.safe_load_all(open(sys.argv[3])) if item]

def resources(kind):
    return {item["metadata"]["name"]: item for item in documents if item.get("kind") == kind}

deployments = resources("Deployment")
services = resources("Service")
policies = resources("NetworkPolicy")
persistent_volume_claims = resources("PersistentVolumeClaim")
secrets = resources("Secret")
accounts = resources("ServiceAccount")
configmaps = resources("ConfigMap")
default_operator = next(item for item in default_documents if item.get("kind") == "Deployment" and item["metadata"]["name"] == "nvt-operator")
assert "securityContext" not in default_operator["spec"]["template"]["spec"]
assert "strategy" not in default_operator["spec"]
assert "nvt.dev/native-egress-rollout-revision" not in default_operator["spec"]["template"].get("metadata", {}).get("annotations", {})
expected = {"fake-east", "fake-west"}
driver_names = {f"nvt-execution-driver-{name}" for name in expected}
assert driver_names <= deployments.keys()
assert driver_names <= services.keys()
assert driver_names <= policies.keys()
assert driver_names <= secrets.keys()
assert "nvt-execution-driver-fake-east" in accounts
assert "nvt-execution-driver-fake-west" not in accounts
assert persistent_volume_claims["nvt-execution-driver-fake-east"]["spec"]["resources"]["requests"]["storage"] == "20Gi"
assert persistent_volume_claims["nvt-execution-driver-fake-east"]["spec"]["storageClassName"] == "fast-state"
assert "nvt-execution-driver-fake-west" not in persistent_volume_claims
assert deployments["nvt-execution-driver-fake-east"]["spec"]["strategy"] == {"type": "Recreate"}
assert "strategy" not in deployments["nvt-execution-driver-fake-west"]["spec"]

operator_pod = deployments["nvt-operator"]["spec"]["template"]["spec"]
operator_security = operator_pod["securityContext"]
assert operator_security == {
    "runAsNonRoot": True,
    "runAsUser": 65532,
    "runAsGroup": 65532,
    "fsGroup": 65532,
    "fsGroupChangePolicy": "OnRootMismatch",
}
projection = next(volume for volume in operator_pod["volumes"] if volume["name"] == "execution-driver-registrations")["projected"]
assert projection["defaultMode"] == 0o440
operator = operator_pod["containers"][0]
operator_env = {item["name"]: item for item in operator["env"]}
assert operator_env["NVT_EXECUTION_DRIVER_REGISTRATIONS_FILE"]["value"] == "/var/run/nvt-execution-drivers/registrations.json"
operator_text = json.dumps(operator, sort_keys=True)
assert "fake-east-cloud" not in operator_text and "fake-west-cloud" not in operator_text

registry = json.loads(configmaps["nvt-execution-driver-registrations"]["data"]["registrations.json"])
assert registry["version"] == 1
assert {item["name"] for item in registry["registrations"]} == expected
assert len({item["tokenFile"] for item in registry["registrations"]}) == 2
assert len({item["caFile"] for item in registry["registrations"]}) == 2

for name, credential in (("fake-east", "fake-east-cloud"), ("fake-west", "fake-west-cloud")):
    pod = deployments[f"nvt-execution-driver-{name}"]["spec"]["template"]["spec"]
    assert len(pod["containers"]) == 1 and len(pod["initContainers"]) == 1
    init = pod["initContainers"][0]
    assert init["image"] == f"ghcr.io/mirkosekulic/nvt-execution-driver-host:{version}"
    container = pod["containers"][0]
    assert container["image"].endswith("@sha256:" + "a" * 64)
    assert container["command"] == ["/nvt-host/nvt-execution-driver-host"]
    if name == "fake-east":
        assert "--pass-env=WORKLOAD_IDENTITY_TOKEN_FILE" in container["args"]
        assert "--pass-env=NVT_EXECUTION_DRIVER_STATE_DIR" in container["args"]
        assert next(item for item in container["env"] if item["name"] == "NVT_EXECUTION_DRIVER_STATE_DIR")["value"] == "/var/lib/nvt-execution-driver"
        assert next(item for item in container["volumeMounts"] if item["name"] == "driver-state")["mountPath"] == "/var/lib/nvt-execution-driver"
        assert next(item for item in pod["volumes"] if item["name"] == "driver-state")["persistentVolumeClaim"]["claimName"] == "nvt-execution-driver-fake-east"
    else:
        assert not any(item == "--pass-env=NVT_EXECUTION_DRIVER_STATE_DIR" for item in container["args"])
        assert all(item["name"] != "driver-state" for item in container["volumeMounts"])
    env = {item["name"]: item for item in container["env"]}
    assert env["CLOUD_TOKEN"]["valueFrom"]["secretKeyRef"]["name"] == credential
    other = "fake-west-cloud" if name == "fake-east" else "fake-east-cloud"
    assert other not in json.dumps(pod, sort_keys=True)
    assert pod["automountServiceAccountToken"] is False
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    startup = container["startupProbe"]
    assert startup["httpGet"] == {"path": "/readyz", "port": "https", "scheme": "HTTPS"}
    assert startup["periodSeconds"] * startup["failureThreshold"] >= 60
    assert startup["timeoutSeconds"] == 2
    assert policies[f"nvt-execution-driver-{name}"]["spec"]["ingress"][0]["from"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/name"] == "nvt-operator"

assert deployments["nvt-execution-driver-fake-east"]["spec"]["template"]["spec"]["serviceAccountName"] == "nvt-execution-driver-fake-east"
assert deployments["nvt-execution-driver-fake-west"]["spec"]["template"]["spec"]["serviceAccountName"] == "fake-west-workload-identity"
PY

python3 - "${EXECUTION_DRIVER_EXISTING_STORAGE_RENDER}" <<'PY'
import sys
import yaml

documents = [item for item in yaml.safe_load_all(open(sys.argv[1])) if item]
assert not any(item.get("kind") == "PersistentVolumeClaim" and item["metadata"]["name"] == "nvt-execution-driver-fake-east" for item in documents)
deployment = next(item for item in documents if item.get("kind") == "Deployment" and item["metadata"]["name"] == "nvt-execution-driver-fake-east")
volume = next(item for item in deployment["spec"]["template"]["spec"]["volumes"] if item["name"] == "driver-state")
assert volume["persistentVolumeClaim"]["claimName"] == "existing-driver-state"
PY

python3 - "${EXECUTION_DRIVER_ENROLLMENT_RENDER}" <<'PY'
import json
import sys
import yaml

documents = [item for item in yaml.safe_load_all(open(sys.argv[1])) if item]
deployments = {item["metadata"]["name"]: item for item in documents if item.get("kind") == "Deployment"}
configmaps = {item["metadata"]["name"]: item for item in documents if item.get("kind") == "ConfigMap"}
operator = deployments["nvt-operator"]["spec"]["template"]["spec"]
operator_template = deployments["nvt-operator"]["spec"]["template"]
container = operator["containers"][0]
environment = {item["name"]: item for item in container["env"]}
assert environment["NVT_GUEST_ENROLLMENT_CONFIG_FILE"]["value"] == "/var/run/nvt-guest-enrollment/config.json"
assert len(operator_template["metadata"]["annotations"]["checksum/guest-enrollment-client"]) == 64
config = json.loads(configmaps["nvt-guest-enrollment-client"]["data"]["config.json"])
assert config == {
    "version": 1,
    "baseURL": "https://nvt-broker.custom-ns.svc:7347",
    "serverName": "nvt-broker.custom-ns.svc",
    "caFile": "/var/run/nvt-guest-enrollment/ca.crt",
    "bearerTokenFile": "/var/run/nvt-guest-enrollment/orchestrator-token",
    "requestTimeoutSeconds": 30,
    "handoffTimeoutSeconds": 30,
    "ttlSeconds": 300,
    "driverRegistrations": ["fake-east"],
}
volume = next(item for item in operator["volumes"] if item["name"] == "guest-enrollment-client")
assert volume["projected"]["defaultMode"] == 0o440
projection_text = json.dumps(volume, sort_keys=True)
assert "nvt-broker-tls" in projection_text and "nvt-enrollment-orchestrator" in projection_text and "control-token" in projection_text
assert "orchestrator-token-" not in projection_text
east_args = deployments["nvt-execution-driver-fake-east"]["spec"]["template"]["spec"]["containers"][0]["args"]
west_args = deployments["nvt-execution-driver-fake-west"]["spec"]["template"]["spec"]["containers"][0]["args"]
assert "--enrollment-socket=/tmp/nvt-guest-enrollment.sock" in east_args
assert "--enrollment-timeout=30s" in east_args
assert "--enrollment-socket=/tmp/nvt-guest-enrollment.sock" not in west_args
assert not any(item.startswith("--enrollment-timeout=") for item in west_args)
for args in (east_args, west_args):
    assert not any(item.startswith("--operation-timeout=") for item in args)
PY

for invalid_enrollment_registrations in \
  '--set executionDrivers.guestEnrollment.registrations[0]=missing' \
  '--set executionDrivers.guestEnrollment.registrations[0]=fake-east --set executionDrivers.guestEnrollment.registrations[1]=fake-east'; do
  read -r -a registration_args <<< "${invalid_enrollment_registrations}"
  if helm template nvt "${CHART}" -n custom-ns \
    -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
    --set executionDrivers.guestEnrollment.enabled=true \
    --set-string executionDrivers.guestEnrollment.brokerURL=https://nvt-broker.custom-ns.svc:7347 \
    --set-string executionDrivers.guestEnrollment.serverName=nvt-broker.custom-ns.svc \
    --set-string executionDrivers.guestEnrollment.ca.existingSecret=nvt-broker-tls \
    --set-string executionDrivers.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment-orchestrator \
    "${registration_args[@]}" > /dev/null 2> "${EXECUTION_DRIVER_FAILURE}"; then
    echo "expected invalid guest enrollment registration selection to fail: ${invalid_enrollment_registrations}" >&2
    exit 1
  fi
done

for enrollment_failure in \
  '--set executionDrivers.guestEnrollment.enabled=true' \
  '--set executionDrivers.guestEnrollment.enabled=true --set-string executionDrivers.guestEnrollment.brokerURL=http://broker.example --set-string executionDrivers.guestEnrollment.serverName=broker.example --set-string executionDrivers.guestEnrollment.ca.existingSecret=ca --set-string executionDrivers.guestEnrollment.orchestratorAuth.existingSecret=auth' \
  '--set executionDrivers.guestEnrollment.enabled=true --set-string executionDrivers.guestEnrollment.brokerURL=https://broker.example:99999 --set-string executionDrivers.guestEnrollment.serverName=broker.example --set-string executionDrivers.guestEnrollment.ca.existingSecret=ca --set-string executionDrivers.guestEnrollment.orchestratorAuth.existingSecret=auth'; do
  read -r -a enrollment_args <<< "${enrollment_failure}"
  if helm template nvt "${CHART}" -n custom-ns -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" "${enrollment_args[@]}" > /dev/null 2> "${EXECUTION_DRIVER_FAILURE}"; then
    echo "expected invalid execution-driver guest enrollment configuration to fail: ${enrollment_failure}" >&2
    exit 1
  fi
done

if [[ "$(id -u)" == "0" ]]; then
  ELEVATE=()
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  ELEVATE=(sudo -n)
else
  echo "operator projection readability test requires root or passwordless sudo" >&2
  exit 1
fi
"${ELEVATE[@]}" python3 - <<'PY'
import os
import shutil
import tempfile

directory = tempfile.mkdtemp(prefix="nvt-operator-projection-")
try:
    os.chown(directory, 0, 65532)
    os.chmod(directory, 0o750)
    paths = []
    for name in ("registrations.json", "ca.crt", "auth-token", "gateway-tls.crt", "gateway-tls.key", "gateway-broker-ca.crt"):
        path = os.path.join(directory, name)
        with open(path, "wb") as value:
            value.write(name.encode())
        os.chown(path, 0, 65532)
        os.chmod(path, 0o440)
        paths.append(path)

    child = os.fork()
    if child == 0:
        try:
            os.setgroups([])
            os.setgid(65532)
            os.setuid(65532)
            for path in paths:
                with open(path, "rb") as value:
                    if not value.read():
                        raise RuntimeError("empty projected file")
        except BaseException:
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    if status != 0:
        raise SystemExit("UID/GID 65532 could not read group-projected 0440 files")
finally:
    shutil.rmtree(directory)
PY

LONG_DRIVER_NAME="$(printf '%063d' 0 | tr 0 a)"
LONG_DRIVER_RESOURCE="nvt-ed-$(python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:56])' "${LONG_DRIVER_NAME}")"
helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set-string executionDrivers.registrations[0].name="${LONG_DRIVER_NAME}" \
  > "${EXECUTION_DRIVER_LONG_NAME_RENDER}"
grep -q "name: \"${LONG_DRIVER_RESOURCE}\"" "${EXECUTION_DRIVER_LONG_NAME_RENDER}"
grep -q "serviceAccountName: \"${LONG_DRIVER_RESOURCE}\"" "${EXECUTION_DRIVER_LONG_NAME_RENDER}"

if helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set-string executionDrivers.registrations[0].image=registry.example.test/nvt/fake-driver:latest \
  >/dev/null 2>"${EXECUTION_DRIVER_FAILURE}"; then
  echo "floating execution-driver image tag was accepted" >&2
  exit 1
fi
grep -q 'image must be pinned by lowercase sha256 digest' "${EXECUTION_DRIVER_FAILURE}"

if helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set-string executionDrivers.registrations[0].resources.requests.cpu=0 \
  >/dev/null 2>"${EXECUTION_DRIVER_FAILURE}"; then
  echo "zero execution-driver CPU request was accepted" >&2
  exit 1
fi
grep -q 'resources.requests.cpu must be a positive Kubernetes quantity' "${EXECUTION_DRIVER_FAILURE}"

if helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set-string executionDrivers.registrations[0].resources.limits.memory=-1Gi \
  >/dev/null 2>"${EXECUTION_DRIVER_FAILURE}"; then
  echo "negative execution-driver memory limit was accepted" >&2
  exit 1
fi
grep -q 'resources.limits.memory must be a positive Kubernetes quantity' "${EXECUTION_DRIVER_FAILURE}"

if helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set-string executionDrivers.registrations[0].resources.requests.cpu=2 \
  >/dev/null 2>"${EXECUTION_DRIVER_FAILURE}"; then
  echo "execution-driver CPU request above its limit was accepted" >&2
  exit 1
fi
grep -q 'resource requests must not exceed limits' "${EXECUTION_DRIVER_FAILURE}"

if helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set-string executionDrivers.registrations[0].resources.requests.memory=1Gi \
  --set-string executionDrivers.registrations[0].resources.limits.memory=512Mi \
  >/dev/null 2>"${EXECUTION_DRIVER_FAILURE}"; then
  echo "execution-driver memory request above its limit was accepted" >&2
  exit 1
fi
grep -q 'resource requests must not exceed limits' "${EXECUTION_DRIVER_FAILURE}"

LARGE_DRIVER_ARGUMENT="$(python3 -c 'print("x" * 16384)')"
if helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set-string executionDrivers.registrations[0].command[1]="${LARGE_DRIVER_ARGUMENT}" \
  >/dev/null 2>"${EXECUTION_DRIVER_FAILURE}"; then
  echo "oversized execution-driver command was accepted" >&2
  exit 1
fi
grep -q 'command exceeds the 16 KiB aggregate bound' "${EXECUTION_DRIVER_FAILURE}"

if helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set-string executionDrivers.registrations[0].passEnv[1]=NVT_EXECUTION_DRIVER_STATE_DIR \
  >/dev/null 2>"${EXECUTION_DRIVER_FAILURE}"; then
  echo "reserved execution-driver state environment was accepted" >&2
  exit 1
fi
grep -q 'environment allowlist contains an invalid name' "${EXECUTION_DRIVER_FAILURE}"

if helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set-string executionDrivers.registrations[1].name=fake-east \
  >/dev/null 2>"${EXECUTION_DRIVER_FAILURE}"; then
  echo "duplicate execution-driver registration was accepted" >&2
  exit 1
fi
grep -q 'registration names must be unique' "${EXECUTION_DRIVER_FAILURE}"

if helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set executionDrivers.registrations[0].serviceAccount.create=false \
  --set-string executionDrivers.registrations[0].serviceAccount.name=fake-west-workload-identity \
  >/dev/null 2>"${EXECUTION_DRIVER_FAILURE}"; then
  echo "shared execution-driver ServiceAccount was accepted" >&2
  exit 1
fi
grep -q 'registrations must use distinct ServiceAccounts' "${EXECUTION_DRIVER_FAILURE}"

if helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set-string executionDrivers.registrations[0].serviceAccount.podLabels.app\\.kubernetes\\.io/name=other-driver \
  >/dev/null 2>"${EXECUTION_DRIVER_FAILURE}"; then
  echo "reserved execution-driver workload label was accepted" >&2
  exit 1
fi
grep -q 'workload-identity Pod label uses a reserved key' "${EXECUTION_DRIVER_FAILURE}"

if helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set-string executionDrivers.registrations[0].storage.size=512Mi \
  >/dev/null 2>"${EXECUTION_DRIVER_FAILURE}"; then
  echo "undersized execution-driver storage was accepted" >&2
  exit 1
fi
grep -q 'storage.size must be between 1Gi and 1Ti' "${EXECUTION_DRIVER_FAILURE}"

if helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set-string executionDrivers.registrations[0].storage.existingClaim=driver-state \
  >/dev/null 2>"${EXECUTION_DRIVER_FAILURE}"; then
  echo "ambiguous execution-driver storage was accepted" >&2
  exit 1
fi
grep -q 'existing storage claim is invalid' "${EXECUTION_DRIVER_FAILURE}"

if helm template nvt "${CHART}" -n custom-ns \
  -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml" \
  --set-string executionDrivers.registrations[0].storage.size= \
  --set-string executionDrivers.registrations[0].storage.storageClassName= \
  --set-string executionDrivers.registrations[0].storage.existingClaim=shared-driver-state \
  --set-string executionDrivers.registrations[1].storage.existingClaim=shared-driver-state \
  >/dev/null 2>"${EXECUTION_DRIVER_FAILURE}"; then
  echo "shared execution-driver existing storage claim was accepted" >&2
  exit 1
fi
grep -q 'registrations must use distinct existing storage claims' "${EXECUTION_DRIVER_FAILURE}"
if grep -q 'NVT_BRANDING_CONFIGMAP\|NVT_GATEWAY_BRANDING_DIR\|name: nvt-branding' "${DEFAULT_RENDER}"; then
  echo "default render unexpectedly enables custom branding" >&2
  exit 1
fi

grep -A1 'name: NVT_BRANDING_CONFIGMAP' "${BRANDING_RENDER}" | grep -q 'company-agent-branding'
grep -A1 'name: NVT_GATEWAY_BRANDING_DIR' "${BRANDING_RENDER}" | grep -q '/usr/local/share/nvt-agent/branding'
grep -A2 'name: nvt-branding' "${BRANDING_RENDER}" | grep -q 'configMap:'
grep -q 'name: "company-agent-branding"' "${BRANDING_RENDER}"
[[ "$(grep -c 'name: nvt-branding' "${BRANDING_RENDER}")" -eq 2 ]]
for key in nvt-agent-mark.svg favicon.ico nvt-agent-mark-64.png nvt-agent-mark-192.png nvt-agent-mark-512.png; do
  [[ "$(grep -Fc "key: ${key}" "${BRANDING_RENDER}")" -eq 1 ]] || {
    echo "expected branding key ${key} exactly once in gateway projection" >&2
    exit 1
  }
done
grep -Fq 'branding:' "${CHART}/README.md"
grep -Fq 'existingConfigMap: company-agent-branding' "${CHART}/README.md"
grep -Fq 'nvt-agent-mark-512.png' "${CHART}/README.md"

for image in \
  nvt-agent-runtime \
  nvt-dind \
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
grep -A1 'name: NVT_DIND_IMAGE' "${ALL_IMAGES_RENDER}" | grep -q "ghcr.io/mirkosekulic/nvt-dind:${CHART_APP_VERSION}"
grep -A1 'name: NVT_DIND_IMAGE_PULL_POLICY' "${ALL_IMAGES_RENDER}" | grep -q 'IfNotPresent'
grep -A1 'name: NVT_DIND_PROTECTED_CIDRS' "${ALL_IMAGES_RENDER}" | grep -q '127.0.0.0/8 169.254.0.0/16'
grep -q 'ghcr.io/mirkosekulic/nvt-operator:operator-override' "${COMPONENT_TAG_RENDER}"
grep -q 'ghcr.io/mirkosekulic/nvt-dind:dind-override' "${COMPONENT_TAG_RENDER}"
for image in \
  nvt-agent-runtime \
  nvt-dind \
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
  nvt-dind \
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
grep -A10 'executionClasses:' "${PROFILE_RENDER}" | grep -q 'name: vm-standard'
grep -A10 'executionClasses:' "${PROFILE_RENDER}" | grep -q 'driver: example-vm'
grep -A10 'executionClasses:' "${PROFILE_RENDER}" | grep -q 'isolation: required'
grep -A3 '^      execution:' "${PROFILE_RENDER}" | grep -q 'kind: pod'
grep -A3 '^      execution:' "${PROFILE_RENDER}" | grep -q 'driver: kubernetes'
grep -q 'provider: codex-main' "${PROFILE_RENDER}"
grep -q 'provider: github-main-app' "${PROFILE_RENDER}"
grep -q 'egressMaxConcurrentTunnels: 512' "${PROFILE_RENDER}"
grep -A5 'capabilities:' "${PROFILE_RENDER}" | grep -q 'SYS_PTRACE'
grep -A4 'requiredNetworks:' "${PROFILE_RENDER}" | grep -q 'name: kind'
grep -A4 'requiredNetworks:' "${PROFILE_RENDER}" | grep -q 'subnet: 172.31.250.0/24'
grep -A8 'docker:' "${PROFILE_RENDER}" | grep -q 'kernelLogDevice: true'
grep -q 'onNoMatch: useDefault' "${PROFILE_RENDER}"
grep -q 'system:serviceaccount:custom-ns:producer' "${PROFILE_RENDER}"
grep -q 'name: implement-pr' "${PROFILE_RENDER}"
grep -q 'name: review-pr' "${PROFILE_RENDER}"
grep -q 'defaultWorkflow: implement-pr' "${PROFILE_RENDER}"
grep -A3 'workflows:' "${PROFILE_RENDER}" | grep -q 'implement-pr'
grep -A3 'workflows:' "${PROFILE_RENDER}" | grep -q 'review-pr'
grep -q 'runtimeClassName: kata-vm-isolation' "${PROFILE_RENDER}"
grep -A6 'resources:' "${PROFILE_RENDER}" | grep -q 'cpu: "2"'
grep -A6 'resources:' "${PROFILE_RENDER}" | grep -q 'memory: 8Gi'
grep -A5 'tolerations:' "${PROFILE_RENDER}" | grep -q 'key: purpose'
grep -A5 'tolerations:' "${PROFILE_RENDER}" | grep -q 'operator: Equal'
grep -A5 'tolerations:' "${PROFILE_RENDER}" | grep -q 'value: nvt-agent'
grep -A5 'tolerations:' "${PROFILE_RENDER}" | grep -q 'effect: NoSchedule'
grep -A5 'workspace:' "${PROFILE_RENDER}" | grep -q 'mode: Persistent'
grep -A5 'workspace:' "${PROFILE_RENDER}" | grep -q 'size: 20Gi'
grep -A5 'workspace:' "${PROFILE_RENDER}" | grep -q 'dockerSize: 30Gi'
grep -A5 'workspace:' "${PROFILE_RENDER}" | grep -q 'storageClassName: managed-csi'
grep -A3 'preparations:' "${PROFILE_RENDER}" | grep -q 'operation: identity'
grep -A3 'workspaceInstructions: |' "${PROFILE_RENDER}" | grep -q 'Follow the administrator-owned repository workflow.'
grep -A3 'workspaceInstructions: |' "${PROFILE_RENDER}" | grep -q 'Keep changes focused and run repository checks.'
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
if grep -q 'native-session\|native-workspace\|NVT_GATEWAY_NATIVE_SESSION\|NVT_GATEWAY_NATIVE_WORKSPACE\|/var/run/nvt-agent/native-session' "${GATEWAY_RENDER}"; then
  echo "default gateway rendering unexpectedly enabled native sessions" >&2
  exit 1
fi

python3 - "${GATEWAY_NATIVE_SESSION_RENDER}" <<'PY'
import sys
import yaml

documents = [item for item in yaml.safe_load_all(open(sys.argv[1])) if item]
deployment = next(item for item in documents if item.get("kind") == "Deployment" and item["metadata"]["name"] == "nvt-agent-gateway")
service = next(item for item in documents if item.get("kind") == "Service" and item["metadata"]["name"] == "nvt-agent-gateway")
pod = deployment["spec"]["template"]["spec"]
assert pod["securityContext"] == {
    "runAsNonRoot": True,
    "runAsUser": 65532,
    "runAsGroup": 65532,
    "fsGroup": 65532,
    "fsGroupChangePolicy": "OnRootMismatch",
    "seccompProfile": {"type": "RuntimeDefault"},
}
volumes = {item["name"]: item for item in pod["volumes"]}
assert volumes["native-session-tls"]["secret"] == {
    "secretName": "nvt-gateway-native-session-tls",
    "defaultMode": 0o440,
    "items": [{"key": "server.crt", "path": "tls.crt"}, {"key": "server.key", "path": "tls.key"}],
}
assert volumes["native-session-broker-ca"]["secret"] == {
    "secretName": "nvt-broker-tls",
    "defaultMode": 0o440,
    "items": [{"key": "ca.crt", "path": "ca.crt"}],
}
container = pod["containers"][0]
assert container["securityContext"] == {
    "allowPrivilegeEscalation": False,
    "readOnlyRootFilesystem": True,
    "capabilities": {"drop": ["ALL"]},
}
args = container["args"]
for expected in (
    "--native-session-enabled=true",
    "--native-session-listen-addr=:7443",
    "--native-session-broker-url=https://nvt-broker.custom-ns.svc.cluster.local:7347",
    "--native-session-broker-server-name=nvt-broker.custom-ns.svc.cluster.local",
    "--native-session-authentication-timeout-seconds=7",
    "--native-session-revalidation-interval-seconds=45",
    "--native-workspace-enabled=true",
    "--native-workspace-listen-addr=:7444",
):
    assert expected in args
assert not any("credential" in item or "bearer" in item or "token" in item for item in args)
assert {item["name"] for item in container["ports"]} == {"http", "native-session", "native-workspace"}
ports = {item["name"]: item for item in service["spec"]["ports"]}
assert ports["native-session"] == {"name": "native-session", "port": 7443, "targetPort": 7443, "appProtocol": "tls"}
assert ports["native-workspace"] == {"name": "native-workspace", "port": 7444, "targetPort": 7444, "appProtocol": "tls"}
PY

for invalid_workspace_args in \
  '--set gateway.nativeWorkspace.enabled=true' \
  '--set gateway.enabled=true --set gateway.nativeWorkspace.enabled=true' \
  '--set gateway.enabled=true --set gateway.nativeSession.enabled=true --set gateway.nativeWorkspace.enabled=true --set gateway.nativeWorkspace.port=0 --set gateway.nativeSession.tls.existingSecret=tls --set-string gateway.nativeSession.brokerURL=https://broker.example:7347 --set-string gateway.nativeSession.serverName=broker.example --set gateway.nativeSession.ca.existingSecret=ca' \
  '--set gateway.enabled=true --set gateway.nativeSession.enabled=true --set gateway.nativeWorkspace.enabled=true --set gateway.nativeWorkspace.port=7443 --set gateway.nativeSession.tls.existingSecret=tls --set-string gateway.nativeSession.brokerURL=https://broker.example:7347 --set-string gateway.nativeSession.serverName=broker.example --set gateway.nativeSession.ca.existingSecret=ca' \
  '--set gateway.enabled=true --set gateway.nativeSession.enabled=true --set gateway.nativeWorkspace.enabled=true --set gateway.nativeWorkspace.port=8080 --set gateway.nativeSession.tls.existingSecret=tls --set-string gateway.nativeSession.brokerURL=https://broker.example:7347 --set-string gateway.nativeSession.serverName=broker.example --set gateway.nativeSession.ca.existingSecret=ca' \
  '--set gateway.enabled=true --set gateway.nativeSession.enabled=true --set gateway.nativeWorkspace.enabled=true --set gateway.nativeWorkspace.port=80 --set gateway.service.port=80 --set gateway.nativeSession.tls.existingSecret=tls --set-string gateway.nativeSession.brokerURL=https://broker.example:7347 --set-string gateway.nativeSession.serverName=broker.example --set gateway.nativeSession.ca.existingSecret=ca'; do
  if helm template nvt "${CHART}" -n custom-ns ${invalid_workspace_args} > /dev/null 2> "${GATEWAY_NATIVE_SESSION_FAILURE}"; then
    echo "expected invalid gateway native-workspace configuration to fail: ${invalid_workspace_args}" >&2
    exit 1
  fi
done

for invalid_args in \
  '--set gateway.nativeSession.enabled=true' \
  '--set gateway.enabled=true --set gateway.nativeSession.enabled=true --set gateway.replicas=0 --set gateway.nativeSession.tls.existingSecret=tls --set-string gateway.nativeSession.brokerURL=https://broker.example:7347 --set-string gateway.nativeSession.serverName=broker.example --set gateway.nativeSession.ca.existingSecret=ca' \
  '--set gateway.enabled=true --set gateway.nativeSession.enabled=true --set gateway.replicas=2 --set gateway.nativeSession.tls.existingSecret=tls --set-string gateway.nativeSession.brokerURL=https://broker.example:7347 --set-string gateway.nativeSession.serverName=broker.example --set gateway.nativeSession.ca.existingSecret=ca' \
  '--set gateway.enabled=true --set gateway.nativeSession.enabled=true --set gateway.nativeSession.port=8080 --set gateway.nativeSession.tls.existingSecret=tls --set-string gateway.nativeSession.brokerURL=https://broker.example:7347 --set-string gateway.nativeSession.serverName=broker.example --set gateway.nativeSession.ca.existingSecret=ca' \
  '--set gateway.enabled=true --set gateway.nativeSession.enabled=true --set gateway.nativeSession.port=80 --set gateway.service.port=80 --set gateway.nativeSession.tls.existingSecret=tls --set-string gateway.nativeSession.brokerURL=https://broker.example:7347 --set-string gateway.nativeSession.serverName=broker.example --set gateway.nativeSession.ca.existingSecret=ca' \
  '--set gateway.enabled=true --set gateway.nativeSession.enabled=true --set gateway.nativeSession.tls.existingSecret=tls --set-string gateway.nativeSession.brokerURL=http://broker.example:7347 --set-string gateway.nativeSession.serverName=broker.example --set gateway.nativeSession.ca.existingSecret=ca' \
  '--set gateway.enabled=true --set gateway.nativeSession.enabled=true --set gateway.nativeSession.tls.existingSecret=tls --set-string gateway.nativeSession.brokerURL=https://broker.example:99999 --set-string gateway.nativeSession.serverName=broker.example --set gateway.nativeSession.ca.existingSecret=ca' \
  '--set gateway.enabled=true --set gateway.nativeSession.enabled=true --set gateway.nativeSession.tls.existingSecret=tls --set-string gateway.nativeSession.brokerURL=https://broker.example:7347 --set-string gateway.nativeSession.serverName=other.example --set gateway.nativeSession.ca.existingSecret=ca' \
  '--set gateway.enabled=true --set gateway.nativeSession.enabled=true --set gateway.nativeSession.tls.existingSecret=tls --set-string gateway.nativeSession.brokerURL=https://broker.example:7347 --set-string gateway.nativeSession.serverName=broker.example --set gateway.nativeSession.ca.existingSecret=ca --set gateway.nativeSession.authenticationTimeoutSeconds=0' \
  '--set gateway.enabled=true --set gateway.nativeSession.enabled=true --set gateway.nativeSession.tls.existingSecret=tls --set-string gateway.nativeSession.brokerURL=https://broker.example:7347 --set-string gateway.nativeSession.serverName=broker.example --set gateway.nativeSession.ca.existingSecret=ca --set gateway.nativeSession.revalidationIntervalSeconds=61'; do
  if helm template nvt "${CHART}" -n custom-ns ${invalid_args} > /dev/null 2> "${GATEWAY_NATIVE_SESSION_FAILURE}"; then
    echo "expected invalid gateway native-session configuration to fail: ${invalid_args}" >&2
    exit 1
  fi
done

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
grep -A35 'nativeGuestBinding:' "${CHART}/crds/nvt.dev_agentruns.yaml" | grep -q 'guestInstanceID:'
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
if grep -q 'NVT_BROKER_GUEST_ENROLLMENT\|guest-enrollment-orchestrator-auth' "${DEFAULT_RENDER}"; then
  echo "default broker rendering must not enable guest enrollment or project its auth Secret" >&2
  exit 1
fi

require_resource "${BROKER_ENROLLMENT_RENDER}" PersistentVolumeClaim nvt-broker-state
grep -A1 'name: NVT_BROKER_GUEST_ENROLLMENT_ENABLED' "${BROKER_ENROLLMENT_RENDER}" | grep -q 'value: "true"'
grep -A1 'name: NVT_BROKER_GUEST_ENROLLMENT_DB' "${BROKER_ENROLLMENT_RENDER}" | grep -q 'value: /state/guest-enrollment.sqlite3'
grep -A1 'name: NVT_BROKER_GUEST_ENROLLMENT_EXCHANGE_URL' "${BROKER_ENROLLMENT_RENDER}" | grep -q 'value: "https://broker.example.test/v1/guest-enrollment/exchange"'
grep -A1 'name: NVT_BROKER_GUEST_ENROLLMENT_ORCHESTRATOR_TOKEN_FILE' "${BROKER_ENROLLMENT_RENDER}" | grep -q 'value: /guest-enrollment-auth/token'
grep -A1 'name: NVT_BROKER_GUEST_ENROLLMENT_RUNTIME_IDENTITY_HISTORY_CAPACITY' "${BROKER_ENROLLMENT_RENDER}" | grep -q 'value: "2000000"'
grep -q 'secretName: "nvt-guest-enrollment-orchestrator"' "${BROKER_ENROLLMENT_RENDER}"
grep -q 'key: "control-plane-token"' "${BROKER_ENROLLMENT_RENDER}"
grep -q 'defaultMode: 0400' "${BROKER_ENROLLMENT_RENDER}"
grep -q 'mountPath: /guest-enrollment-auth' "${BROKER_ENROLLMENT_RENDER}"
grep -q 'readinessProbe:' "${BROKER_ENROLLMENT_RENDER}"
grep -q 'restart both the broker and operator Deployments' "${CHART}/README.md"
if has_resource "${BROKER_ENROLLMENT_RENDER}" Secret nvt-guest-enrollment-orchestrator; then
  echo "guest enrollment must reference, never create, the orchestrator auth Secret" >&2
  exit 1
fi

for enrollment_failure in \
  '--set broker.guestEnrollment.enabled=true' \
  '--set broker.guestEnrollment.enabled=true --set broker.persistence.enabled=true --set broker.tls.enabled=false' \
  '--set broker.guestEnrollment.enabled=true --set broker.persistence.enabled=true --set-string broker.guestEnrollment.exchangeURL=http://broker.example.test/v1/guest-enrollment/exchange --set broker.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment' \
  '--set broker.guestEnrollment.enabled=true --set broker.persistence.enabled=true --set-string broker.guestEnrollment.exchangeURL=https://broker.example.test:0/v1/guest-enrollment/exchange --set broker.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment' \
  '--set broker.guestEnrollment.enabled=true --set broker.persistence.enabled=true --set-string broker.guestEnrollment.exchangeURL=https://broker.example.test:99999/v1/guest-enrollment/exchange --set broker.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment' \
  '--set broker.guestEnrollment.enabled=true --set broker.persistence.enabled=true --set-string broker.guestEnrollment.exchangeURL=https://broker.example.test/v1/guest-enrollment/exchange --set broker.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment --set broker.guestEnrollment.runtimeIdentityHistoryCapacity=19999' \
  '--set broker.guestEnrollment.enabled=true --set broker.persistence.enabled=true --set-string broker.guestEnrollment.exchangeURL=https://broker.example.test/v1/guest-enrollment/exchange --set broker.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment --set broker.guestEnrollment.runtimeIdentityHistoryCapacity=10000001' \
  '--set broker.guestEnrollment.enabled=true --set broker.persistence.enabled=true --set-string broker.guestEnrollment.exchangeURL=https://broker.example.test/v1/guest-enrollment/exchange --set broker.guestEnrollment.orchestratorAuth.existingSecret=Invalid_Name'; do
  read -r -a enrollment_args <<< "${enrollment_failure}"
  if helm template nvt "${CHART}" -n custom-ns "${enrollment_args[@]}" > /dev/null 2> "${BROKER_ENROLLMENT_FAILURE}"; then
    echo "expected invalid guest enrollment configuration to fail rendering: ${enrollment_failure}" >&2
    exit 1
  fi
done
if ! helm template nvt "${CHART}" -n custom-ns \
  --set broker.guestEnrollment.enabled=true \
  --set broker.persistence.enabled=true \
  --set-string broker.guestEnrollment.exchangeURL=https://broker.example.test:65535/v1/guest-enrollment/exchange \
  --set broker.guestEnrollment.orchestratorAuth.existingSecret=nvt-enrollment \
  > /dev/null 2> "${BROKER_ENROLLMENT_FAILURE}"; then
  echo "expected maximum valid guest enrollment exchange port to render" >&2
  exit 1
fi
if helm template nvt "${CHART}" -n custom-ns \
  --set broker.enabled=false \
  --set broker.guestEnrollment.enabled=true \
  > /dev/null 2> "${BROKER_ENROLLMENT_FAILURE}"; then
  echo "expected guest enrollment with the broker disabled to fail rendering" >&2
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
if grep -Eq 'workspace(Size|DockerSize|StorageClassName):' "${PRODUCER_RENDER}"; then
  echo "ephemeral producer config must omit persistent workspace fields" >&2
  exit 1
fi
grep -q 'workspaceMode: "Persistent"' "${PRODUCER_PERSISTENT_RENDER}"
grep -q 'workspaceSize: "20Gi"' "${PRODUCER_PERSISTENT_RENDER}"
grep -q 'workspaceDockerSize: "30Gi"' "${PRODUCER_PERSISTENT_RENDER}"
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
grep -q 'producer.agentRun.workspaceSize, workspaceDockerSize, and workspaceStorageClassName require workspaceMode Persistent' "${PRODUCER_EPHEMERAL_STORAGE_FAILURE}"
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
grep -q 'workflow: "review-pr"' "${PRODUCER_PROFILED_RENDER}"
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
if helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true \
  --set producer.submission.workflow=review-pr \
  > /dev/null 2> "${WORKDIR}/producer-workflow-mode-failure.txt"; then
  echo "expected producer workflow outside profiled mode to fail rendering" >&2
  exit 1
fi
grep -q 'producer.submission.workflow requires profiled scheduleAdmission mode' "${WORKDIR}/producer-workflow-mode-failure.txt"
if helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true \
  --set producer.submission.admissionMode=profiled \
  --set-string producer.submission.workflow='Review PR' \
  > /dev/null 2> "${WORKDIR}/producer-workflow-name-failure.txt"; then
  echo "expected non-normalized producer workflow to fail rendering" >&2
  exit 1
fi
grep -q 'producer.submission.workflow must be a normalized DNS label' "${WORKDIR}/producer-workflow-name-failure.txt"
if helm template nvt "${CHART}" -n custom-ns --set producer.enabled=true \
  --set producer.submission.admissionMode=profiled \
  --set-string producer.submission.workflow="$(printf 'a%.0s' {1..64})" \
  > /dev/null 2> "${WORKDIR}/producer-workflow-length-failure.txt"; then
  echo "expected oversized producer workflow name to fail rendering" >&2
  exit 1
fi
grep -q 'producer.submission.workflow must be a normalized DNS label' "${WORKDIR}/producer-workflow-length-failure.txt"
if helm template nvt "${CHART}" -n custom-ns \
  --set agentSchedule.workflowProfiles[0].name=review-pr \
  --set agentSchedule.allowedProducers[0]=system:serviceaccount:nvt:legacy \
  > /dev/null 2> "${WORKDIR}/schedule-workflow-migration-failure.txt"; then
  echo "expected mixed workflow and legacy producer authorization to fail rendering" >&2
  exit 1
fi
grep -q 'workflow-enabled agentSchedule requires workflowProfiles and producerPolicies and cannot use legacy allowedProducers' "${WORKDIR}/schedule-workflow-migration-failure.txt"
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
