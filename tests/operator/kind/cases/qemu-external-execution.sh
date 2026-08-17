#!/usr/bin/env bash

# Real provider-neutral external lifecycle proof using the digest-pinned QEMU
# reference driver, a TCG Linux guest, the production broker enrollment issuer,
# the production native host-bundle bootstrap/supervisor, and a host-owned
# restrict=on network that admits only the attachment's bootstrap/control
# destinations. The ordinary UID-65532 fixture reaches the hermetic upstream
# only through capture -> native relay -> its exact per-run egressd target.

QEMU_EGRESS_FIXTURE_HOST="echo.nvt-fixture.test"

case_validate_config() {
  QEMU_EXECUTION_TIMEOUT_SECONDS="${QEMU_EXECUTION_TIMEOUT_SECONDS:-420}"
  require_positive_integer QEMU_EXECUTION_TIMEOUT_SECONDS "${QEMU_EXECUTION_TIMEOUT_SECONDS}"
  [[ "${NAMESPACE}" == nvt ]] || die "the QEMU TLS fixture requires namespace nvt"
}

case_render() {
  validate_chart_render --set agentSchedule.enabled=false
}

case_kind_setup() {
  make -C "${ROOT}" operator-build execution-driver-host-build broker-build gateway-build egressd-build native-egress-relay-build

  KIND_BUILDX_BUILDER="nvt-kind-qemu-${CLUSTER}"
  docker buildx create --name "${KIND_BUILDX_BUILDER}" --driver docker-container --use >/dev/null
  docker buildx build --builder "${KIND_BUILDX_BUILDER}" --platform "linux/$(go env GOARCH)" \
    -f "${ROOT}/executiondrivers/qemu/Dockerfile" \
    -t nvt.local/qemu-reference-driver:kind \
    --output "type=oci,dest=${SMOKE_TMPDIR}/qemu-driver.oci.tar" "${ROOT}" >/dev/null
  docker buildx rm -f "${KIND_BUILDX_BUILDER}" >/dev/null
  KIND_BUILDX_BUILDER=""

  local digest
  digest="$(tar -xOf "${SMOKE_TMPDIR}/qemu-driver.oci.tar" index.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["manifests"][0]["digest"])')"
  [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || die "QEMU execution-driver archive has no immutable digest"
  QEMU_DRIVER_IMAGE="nvt.local/qemu-reference-driver@${digest}"
  python3 "${ROOT}/tests/operator/kind/extract-oci-file.py" \
    "${SMOKE_TMPDIR}/qemu-driver.oci.tar" /opt/nvt-qemu/guest/digest "${SMOKE_TMPDIR}/guest-digest.txt"
  QEMU_GUEST_DIGEST="$(tr -d '\n' <"${SMOKE_TMPDIR}/guest-digest.txt")"
  [[ "${QEMU_GUEST_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]] || die "QEMU guest artifact digest is invalid"

  local chart_version revision
  chart_version="$(awk -F ': *' '/^appVersion:/ {gsub(/"/, "", $2); print $2}' "${ROOT}/charts/nvt/Chart.yaml")"
  revision="$(git -C "${ROOT}" rev-parse HEAD)"
  docker build -f "${ROOT}/tests/fixtures/host-bundle-registry/Dockerfile" \
    --build-arg "NVT_VERSION=${chart_version}" --build-arg "NVT_REVISION=${revision}" \
    -t nvt-host-bundle-registry:qemu-kind "${ROOT}" >/dev/null
  docker run --rm --entrypoint cat nvt-host-bundle-registry:qemu-kind /fixture/digest.txt >"${SMOKE_TMPDIR}/host-bundle-digest.txt"
  docker run --rm --entrypoint cat nvt-host-bundle-registry:qemu-kind /fixture/tls.crt >"${SMOKE_TMPDIR}/registry-ca.crt"
  docker run --rm --entrypoint cat nvt-host-bundle-registry:qemu-kind /fixture/tls.key >"${SMOKE_TMPDIR}/gateway-tls.key"
  HOST_BUNDLE_DIGEST="$(tr -d '\n' <"${SMOKE_TMPDIR}/host-bundle-digest.txt")"
  [[ "${HOST_BUNDLE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]] || die "host-bundle fixture has no immutable OCI index digest"

  make -C "${ROOT}" CLUSTER="${CLUSTER}" CREATE_CLUSTER="${CREATE_CLUSTER}" \
    ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT}" operator-kind-cluster-enforced
  kind load image-archive "${SMOKE_TMPDIR}/qemu-driver.oci.tar" --name "${CLUSTER}"
  local node
  for node in $(kind get nodes --name "${CLUSTER}"); do
    docker exec "${node}" ctr --namespace k8s.io images tag \
      nvt.local/qemu-reference-driver:kind "${QEMU_DRIVER_IMAGE}" >/dev/null
  done
  kind load docker-image nvt-host-bundle-registry:qemu-kind --name "${CLUSTER}"
  kind load docker-image nvt-operator:latest --name "${CLUSTER}"
  kind load docker-image nvt-execution-driver-host:latest --name "${CLUSTER}"
  kind load docker-image nvt-broker:latest --name "${CLUSTER}"
  kind load docker-image nvt-agent-gateway:latest --name "${CLUSTER}"
  kind load docker-image "${EGRESSD_IMAGE:-nvt-egressd:latest}" --name "${CLUSTER}"
  kind load docker-image "${NATIVE_EGRESS_RELAY_IMAGE:-nvt-native-egress-relay:latest}" --name "${CLUSTER}"

  kubectl_smoke create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl_smoke apply -f -
  kubectl_smoke -n "${NAMESPACE}" create secret generic nvt-gateway-native-session-tls \
    --from-file=tls.crt="${SMOKE_TMPDIR}/registry-ca.crt" \
    --from-file=tls.key="${SMOKE_TMPDIR}/gateway-tls.key" \
    --dry-run=client -o yaml | kubectl_smoke apply -f -
  NATIVE_EGRESS_CONTROL_CANARY='nvt_rc1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
  kubectl_smoke -n "${NAMESPACE}" create secret generic nvt-native-egress-relay-credentials \
    --from-file=data-tls.crt="${SMOKE_TMPDIR}/registry-ca.crt" \
    --from-file=data-tls.key="${SMOKE_TMPDIR}/gateway-tls.key" \
    --from-file=data-ca.crt="${SMOKE_TMPDIR}/registry-ca.crt" \
    --from-file=control-ca.crt="${SMOKE_TMPDIR}/registry-ca.crt" \
    --from-file=control-tls.crt="${SMOKE_TMPDIR}/registry-ca.crt" \
    --from-file=control-tls.key="${SMOKE_TMPDIR}/gateway-tls.key" \
    --from-literal=control-token="${NATIVE_EGRESS_CONTROL_CANARY}" \
    --dry-run=client -o yaml | kubectl_smoke apply -f -
  kubectl_smoke apply -f - <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nvt-host-bundle-registry
  namespace: ${NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels: {app: nvt-host-bundle-registry}
  template:
    metadata:
      labels: {app: nvt-host-bundle-registry}
    spec:
      containers:
        - name: registry
          image: nvt-host-bundle-registry:qemu-kind
          imagePullPolicy: IfNotPresent
          ports: [{name: https, containerPort: 443}]
          readinessProbe:
            tcpSocket: {port: https}
            periodSeconds: 1
---
apiVersion: v1
kind: Service
metadata:
  name: nvt-host-bundle-registry
  namespace: ${NAMESPACE}
spec:
  selector: {app: nvt-host-bundle-registry}
  ports: [{name: https, port: 443, targetPort: https}]
YAML
  kubectl_smoke rollout status deployment/nvt-host-bundle-registry -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"

  ENROLLMENT_ORCHESTRATOR_CANARY='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_'
  kubectl_smoke -n "${NAMESPACE}" create secret generic nvt-enrollment-orchestrator \
    --from-literal="token=${ENROLLMENT_ORCHESTRATOR_CANARY}" \
    --dry-run=client -o yaml | kubectl_smoke apply -f -
  # The guest knows only this non-secret scanner prefix. The complete random
  # provider value remains cluster-side, so any file/argv/environment leak is
  # detected without delivering the expected secret to the guest.
  QEMU_PROVIDER_CANARY="nvt_provider_secret_canary_${RANDOM}_${RANDOM}"
  ECHO_EXPECTED_CREDENTIAL_SHA256="$(printf 'Bearer %s' "${QEMU_PROVIDER_CANARY}" | sha256sum | cut -d' ' -f1)"
  printf 'NVT_SMOKE_STATIC_TOKEN=%s\n' "${QEMU_PROVIDER_CANARY}" | \
    kubectl_smoke -n "${NAMESPACE}" create secret generic nvt-smoke-broker-env \
      --from-env-file=/dev/stdin --dry-run=client -o yaml | kubectl_smoke apply -f -
  cat >"${SMOKE_TMPDIR}/qemu-broker-providers.yaml" <<YAML
broker:
  envSecretName: nvt-smoke-broker-env
  config:
    providers:
      - name: static-bearer-main
        plugin: token
        config: {token-env: NVT_SMOKE_STATIC_TOKEN, injection-hosts: [${QEMU_EGRESS_FIXTURE_HOST}]}
        allow: {repositories: [example/*]}
YAML
  deploy_echo_fixture
  local fixture_label
  fixture_label="$(printf '%s' "${QEMU_EGRESS_FIXTURE_HOST}" | sha256sum | cut -c1-32)"
  kubectl_smoke patch deployment "${ECHO_FIXTURE_NAME}" -n "${NAMESPACE}" --type merge \
    -p '{"spec":{"template":{"metadata":{"labels":{"nvt.dev/egress-host":"'"${fixture_label}"'"}}}}}'
  kubectl_smoke -n "${NAMESPACE}" rollout status "deployment/${ECHO_FIXTURE_NAME}" --timeout="${ROLLOUT_TIMEOUT}"
  install_qemu_fixture_dns_rewrite
  cat >"${SMOKE_TMPDIR}/qemu-values.yaml" <<YAML
agentSchedule:
  enabled: false
operator:
  image: {repository: nvt-operator, tag: latest, pullPolicy: IfNotPresent}
broker:
  image: {repository: nvt-broker, tag: latest, pullPolicy: IfNotPresent}
  envSecretName: nvt-smoke-broker-env
  persistence: {enabled: true, size: 1Gi}
  guestEnrollment:
    enabled: true
    exchangeURL: https://nvt-broker.${NAMESPACE}.svc.cluster.local:7347/v1/guest-enrollment/exchange
    orchestratorAuth: {existingSecret: nvt-enrollment-orchestrator, tokenKey: token}
gateway:
  enabled: true
  image: {repository: nvt-agent-gateway, tag: latest, pullPolicy: IfNotPresent}
  nativeSession:
    enabled: true
    port: 7443
    tls: {existingSecret: nvt-gateway-native-session-tls, certificateKey: tls.crt, privateKeyKey: tls.key}
    brokerURL: https://nvt-broker.${NAMESPACE}.svc.cluster.local:7347
    serverName: nvt-broker.${NAMESPACE}.svc.cluster.local
    ca: {existingSecret: nvt-broker-tls, key: ca.crt}
    authenticationTimeoutSeconds: 5
    revalidationIntervalSeconds: 30
egress:
  egressd:
    image: {repository: nvt-egressd, tag: latest, pullPolicy: IfNotPresent}
  allowInsecureUpstreams: true
  networkPolicyCapable: true
nativeEgressRelay:
  enabled: true
  rolloutRevision: qemu-reference-1
  image: {repository: nvt-native-egress-relay, tag: latest, pullPolicy: IfNotPresent}
  data:
    port: 7445
    ingressCIDRs: [192.168.0.0/16]
  attachment:
    generation: 1
    relayHost: nvt-native-egress-relay.${NAMESPACE}.svc.cluster.local
    relayServerName: nvt-native-egress-relay.${NAMESPACE}.svc.cluster.local
    requiredDestinations:
      - {purpose: bootstrap, host: nvt-broker.${NAMESPACE}.svc.cluster.local, port: 7347}
      - {purpose: bootstrap, host: nvt-host-bundle-registry.${NAMESPACE}.svc.cluster.local, port: 443}
      - {purpose: control, host: nvt-agent-gateway.${NAMESPACE}.svc.cluster.local, port: 7443}
  control:
    port: 7446
    serverName: nvt-native-egress-relay-control.${NAMESPACE}.svc.cluster.local
    timeoutSeconds: 10
  brokerURL: https://nvt-broker.${NAMESPACE}.svc.cluster.local:7347
  brokerServerName: nvt-broker.${NAMESPACE}.svc.cluster.local
  credentials: {existingSecret: nvt-native-egress-relay-credentials}
  brokerCA: {existingSecret: nvt-broker-tls, key: ca.crt}
executionDrivers:
  hostImage: {repository: nvt-execution-driver-host, tag: latest, pullPolicy: IfNotPresent}
  guestEnrollment:
    enabled: true
    registrations: [qemu-reference]
    brokerURL: https://nvt-broker.${NAMESPACE}.svc.cluster.local:7347
    serverName: nvt-broker.${NAMESPACE}.svc.cluster.local
    ca: {existingSecret: nvt-broker-tls, key: ca.crt}
    orchestratorAuth: {existingSecret: nvt-enrollment-orchestrator, tokenKey: token}
    requestTimeoutSeconds: 15
    handoffTimeoutSeconds: 30
    ttlSeconds: 300
  registrations:
    - name: qemu-reference
      image: ${QEMU_DRIVER_IMAGE}
      command: [/usr/local/bin/nvt-qemu-driver]
      resources:
        requests: {cpu: 500m, memory: 512Mi}
        limits: {cpu: "4", memory: 2Gi}
      storage: {size: 2Gi}
      serviceAccount: {create: true}
YAML
  helm upgrade --install nvt "${ROOT}/charts/nvt" --kube-context "${KUBECTL_CONTEXT}" \
    -n "${NAMESPACE}" --timeout "${ROLLOUT_TIMEOUT}" -f "${SMOKE_TMPDIR}/qemu-values.yaml" -f "${SMOKE_TMPDIR}/qemu-broker-providers.yaml"
  kubectl_smoke rollout status deployment/nvt-execution-driver-qemu-reference -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
  kubectl_smoke rollout status deployment/nvt-broker -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
  kubectl_smoke rollout status deployment/nvt-agent-gateway -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
  kubectl_smoke rollout status deployment/nvt-native-egress-relay -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
  kubectl_smoke rollout status deployment/nvt-operator -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
  kubectl_smoke get secret nvt-broker-tls -n "${NAMESPACE}" -o jsonpath='{.data.ca\.crt}' | base64 -d >"${SMOKE_TMPDIR}/broker-ca.crt"
}

install_qemu_fixture_dns_rewrite() {
  local target="${ECHO_FIXTURE_NAME}.${NAMESPACE}.svc.cluster.local" corefile
  corefile="$(kubectl_smoke -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}')"
  if [[ "${corefile}" != *"${QEMU_EGRESS_FIXTURE_HOST}"* ]]; then
    corefile="${corefile/ready/ready
    rewrite name ${QEMU_EGRESS_FIXTURE_HOST} ${target}}"
    kubectl_smoke -n kube-system create configmap coredns \
      --from-literal=Corefile="${corefile}" --dry-run=client -o yaml | kubectl_smoke -n kube-system apply -f -
    kubectl_smoke -n kube-system rollout restart deployment/coredns
    kubectl_smoke -n kube-system rollout status deployment/coredns --timeout="${ROLLOUT_TIMEOUT}"
  fi
}

case_run() {
  python3 - "${SMOKE_TMPDIR}/broker-ca.crt" "${SMOKE_TMPDIR}/registry-ca.crt" \
    "${QEMU_GUEST_DIGEST}" "${HOST_BUNDLE_DIGEST}" "${NAMESPACE}" "${QEMU_EGRESS_FIXTURE_HOST}" <<'PY' | kubectl_smoke apply -f -
import json,sys
broker_ca=open(sys.argv[1]).read()
registry_ca=open(sys.argv[2]).read()
configuration={
  "contract_version":"nvt.qemu-driver/v1",
  "guest_image":{"digest":sys.argv[3]},
  "host_bundle":{"repository":f"https://nvt-host-bundle-registry.{sys.argv[5]}.svc.cluster.local/nvt/host-bundle","digest":sys.argv[4]},
  "registry_ca_pem":registry_ca,
  "enrollment_ca_pem":broker_ca,
  "native_session_endpoint":f"tls://nvt-agent-gateway.{sys.argv[5]}.svc.cluster.local:7443",
  "native_session_ca_pem":registry_ca,
  "native_egress_probe":{"host":sys.argv[6],"port":443,"capability":"static-bearer-main"},
  "cpus":1,"memory_mib":512,"acceleration":"tcg","boot_timeout_seconds":110,
}
run={
  "apiVersion":"nvt.dev/v1alpha1","kind":"AgentRun",
  "metadata":{"name":"qemu-external-lifecycle","namespace":sys.argv[5]},
  "spec":{
    "execution":{"kind":"vm","driver":"qemu-reference","classRef":"qemu-small","configuration":configuration},
    "egress":"mediated","egressEnforcement":True,"egressTransport":"forward-proxy",
    "broker":{"grants":[{
      "provider":"static-bearer-main","repositories":["example/repo"],"materialization":"header-inject",
      "egressHosts":[f"{sys.argv[6]}:443"],"allowInsecureUpstream":True,
    }]},
    "runtime":{"type":"codex","autonomy":"trusted-local"},"image":"unused-for-external-execution",
    "workspace":{"mode":"Ephemeral"},"agent":{"config":{"plugins":[],"tools":{"packages":[],"mise":[],"additional-paths":[],"shell":[]}}},
  },
}
print(json.dumps(run))
PY

  capture_qemu_identity
  wait_for_qemu_running
  assert_no_qemu_agent_pod
  assert_qemu_provider_present
  assert_native_egress_proof
  assert_infrastructure_confinement
  assert_qemu_process_tree_clean
  assert_enrollment_consumed
  assert_sensitive_material_absent

  log "restarting the operator and proving exact publication reconstruction"
  restart_operator_without_overlap
  wait_for_qemu_recovery
  assert_native_egress_proof
  assert_infrastructure_confinement
  assert_qemu_process_tree_clean
  assert_sensitive_material_absent

  log "restarting the QEMU driver host and proving durable TCG guest recovery"
  restart_qemu_driver_without_overlap
  wait_for_qemu_recovery
  assert_qemu_provider_present
  assert_native_egress_proof
  assert_infrastructure_confinement
  assert_qemu_process_tree_clean
  assert_sensitive_material_absent

  log "withdrawing the relay and proving capture readiness fails closed without direct bypass"
  kubectl_smoke scale deployment/nvt-native-egress-relay -n "${NAMESPACE}" --replicas=0
  wait_for_qemu_egress_withdrawal
  assert_qemu_host_fence_live
  kubectl_smoke scale deployment/nvt-native-egress-relay -n "${NAMESPACE}" --replicas=1
  kubectl_smoke rollout status deployment/nvt-native-egress-relay -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
  wait_for_qemu_recovery
  assert_native_egress_proof
  assert_qemu_process_tree_clean

  log "withdrawing the broker and proving relay revalidation fails closed"
  kubectl_smoke scale deployment/nvt-broker -n "${NAMESPACE}" --replicas=0
  wait_for_qemu_egress_withdrawal
  assert_qemu_host_fence_live
  kubectl_smoke scale deployment/nvt-broker -n "${NAMESPACE}" --replicas=1
  kubectl_smoke rollout status deployment/nvt-broker -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
  wait_for_qemu_recovery
  assert_native_egress_proof
  assert_infrastructure_confinement
  assert_qemu_process_tree_clean

  log "revoking the exact guest binding and proving live flows/readiness fail closed"
  revoke_qemu_binding
  wait_for_qemu_egress_withdrawal
  assert_qemu_host_fence_live

  log "deleting the AgentRun and proving exact-driver resource cleanup"
  kubectl_smoke delete agentrun qemu-external-lifecycle -n "${NAMESPACE}" --wait=false
  local deadline=$((SECONDS + QEMU_EXECUTION_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    if ! kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" >/dev/null 2>&1; then
      assert_qemu_provider_absent
      assert_qemu_broker_cleanup
      assert_sensitive_material_absent
      return
    fi
    sleep 2
  done
  die "QEMU AgentRun finalizer did not clear after provider cleanup"
}

qemu_driver_pod() {
  kubectl_smoke get pod -n "${NAMESPACE}" -l nvt.dev/execution-driver-registration=qemu-reference -o jsonpath='{.items[0].metadata.name}'
}

capture_qemu_identity() {
  QEMU_AGENTRUN_UID="$(kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" -o jsonpath='{.metadata.uid}')"
  QEMU_EXECUTION_ID="nvt-agentrun-$(printf '%s' "${QEMU_AGENTRUN_UID}" | sha256sum | awk '{print $1}')"
  QEMU_STATE_KEY="$(printf '%s' "${QEMU_EXECUTION_ID}" | sha256sum | awk '{print $1}')"
}

wait_for_qemu_running() {
  local deadline=$((SECONDS + QEMU_EXECUTION_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    # Infrastructure confinement intentionally makes the portable driver
    # Running/Ready before enrollment is released. Require the independent
    # live guest readiness probe too before treating the reference lifecycle
    # as fully converged.
    if qemu_agentrun_ready && qemu_provider_ready; then
      return
    fi
    sleep 2
  done
  die "real QEMU guest did not reach native agentd/session readiness"
}

case_diagnostics() {
  local pod
  printf '\n[operator-kind-smoke] QEMU lifecycle diagnostics\n' >&2
  kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" -o yaml >&2 || true
  kubectl_smoke logs deployment/nvt-operator -n "${NAMESPACE}" --all-containers --tail=300 >&2 || true
  pod="$(qemu_driver_pod 2>/dev/null || true)"
  if [[ -n "${pod}" ]]; then
    kubectl_smoke describe pod "${pod}" -n "${NAMESPACE}" >&2 || true
    kubectl_smoke logs "${pod}" -n "${NAMESPACE}" -c driver-host --tail=300 >&2 || true
    kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c driver-host -- sh -c \
      'find /var/lib/nvt-execution-driver -maxdepth 3 -type f -not -name guest.qcow2 -print -exec sh -c '\''echo "--- $1"; cat "$1"'\'' sh {} \;' >&2 || true
  fi
  kubectl_smoke logs deployment/nvt-broker -n "${NAMESPACE}" --all-containers --tail=300 >&2 || true
  kubectl_smoke logs deployment/nvt-agent-gateway -n "${NAMESPACE}" --all-containers --tail=300 >&2 || true
  kubectl_smoke logs deployment/nvt-native-egress-relay -n "${NAMESPACE}" --all-containers --tail=300 >&2 || true
  kubectl_smoke get pods,services,networkpolicies -n "${NAMESPACE}" -l nvt.dev/agentrun=qemu-external-lifecycle -o wide >&2 || true
}

restart_qemu_driver_without_overlap() {
  local deployment=nvt-execution-driver-qemu-reference old_uid deadline pods active_uid active_count
  [[ "$(kubectl_smoke get deployment "${deployment}" -n "${NAMESPACE}" -o jsonpath='{.spec.strategy.type}')" == Recreate ]] ||
    die "storage-backed QEMU driver deployment is not Recreate"
  old_uid="$(kubectl_smoke get pod -n "${NAMESPACE}" -l nvt.dev/execution-driver-registration=qemu-reference -o jsonpath='{.items[0].metadata.uid}')"
  kubectl_smoke rollout restart deployment/"${deployment}" -n "${NAMESPACE}"
  deadline=$((SECONDS + QEMU_EXECUTION_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    pods="$(kubectl_smoke get pod -n "${NAMESPACE}" -l nvt.dev/execution-driver-registration=qemu-reference -o json)"
    read -r active_count active_uid < <(python3 -c '
import json,sys
items=[item for item in json.load(sys.stdin)["items"] if not item["metadata"].get("deletionTimestamp")]
print(len(items), items[0]["metadata"]["uid"] if len(items)==1 else "")
' <<<"${pods}")
    if (( active_count > 1 )); then
      die "Recreate rollout permitted overlapping QEMU driver owners"
    fi
    if [[ "${active_count}" == 1 && "${active_uid}" != "${old_uid}" ]] &&
      kubectl_smoke rollout status deployment/"${deployment}" -n "${NAMESPACE}" --timeout=1s >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  die "QEMU driver Recreate rollout did not converge"
}

restart_operator_without_overlap() {
  local deployment=nvt-operator old_uid deadline pods active_uid active_count
  [[ "$(kubectl_smoke get deployment "${deployment}" -n "${NAMESPACE}" -o jsonpath='{.spec.strategy.type}')" == Recreate ]] ||
    die "native-egress publisher deployment is not Recreate"
  old_uid="$(kubectl_smoke get pod -n "${NAMESPACE}" -l app.kubernetes.io/name=nvt-operator -o jsonpath='{.items[0].metadata.uid}')"
  kubectl_smoke rollout restart deployment/"${deployment}" -n "${NAMESPACE}"
  deadline=$((SECONDS + QEMU_EXECUTION_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    pods="$(kubectl_smoke get pod -n "${NAMESPACE}" -l app.kubernetes.io/name=nvt-operator -o json)"
    read -r active_count active_uid < <(python3 -c '
import json,sys
items=[item for item in json.load(sys.stdin)["items"] if not item["metadata"].get("deletionTimestamp")]
print(len(items), items[0]["metadata"]["uid"] if len(items)==1 else "")
' <<<"${pods}")
    if (( active_count > 1 )); then
      die "Recreate rollout permitted overlapping native-egress publishers"
    fi
    if [[ "${active_count}" == 1 && "${active_uid}" != "${old_uid}" ]] &&
      kubectl_smoke rollout status deployment/"${deployment}" -n "${NAMESPACE}" --timeout=1s >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  die "operator Recreate rollout did not converge"
}

wait_for_qemu_recovery() {
  local deadline=$((SECONDS + QEMU_EXECUTION_TIMEOUT_SECONDS)) consecutive=0
  while (( SECONDS < deadline )); do
    if qemu_provider_ready && qemu_agentrun_ready; then
      consecutive=$((consecutive + 1))
      # Span a complete five-second native-session heartbeat interval. This
      # proves the new owner restored durable state, QEMU remains live, and
      # guest readiness is stable rather than a single transient sample.
      if (( consecutive >= 4 )); then
        return
      fi
    else
      consecutive=0
    fi
    sleep 2
  done
  die "QEMU guest did not recover from durable state after driver restart"
}

qemu_agentrun_ready() {
  local phase ready enrollment
  phase="$(kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  ready="$(kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" -o jsonpath='{.status.conditions[?(@.type=="ExternalExecutionReady")].status}' 2>/dev/null || true)"
  enrollment="$(kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" -o jsonpath='{.status.conditions[?(@.type=="ExecutionBackendAvailable")].reason}' 2>/dev/null || true)"
  [[ "${phase}" == Running && "${ready}" == True && "${enrollment}" == ExternalBootstrapAccepted ]]
}

qemu_provider_ready() {
  local pod state host_port
  pod="$(qemu_driver_pod 2>/dev/null)" || return 1
  [[ -n "${pod}" ]] || return 1
  state="$(kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c driver-host -- \
    cat "/var/lib/nvt-execution-driver/executions/${QEMU_STATE_KEY}/state.json" 2>/dev/null)" || return 1
  host_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["host_port"])' <<<"${state}" 2>/dev/null)" || return 1
  [[ "${host_port}" =~ ^[0-9]+$ ]] || return 1
  kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c driver-host -- sh -eu -c \
    'test -f "$1/executions/$2/guest.qcow2"; ps | grep -q "[q]emu-system-x86_64"; wget -q -T 2 -O /dev/null "http://127.0.0.1:$3/ready"' \
    sh /var/lib/nvt-execution-driver "${QEMU_STATE_KEY}" "${host_port}" >/dev/null 2>&1
}

assert_native_egress_proof() {
  local pod state host_port body deadline
  pod="$(qemu_driver_pod)"
  state="$(kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c driver-host -- \
    cat "/var/lib/nvt-execution-driver/executions/${QEMU_STATE_KEY}/state.json")"
  host_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["host_port"])' <<<"${state}")"
  deadline=$((SECONDS + 90))
  while (( SECONDS < deadline )); do
    body="$(kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c driver-host -- \
      wget -q -T 5 -O- "http://127.0.0.1:${host_port}/native-egress-proof" 2>/dev/null || true)"
    if python3 -c '
import json,sys
value=json.load(sys.stdin)
assert value == {"mediated":True,"credential_match":True,"infrastructure_bypass_denied":True,"authority_material_absent":True}
' <<<"${body}" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  die "native VM mediated egress proof is incomplete"
}

assert_infrastructure_confinement() {
  local pod state expected process
  pod="$(qemu_driver_pod)"
  state="$(kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c driver-host -- \
    cat "/var/lib/nvt-execution-driver/executions/${QEMU_STATE_KEY}/state.json")"
  expected="$(python3 -c '
import json,sys
value=json.load(sys.stdin)
attachment=value["native_egress_attachment"]
assert attachment["contract_version"] == "nvt.native-egress-attachment/v1"
assert attachment["digest"].startswith("sha256:")
print(attachment["digest"])
' <<<"${state}")"
  process="$(kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c driver-host -- sh -c 'tr "\000" "\n" </proc/$(pgrep -o qemu-system-x86_64)/cmdline')"
  [[ "${process}" == *"restrict=on"* ]] || die "QEMU host network is not restricted"
  [[ "${process}" == *"guestfwd=tcp:"* ]] || die "QEMU host network has no exact attachment forwards"
  [[ "${process}" != *"${expected}"* && "${process}" != *"BEGIN CERTIFICATE"* ]] || die "attachment trust metadata entered QEMU argv"
  local condition generation digest
  condition="$(kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" -o jsonpath='{.status.conditions[?(@.type=="NativeEgressReady")].status}')"
  generation="$(kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" -o jsonpath='{.status.nativeEgressAttachment.generation}')"
  digest="$(kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" -o jsonpath='{.status.nativeEgressAttachment.digest}')"
  [[ "${condition}" == True && "${generation}" == 1 && "${digest}" == "${expected}" ]] || die "operator did not publish the exact confined attachment"
}

assert_qemu_host_fence_live() {
  local pod process
  pod="$(qemu_driver_pod)"
  process="$(kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c driver-host -- sh -c 'tr "\000" "\n" </proc/$(pgrep -o qemu-system-x86_64)/cmdline')"
  [[ "${process}" == *"restrict=on"* && "${process}" == *"guestfwd=tcp:"* ]] ||
    die "QEMU infrastructure confinement relaxed before provider Delete"
}

revoke_qemu_binding() {
  local broker_pod guest desired_generation
  broker_pod="$(kubectl_smoke get pod -n "${NAMESPACE}" -l app.kubernetes.io/name=nvt-broker -o jsonpath='{.items[0].metadata.name}')"
  guest="$(kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" -o jsonpath='{.status.nativeGuestBinding.guestInstanceID}')"
  desired_generation="$(kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" -o jsonpath='{.status.nativeGuestBinding.desiredGeneration}')"
  [[ -n "${guest}" && "${desired_generation}" =~ ^[1-9][0-9]*$ ]] || die "exact native guest binding is unavailable for revocation"
  kubectl_smoke exec -n "${NAMESPACE}" "${broker_pod}" -c broker -- python3 -c '
import json,ssl,sys,urllib.request
binding={
 "agent_run_uid":sys.argv[1],"execution_id":sys.argv[2],"driver_registration":"qemu-reference",
 "desired_generation":int(sys.argv[3]),"guest_instance_id":sys.argv[4],
}
body=json.dumps({"contract_version":"nvt.guest-enrollment/v1","binding":binding},separators=(",",":")).encode()
token=open("/guest-enrollment-auth/token",encoding="utf-8").read().strip()
request=urllib.request.Request("https://nvt-broker.nvt.svc.cluster.local:7347/v1/guest-enrollment/revoke-binding",data=body,method="POST",headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"})
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile="/tls/ca.crt")))
with opener.open(request,timeout=10) as response:
 assert response.status == 200
' "${QEMU_AGENTRUN_UID}" "${QEMU_EXECUTION_ID}" "${desired_generation}" "${guest}"
}

wait_for_qemu_egress_withdrawal() {
  local pod state host_port deadline
  pod="$(qemu_driver_pod)"
  state="$(kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c driver-host -- \
    cat "/var/lib/nvt-execution-driver/executions/${QEMU_STATE_KEY}/state.json")"
  host_port="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["host_port"])' <<<"${state}")"
  deadline=$((SECONDS + 90))
  while (( SECONDS < deadline )); do
    if ! kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c driver-host -- \
      wget -q -T 2 -O /dev/null "http://127.0.0.1:${host_port}/ready" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  die "guest readiness survived native egress relay withdrawal"
}

assert_no_qemu_agent_pod() {
  if kubectl_smoke get pod qemu-external-lifecycle-agent -n "${NAMESPACE}" >/dev/null 2>&1; then
    die "external QEMU execution unexpectedly created an Agent Pod"
  fi
}

assert_qemu_provider_present() {
  qemu_provider_ready
}

assert_qemu_provider_absent() {
  local pod
  pod="$(qemu_driver_pod)"
  kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c driver-host -- sh -eu -c \
    'test ! -e "$1/executions/$2"; test -z "$(find "$1/executions" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)"; \
     for status in /proc/[0-9]*/status; do snapshot="$(cat "$status" 2>/dev/null)" || continue; name="$(printf "%s\n" "$snapshot" | sed -n "s/^Name:[[:space:]]*//p")"; state="$(printf "%s\n" "$snapshot" | sed -n "s/^State:[[:space:]]*//p")"; \
       case "$name" in qemu-system-*|busybox|tini) case "$state" in Z*) exit 1;; esac;; esac; done; \
     ! ps | grep -q "[q]emu-system-x86_64"' \
    sh /var/lib/nvt-execution-driver "${QEMU_STATE_KEY}"
}

assert_qemu_process_tree_clean() {
  local pod
  pod="$(qemu_driver_pod)"
  kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c driver-host -- sh -eu -c '
    active=0
    for status in /proc/[0-9]*/status; do
      snapshot="$(cat "$status" 2>/dev/null)" || continue
      name="$(printf "%s\n" "$snapshot" | sed -n "s/^Name:[[:space:]]*//p")"
      state="$(printf "%s\n" "$snapshot" | sed -n "s/^State:[[:space:]]*//p")"
      case "$name" in
        qemu-system-*) case "$state" in Z*) exit 1;; *) active=$((active + 1));; esac ;;
        busybox) case "$state" in Z*) exit 1;; esac ;;
        tini) case "$state" in Z*) exit 1;; esac ;;
      esac
    done
    test "$active" -eq 1
  ' || die "QEMU reference left an ambiguous or unreaped process tree"
}

assert_enrollment_consumed() {
  local pod deadline
  pod="$(kubectl_smoke get pod -n "${NAMESPACE}" -l app.kubernetes.io/name=nvt-broker -o jsonpath='{.items[0].metadata.name}')"
  deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    if kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c broker -- python3 -c '
import sqlite3,sys
db=sqlite3.connect("/state/guest-enrollment.sqlite3")
rows=db.execute("SELECT state,runtime_identity_active,token_digest,runtime_identity_digest FROM enrollments WHERE agent_run_uid=? AND execution_id=? AND driver_registration=?",(sys.argv[1],sys.argv[2],"qemu-reference")).fetchall()
assert len(rows)==1 and rows[0][0]=="consumed" and rows[0][1]==1
assert rows[0][2].startswith("sha256:") and rows[0][3].startswith("sha256:")
history=db.execute("SELECT runtime_identity_digest FROM runtime_identity_history WHERE token_digest=?",(rows[0][2],)).fetchall()
assert len(history)>=1 and all(value[0].startswith("sha256:") for value in history)
sessions=db.execute("SELECT credential_digest,audience,expires_at FROM guest_session_credentials WHERE token_digest=?",(rows[0][2],)).fetchall()
assert 1 <= len(sessions) <= 2
assert all(value[0].startswith("sha256:") and value[1]=="nvt.native-guest-control/v1" and value[2] for value in sessions)
' "${QEMU_AGENTRUN_UID}" "${QEMU_EXECUTION_ID}" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  die "native guest runtime identity did not rotate"
}

assert_qemu_broker_cleanup() {
  local pod
  pod="$(kubectl_smoke get pod -n "${NAMESPACE}" -l app.kubernetes.io/name=nvt-broker -o jsonpath='{.items[0].metadata.name}')"
  kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c broker -- python3 -c '
import sqlite3,sys
db=sqlite3.connect("/state/guest-enrollment.sqlite3")
key=(sys.argv[1],sys.argv[2],"qemu-reference")
assert not db.execute("SELECT 1 FROM enrollments WHERE agent_run_uid=? AND execution_id=? AND driver_registration=?",key).fetchall()
assert not db.execute("SELECT 1 FROM guest_session_credentials").fetchall()
assert not db.execute("SELECT 1 FROM native_egress_credentials").fetchall()
row=db.execute("SELECT cleanup_completed_at FROM execution_tombstones WHERE agent_run_uid=? AND execution_id=? AND driver_registration=?",key).fetchone()
assert row is not None and row[0] is not None
' "${QEMU_AGENTRUN_UID}" "${QEMU_EXECUTION_ID}"
}

assert_sensitive_material_absent() {
  local pod run_json logs
  pod="$(qemu_driver_pod)"
  run_json="$(kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" -o json 2>/dev/null || true)"
  logs="$(kubectl_smoke logs -n "${NAMESPACE}" "${pod}" -c driver-host --tail=200 2>/dev/null || true)$(kubectl_smoke logs -n "${NAMESPACE}" deployment/nvt-operator --tail=200 2>/dev/null || true)$(kubectl_smoke logs -n "${NAMESPACE}" deployment/nvt-broker --tail=200 2>/dev/null || true)$(kubectl_smoke logs -n "${NAMESPACE}" deployment/nvt-agent-gateway --tail=200 2>/dev/null || true)$(kubectl_smoke logs -n "${NAMESPACE}" deployment/nvt-native-egress-relay --tail=200 2>/dev/null || true)"
  for needle in "${ENROLLMENT_ORCHESTRATOR_CANARY}" "${NATIVE_EGRESS_CONTROL_CANARY}" "${QEMU_PROVIDER_CANARY}"; do
    [[ "${run_json}${logs}" != *"${needle}"* ]] || die "trusted credential entered status or logs"
  done
  kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c driver-host -- sh -eu -c \
    'if [ -d /var/lib/nvt-execution-driver/executions ]; then for needle in "$1" "$2" "$3"; do ! grep -R -a -F "$needle" /var/lib/nvt-execution-driver/executions >/dev/null 2>&1; done; fi' \
    sh "${ENROLLMENT_ORCHESTRATOR_CANARY}" "${NATIVE_EGRESS_CONTROL_CANARY}" "${QEMU_PROVIDER_CANARY}"
}
