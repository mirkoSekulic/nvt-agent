#!/usr/bin/env bash

# Real provider-neutral external lifecycle proof using the digest-pinned QEMU
# reference driver, a TCG Linux guest, the production broker enrollment issuer,
# and the production native host-bundle bootstrap/supervisor.

case_validate_config() {
  QEMU_EXECUTION_TIMEOUT_SECONDS="${QEMU_EXECUTION_TIMEOUT_SECONDS:-420}"
  require_positive_integer QEMU_EXECUTION_TIMEOUT_SECONDS "${QEMU_EXECUTION_TIMEOUT_SECONDS}"
}

case_render() {
  validate_chart_render --set agentSchedule.enabled=false
}

case_kind_setup() {
  make -C "${ROOT}" operator-build execution-driver-host-build broker-build

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
  HOST_BUNDLE_DIGEST="$(tr -d '\n' <"${SMOKE_TMPDIR}/host-bundle-digest.txt")"
  [[ "${HOST_BUNDLE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]] || die "host-bundle fixture has no immutable OCI index digest"

  make -C "${ROOT}" CLUSTER="${CLUSTER}" CREATE_CLUSTER="${CREATE_CLUSTER}" operator-kind-cluster
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

  kubectl_smoke create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl_smoke apply -f -
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
  cat >"${SMOKE_TMPDIR}/qemu-values.yaml" <<YAML
agentSchedule:
  enabled: false
operator:
  image: {repository: nvt-operator, tag: latest, pullPolicy: IfNotPresent}
broker:
  image: {repository: nvt-broker, tag: latest, pullPolicy: IfNotPresent}
  persistence: {enabled: true, size: 1Gi}
  guestEnrollment:
    enabled: true
    exchangeURL: https://nvt-broker.${NAMESPACE}.svc.cluster.local:7347/v1/guest-enrollment/exchange
    orchestratorAuth: {existingSecret: nvt-enrollment-orchestrator, tokenKey: token}
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
    -n "${NAMESPACE}" --timeout "${ROLLOUT_TIMEOUT}" -f "${SMOKE_TMPDIR}/qemu-values.yaml"
  kubectl_smoke rollout status deployment/nvt-execution-driver-qemu-reference -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
  kubectl_smoke rollout status deployment/nvt-broker -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
  kubectl_smoke rollout status deployment/nvt-operator -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
  kubectl_smoke get secret nvt-broker-tls -n "${NAMESPACE}" -o jsonpath='{.data.ca\.crt}' | base64 -d >"${SMOKE_TMPDIR}/broker-ca.crt"
}

case_run() {
  python3 - "${SMOKE_TMPDIR}/broker-ca.crt" "${SMOKE_TMPDIR}/registry-ca.crt" \
    "${QEMU_GUEST_DIGEST}" "${HOST_BUNDLE_DIGEST}" "${NAMESPACE}" <<'PY' | kubectl_smoke apply -f -
import json,sys
broker_ca=open(sys.argv[1]).read()
registry_ca=open(sys.argv[2]).read()
configuration={
  "contract_version":"nvt.qemu-driver/v1",
  "guest_image":{"digest":sys.argv[3]},
  "host_bundle":{"repository":f"https://nvt-host-bundle-registry.{sys.argv[5]}.svc.cluster.local/nvt/host-bundle","digest":sys.argv[4]},
  "registry_ca_pem":registry_ca,
  "enrollment_ca_pem":broker_ca,
  "cpus":1,"memory_mib":512,"acceleration":"tcg","boot_timeout_seconds":110,
}
run={
  "apiVersion":"nvt.dev/v1alpha1","kind":"AgentRun",
  "metadata":{"name":"qemu-external-lifecycle","namespace":sys.argv[5]},
  "spec":{
    "execution":{"kind":"vm","driver":"qemu-reference","classRef":"qemu-small","configuration":configuration},
    "runtime":{"type":"codex","autonomy":"trusted-local"},"image":"unused-for-external-execution",
    "workspace":{"mode":"Ephemeral"},"agent":{"config":{"plugins":[],"tools":{"packages":[],"mise":[],"additional-paths":[],"shell":[]}}},
  },
}
print(json.dumps(run))
PY

  wait_for_qemu_running
  assert_no_qemu_agent_pod
  capture_qemu_identity
  assert_qemu_provider_present
  assert_enrollment_consumed
  assert_sensitive_material_absent

  log "restarting the QEMU driver host and proving durable TCG guest recovery"
  restart_qemu_driver_without_overlap
  wait_for_qemu_recovery
  assert_qemu_provider_present
  assert_sensitive_material_absent

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
  local deadline=$((SECONDS + QEMU_EXECUTION_TIMEOUT_SECONDS)) phase ready enrollment
  while (( SECONDS < deadline )); do
    phase="$(kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    ready="$(kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" -o jsonpath='{.status.conditions[?(@.type=="ExternalExecutionReady")].status}' 2>/dev/null || true)"
    enrollment="$(kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" -o jsonpath='{.status.conditions[?(@.type=="ExecutionBackendAvailable")].reason}' 2>/dev/null || true)"
    if [[ "${phase}" == Running && "${ready}" == True && "${enrollment}" == ExternalBootstrapAccepted ]]; then
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

wait_for_qemu_recovery() {
  local deadline=$((SECONDS + QEMU_EXECUTION_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    if qemu_provider_ready; then
      wait_for_qemu_running
      return
    fi
    sleep 2
  done
  die "QEMU guest did not recover from durable state after driver restart"
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
    'test ! -e "$1/executions/$2"; test -z "$(find "$1/executions" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)"' \
    sh /var/lib/nvt-execution-driver "${QEMU_STATE_KEY}"
}

assert_enrollment_consumed() {
  local pod
  pod="$(kubectl_smoke get pod -n "${NAMESPACE}" -l app.kubernetes.io/name=nvt-broker -o jsonpath='{.items[0].metadata.name}')"
  kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c broker -- python3 -c '
import sqlite3,sys
db=sqlite3.connect("/state/guest-enrollment.sqlite3")
rows=db.execute("SELECT state,runtime_identity_active,token_digest,runtime_identity_digest FROM enrollments WHERE agent_run_uid=? AND execution_id=? AND driver_registration=?",(sys.argv[1],sys.argv[2],"qemu-reference")).fetchall()
assert len(rows)==1 and rows[0][0]=="consumed" and rows[0][1]==1
assert rows[0][2].startswith("sha256:") and rows[0][3].startswith("sha256:")
' "${QEMU_AGENTRUN_UID}" "${QEMU_EXECUTION_ID}"
}

assert_qemu_broker_cleanup() {
  local pod
  pod="$(kubectl_smoke get pod -n "${NAMESPACE}" -l app.kubernetes.io/name=nvt-broker -o jsonpath='{.items[0].metadata.name}')"
  kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c broker -- python3 -c '
import sqlite3,sys
db=sqlite3.connect("/state/guest-enrollment.sqlite3")
key=(sys.argv[1],sys.argv[2],"qemu-reference")
assert not db.execute("SELECT 1 FROM enrollments WHERE agent_run_uid=? AND execution_id=? AND driver_registration=?",key).fetchall()
row=db.execute("SELECT cleanup_completed_at FROM execution_tombstones WHERE agent_run_uid=? AND execution_id=? AND driver_registration=?",key).fetchone()
assert row is not None and row[0] is not None
' "${QEMU_AGENTRUN_UID}" "${QEMU_EXECUTION_ID}"
}

assert_sensitive_material_absent() {
  local pod run_json logs
  pod="$(qemu_driver_pod)"
  run_json="$(kubectl_smoke get agentrun qemu-external-lifecycle -n "${NAMESPACE}" -o json 2>/dev/null || true)"
  logs="$(kubectl_smoke logs -n "${NAMESPACE}" "${pod}" -c driver-host --tail=200 2>/dev/null || true)$(kubectl_smoke logs -n "${NAMESPACE}" deployment/nvt-operator --tail=200 2>/dev/null || true)$(kubectl_smoke logs -n "${NAMESPACE}" deployment/nvt-broker --tail=200 2>/dev/null || true)"
  [[ "${run_json}${logs}" != *"${ENROLLMENT_ORCHESTRATOR_CANARY}"* ]] || die "orchestrator credential entered status or logs"
  kubectl_smoke exec -n "${NAMESPACE}" "${pod}" -c driver-host -- sh -eu -c \
    'if [ -d /var/lib/nvt-execution-driver/executions ]; then ! grep -R -F "$1" /var/lib/nvt-execution-driver/executions >/dev/null 2>&1; fi' \
    sh "${ENROLLMENT_ORCHESTRATOR_CANARY}"
}
