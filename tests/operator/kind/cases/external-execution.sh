#!/usr/bin/env bash

# Exact end-to-end external execution lifecycle through the chart-managed,
# authenticated driver host. A local OCI archive is imported and named by its
# immutable digest so the hermetic test retains the production pinning contract.

case_validate_config() {
  EXTERNAL_EXECUTION_TIMEOUT_SECONDS="${EXTERNAL_EXECUTION_TIMEOUT_SECONDS:-120}"
  require_positive_integer EXTERNAL_EXECUTION_TIMEOUT_SECONDS "${EXTERNAL_EXECUTION_TIMEOUT_SECONDS}"
}

case_render() {
  validate_chart_render \
    --set agentSchedule.enabled=false \
    -f "${ROOT}/tests/operator/helm/execution-drivers-values.yaml"
}

case_kind_setup() {
  # Build before starting the control-plane so constrained development
  # environments cannot evict the Kind node during a cold Go image build.
  make -C "${ROOT}" operator-build execution-driver-host-build
  KIND_BUILDX_BUILDER="nvt-kind-oci-${CLUSTER}"
  docker buildx create --name "${KIND_BUILDX_BUILDER}" --driver docker-container --use >/dev/null
  docker buildx build --builder "${KIND_BUILDX_BUILDER}" --platform "linux/$(go env GOARCH)" \
    -f "${ROOT}/tests/fixtures/execution-driver/Dockerfile" \
    -t nvt.local/fake-driver:kind \
    --output "type=oci,dest=${SMOKE_TMPDIR}/fake-driver.oci.tar" "${ROOT}" >/dev/null
  docker buildx rm -f "${KIND_BUILDX_BUILDER}" >/dev/null
  KIND_BUILDX_BUILDER=""
  local digest node
  digest="$(tar -xOf "${SMOKE_TMPDIR}/fake-driver.oci.tar" index.json | python3 -c 'import json,sys; print(json.load(sys.stdin)["manifests"][0]["digest"])')"
  [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || die "fake execution-driver OCI archive has no immutable digest"

  make -C "${ROOT}" CLUSTER="${CLUSTER}" CREATE_CLUSTER="${CREATE_CLUSTER}" \
    operator-kind-cluster
  kind load image-archive "${SMOKE_TMPDIR}/fake-driver.oci.tar" --name "${CLUSTER}"
  for node in $(kind get nodes --name "${CLUSTER}"); do
    docker exec "${node}" ctr --namespace k8s.io images tag \
      nvt.local/fake-driver:kind "nvt.local/fake-driver@${digest}" >/dev/null
  done
  EXTERNAL_DRIVER_IMAGE="nvt.local/fake-driver@${digest}"
  [[ "${EXTERNAL_DRIVER_IMAGE}" =~ @sha256:[0-9a-f]{64}$ ]] || die "fake execution driver did not produce a digest-pinned image"

  kind load docker-image nvt-operator:latest --name "${CLUSTER}"
  kind load docker-image nvt-execution-driver-host:latest --name "${CLUSTER}"
  kubectl_smoke create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl_smoke apply -f -
  kubectl_smoke -n "${NAMESPACE}" create secret generic fake-driver-environment \
    --from-literal=state-dir=/tmp/nvt-fake-driver-state \
    --dry-run=client -o yaml | kubectl_smoke apply -f -

  cat >"${SMOKE_TMPDIR}/external-execution-values.yaml" <<YAML
agentSchedule:
  enabled: false
operator:
  image:
    repository: nvt-operator
    tag: latest
    pullPolicy: IfNotPresent
executionDrivers:
  hostImage:
    repository: nvt-execution-driver-host
    tag: latest
    pullPolicy: IfNotPresent
  registrations:
    - name: fake-vm
      image: ${EXTERNAL_DRIVER_IMAGE}
      command: [/fake-driver]
      resources:
        requests: {cpu: 50m, memory: 32Mi}
        limits: {cpu: 500m, memory: 128Mi}
      serviceAccount: {create: true}
      secretEnvironment:
        - name: NVT_FAKE_DRIVER_STATE_DIR
          secretName: fake-driver-environment
          key: state-dir
YAML
  helm upgrade --install nvt "${ROOT}/charts/nvt" \
    --kube-context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" \
    --timeout "${ROLLOUT_TIMEOUT}" -f "${SMOKE_TMPDIR}/external-execution-values.yaml"
  kubectl_smoke rollout status deployment/nvt-execution-driver-fake-vm -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
  kubectl_smoke rollout status deployment/nvt-operator -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
}

case_run() {
  cat <<YAML | kubectl_smoke apply -f -
apiVersion: nvt.dev/v1alpha1
kind: AgentRun
metadata:
  name: external-lifecycle
  namespace: ${NAMESPACE}
spec:
  execution:
    kind: vm
    driver: fake-vm
    classRef: fake-small
    configuration:
      ready: true
      delete_steps: 1
  runtime: {type: codex, autonomy: trusted-local}
  image: unused-for-external-execution
  workspace: {mode: Ephemeral}
  agent:
    config:
      plugins: []
      tools: {packages: [], mise: [], additional-paths: [], shell: []}
YAML
  wait_for_external_running
  assert_no_agent_pod

  log "restarting the operator and proving level-triggered recovery"
  kubectl_smoke rollout restart deployment/nvt-operator -n "${NAMESPACE}"
  kubectl_smoke rollout status deployment/nvt-operator -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
  wait_for_external_running
  assert_no_agent_pod

  log "deleting the external AgentRun and waiting for driver cleanup/finalizer completion"
  kubectl_smoke delete agentrun external-lifecycle -n "${NAMESPACE}" --wait=false
  local deadline=$((SECONDS + EXTERNAL_EXECUTION_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    if ! kubectl_smoke get agentrun external-lifecycle -n "${NAMESPACE}" >/dev/null 2>&1; then
      log "external AgentRun cleanup completed"
      return
    fi
    sleep 2
  done
  die "external AgentRun finalizer did not clear after driver cleanup"
}

wait_for_external_running() {
  local deadline=$((SECONDS + EXTERNAL_EXECUTION_TIMEOUT_SECONDS))
  local phase condition
  while (( SECONDS < deadline )); do
    phase="$(kubectl_smoke get agentrun external-lifecycle -n "${NAMESPACE}" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    condition="$(kubectl_smoke get agentrun external-lifecycle -n "${NAMESPACE}" -o jsonpath='{.status.conditions[?(@.type=="ExternalExecutionReady")].status}' 2>/dev/null || true)"
    if [[ "${phase}" == "Running" && "${condition}" == "True" ]]; then
      return
    fi
    sleep 2
  done
  die "external AgentRun did not reach portable Running/Ready state"
}

assert_no_agent_pod() {
  if kubectl_smoke get pod external-lifecycle-agent -n "${NAMESPACE}" >/dev/null 2>&1; then
    die "external AgentRun unexpectedly created the Kubernetes Agent Pod"
  fi
}
