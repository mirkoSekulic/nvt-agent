#!/usr/bin/env bash

load_config() {
  KIND_SMOKE_MODE="${KIND_SMOKE_MODE:-${SMOKE_MODE:-kind}}"
  KIND_SMOKE_CASE="${KIND_SMOKE_CASE:-parallel-lifecycle}"
  CLUSTER="${CLUSTER:-nvt-smoke}"
  NAMESPACE="${NAMESPACE:-nvt}"
  CREATE_CLUSTER="${CREATE_CLUSTER:-1}"
  DELETE_CLUSTER="${DELETE_CLUSTER:-0}"
  PORT_FORWARD_PORT="${PORT_FORWARD_PORT:-18082}"
  ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT:-180s}"
  RUN_TIMEOUT_SECONDS="${RUN_TIMEOUT_SECONDS:-300}"
  CLEANUP_TIMEOUT_SECONDS="${CLEANUP_TIMEOUT_SECONDS:-180}"
  KUBECTL_CONTEXT="kind-${CLUSTER}"
  TMPDIR="${TMPDIR:-$(mktemp -d)}"
  PORT_FORWARD_PID="${PORT_FORWARD_PID:-}"
}

log() {
  printf '[operator-kind-smoke] %s\n' "$*"
}

die() {
  printf '[operator-kind-smoke] ERROR: %s\n' "$*" >&2
  exit 1
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required on PATH"
}

require_render_tools() {
  need_command helm
  need_command python3
}

require_kind_tools() {
  need_command docker
  need_command kind
  need_command kubectl
  need_command helm
  need_command curl
  need_command python3
}

require_non_negative_integer() {
  local name="$1"
  local value="$2"
  [[ "${value}" =~ ^[0-9]+$ ]] || die "${name} must be an integer greater than or equal to 0"
}

require_positive_integer() {
  local name="$1"
  local value="$2"
  require_non_negative_integer "${name}" "${value}"
  [[ "${value}" -ge 1 ]] || die "${name} must be greater than or equal to 1"
}

kubectl_smoke() {
  kubectl --context "${KUBECTL_CONTEXT}" "$@"
}

diagnostics() {
  local status=$?
  if [[ ${status} -eq 0 || "${KIND_SMOKE_MODE:-kind}" != "kind" ]]; then
    return
  fi

  printf '\n[operator-kind-smoke] diagnostics after failure\n' >&2
  kubectl_smoke get pods,agentruns,agentschedules -n "${NAMESPACE}" -o wide >&2 || true
  kubectl_smoke describe agentschedule default -n "${NAMESPACE}" >&2 || true
  kubectl_smoke get agentruns -n "${NAMESPACE}" -o name 2>/dev/null | while read -r run; do
    kubectl_smoke describe "${run}" -n "${NAMESPACE}" >&2 || true
  done
  kubectl_smoke logs deployment/nvt-operator -n "${NAMESPACE}" --all-containers --tail=200 >&2 || true
  kubectl_smoke logs deployment/nvt-broker -n "${NAMESPACE}" --all-containers --tail=200 >&2 || true
  kubectl_smoke get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=nvt-agent -o name 2>/dev/null | while read -r pod; do
    kubectl_smoke describe "${pod}" -n "${NAMESPACE}" >&2 || true
    kubectl_smoke logs "${pod}" -n "${NAMESPACE}" --all-containers --tail=200 >&2 || true
  done
  if [[ -n "${PORT_FORWARD_PID:-}" ]]; then
    cat "${TMPDIR}/operator-port-forward.log" >&2 || true
  fi
}

cleanup() {
  local status=$?
  if [[ -n "${PORT_FORWARD_PID:-}" ]]; then
    kill "${PORT_FORWARD_PID}" >/dev/null 2>&1 || true
    wait "${PORT_FORWARD_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${TMPDIR:-}" ]]; then
    rm -rf "${TMPDIR}"
  fi
  if [[ "${DELETE_CLUSTER:-0}" == "1" ]]; then
    log "deleting kind cluster ${CLUSTER}"
    kind delete cluster --name "${CLUSTER}" >/dev/null 2>&1 || true
  fi
  return "${status}"
}

validate_common_config() {
  require_non_negative_integer PORT_FORWARD_PORT "${PORT_FORWARD_PORT}"
  require_non_negative_integer RUN_TIMEOUT_SECONDS "${RUN_TIMEOUT_SECONDS}"
  require_non_negative_integer CLEANUP_TIMEOUT_SECONDS "${CLEANUP_TIMEOUT_SECONDS}"
}

validate_chart_render() {
  log "validating Helm chart render"
  helm template nvt "${ROOT}/charts/nvt" -n "${NAMESPACE}" "$@" >/dev/null
  helm lint "${ROOT}/charts/nvt"
}

ensure_cluster() {
  if kind get clusters | grep -Fxq "${CLUSTER}"; then
    log "using existing kind cluster ${CLUSTER}"
    return
  fi

  if [[ "${CREATE_CLUSTER}" != "1" ]]; then
    die "kind cluster ${CLUSTER} does not exist and CREATE_CLUSTER is not 1"
  fi

  log "creating kind cluster ${CLUSTER}"
  kind create cluster --name "${CLUSTER}"
}

build_and_load_images() {
  log "building local images"
  make -C "${ROOT}" runtime-build
  make -C "${ROOT}" broker-build
  make -C "${ROOT}" operator-build

  log "loading local images into kind"
  kind load docker-image nvt-agent-runtime:latest --name "${CLUSTER}"
  kind load docker-image nvt-broker:latest --name "${CLUSTER}"
  kind load docker-image nvt-operator:latest --name "${CLUSTER}"
}

install_chart() {
  log "installing core chart into namespace ${NAMESPACE}"
  helm upgrade --install nvt "${ROOT}/charts/nvt" \
    -n "${NAMESPACE}" \
    --create-namespace \
    --wait \
    --timeout "${ROLLOUT_TIMEOUT}" \
    "$@"

  kubectl_smoke rollout status deployment/nvt-broker -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
  kubectl_smoke rollout status deployment/nvt-operator -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
}

start_operator_port_forward() {
  log "port-forwarding nvt-operator Service on localhost:${PORT_FORWARD_PORT}"
  kubectl_smoke port-forward -n "${NAMESPACE}" service/nvt-operator "${PORT_FORWARD_PORT}:8082" \
    >"${TMPDIR}/operator-port-forward.log" 2>&1 &
  PORT_FORWARD_PID=$!
  wait_for_port "${PORT_FORWARD_PORT}" 30
}

wait_for_port() {
  local port="$1"
  local timeout_seconds="$2"
  local deadline=$((SECONDS + timeout_seconds))
  while (( SECONDS < deadline )); do
    if (echo >"/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  die "timed out waiting for localhost:${port}"
}

admission_url() {
  printf 'http://127.0.0.1:%s/v1/schedules/%s/default/runs' "${PORT_FORWARD_PORT}" "${NAMESPACE}"
}

post_schedule_admission() {
  local body="$1"
  local response="$2"
  local status_file="$3"
  local status

  status="$(
    curl -sS \
      -o "${response}" \
      -w '%{http_code}' \
      -H 'Content-Type: application/json' \
      --data-binary "@${body}" \
      "$(admission_url)"
  )"
  printf '%s\n' "${status}" >"${status_file}"
}

agentrun_phase() {
  local run_name="$1"
  kubectl_smoke get agentrun "${run_name}" -n "${NAMESPACE}" -o jsonpath='{.status.phase}' 2>/dev/null || true
}

wait_for_agentrun_exists() {
  local run_name="$1"
  local deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    if kubectl_smoke get agentrun "${run_name}" -n "${NAMESPACE}" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  die "timed out waiting for AgentRun ${run_name} to exist"
}

wait_for_phase_any() {
  local run_name="$1"
  local timeout_seconds="$2"
  shift 2
  local phases=("$@")
  local deadline=$((SECONDS + timeout_seconds))
  local phase

  while (( SECONDS < deadline )); do
    phase="$(agentrun_phase "${run_name}")"
    for expected in "${phases[@]}"; do
      if [[ "${phase}" == "${expected}" ]]; then
        log "${run_name} reached phase ${phase}"
        return
      fi
    done
    sleep 2
  done
  die "timed out waiting for ${run_name} phase in: ${phases[*]} (last phase: ${phase:-<none>})"
}

wait_for_pod_deleted() {
  local pod_name="$1"
  local timeout_seconds="$2"
  local deadline=$((SECONDS + timeout_seconds))

  while (( SECONDS < deadline )); do
    if ! kubectl_smoke get pod "${pod_name}" -n "${NAMESPACE}" >/dev/null 2>&1; then
      log "${pod_name} was deleted"
      return
    fi
    sleep 2
  done
  die "timed out waiting for ${pod_name} deletion"
}
