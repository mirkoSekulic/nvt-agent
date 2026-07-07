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
  SMOKE_TMPDIR="$(mktemp -d)"
  SMOKE_TMPDIR_CREATED=1
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

# deploy_echo_fixture loads and deploys the hermetic upstream echo image
# (tests/fixtures/echo) into the active cluster/namespace. It replaces the
# external httpbin.org dependency: egressd reaches it over plain HTTP on
# port 443 (the port the enforced egressd egress NetworkPolicy allows, since
# Calico evaluates the post-DNAT Pod port). The echo reflects the request so
# a smoke can assert the injected credential arrived and the placeholder did
# not. Reusable by the enforced-egress, quota, and revocation smokes.
ECHO_FIXTURE_NAME="${ECHO_FIXTURE_NAME:-nvt-smoke-echo}"
ECHO_FIXTURE_PORT="${ECHO_FIXTURE_PORT:-443}"

deploy_echo_fixture() {
  log "deploying hermetic echo upstream fixture ${ECHO_FIXTURE_NAME}"
  make -C "${ROOT}" CLUSTER="${CLUSTER}" echo-kind-load
  kubectl_smoke apply -f - <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${ECHO_FIXTURE_NAME}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: ${ECHO_FIXTURE_NAME}
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: ${ECHO_FIXTURE_NAME}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ${ECHO_FIXTURE_NAME}
    spec:
      containers:
        - name: echo
          image: ${ECHO_IMAGE:-nvt-smoke-echo:latest}
          imagePullPolicy: IfNotPresent
          env:
            - name: ECHO_LISTEN
              value: ":${ECHO_FIXTURE_PORT}"
          ports:
            - containerPort: ${ECHO_FIXTURE_PORT}
          readinessProbe:
            httpGet:
              path: /healthz
              port: ${ECHO_FIXTURE_PORT}
            periodSeconds: 2
---
apiVersion: v1
kind: Service
metadata:
  name: ${ECHO_FIXTURE_NAME}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: ${ECHO_FIXTURE_NAME}
spec:
  selector:
    app.kubernetes.io/name: ${ECHO_FIXTURE_NAME}
  ports:
    - name: http
      port: ${ECHO_FIXTURE_PORT}
      targetPort: ${ECHO_FIXTURE_PORT}
YAML
  kubectl_smoke -n "${NAMESPACE}" rollout status "deployment/${ECHO_FIXTURE_NAME}" --timeout="${ROLLOUT_TIMEOUT}"
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
    cat "${SMOKE_TMPDIR}/operator-port-forward.log" >&2 || true
  fi
}

cleanup() {
  local status=$?
  if [[ -n "${PORT_FORWARD_PID:-}" ]]; then
    kill "${PORT_FORWARD_PID}" >/dev/null 2>&1 || true
    wait "${PORT_FORWARD_PID}" >/dev/null 2>&1 || true
  fi
  if [[ "${SMOKE_TMPDIR_CREATED:-0}" == "1" && -n "${SMOKE_TMPDIR:-}" ]]; then
    rm -rf "${SMOKE_TMPDIR}"
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

start_operator_port_forward() {
  # A stale listener on this port (e.g. a leaked port-forward from a prior
  # run pointing at a different cluster) would silently route admissions to
  # the wrong operator. Refuse to proceed if the port is already bound.
  if curl -sS -o /dev/null --max-time 2 "http://127.0.0.1:${PORT_FORWARD_PORT}/" 2>/dev/null; then
    die "localhost:${PORT_FORWARD_PORT} is already serving before port-forward; a stale forward would route admissions to the wrong cluster"
  fi
  log "port-forwarding nvt-operator Service on localhost:${PORT_FORWARD_PORT}"
  kubectl_smoke port-forward -n "${NAMESPACE}" service/nvt-operator "${PORT_FORWARD_PORT}:8082" \
    >"${SMOKE_TMPDIR}/operator-port-forward.log" 2>&1 &
  PORT_FORWARD_PID=$!
  # If the local port was already bound, kubectl exits immediately; catch a
  # dead forward loudly instead of falling through to the wrong endpoint.
  sleep 1
  if ! kill -0 "${PORT_FORWARD_PID}" 2>/dev/null; then
    die "operator port-forward exited immediately: $(cat "${SMOKE_TMPDIR}/operator-port-forward.log")"
  fi
  wait_for_operator_http 30
}

wait_for_operator_http() {
  local timeout_seconds="$1"
  local deadline=$((SECONDS + timeout_seconds))
  local status
  local consecutive=0

  # Require two consecutive 405s: right after a rollout the port-forward can
  # briefly connect to an operator whose admission server is up but still
  # settling, so a single probe is not enough to trust the first admission.
  while (( SECONDS < deadline )); do
    status="$(
      curl -sS -o /dev/null -w '%{http_code}' "$(admission_url)" 2>/dev/null || true
    )"
    if [[ "${status}" == "405" ]]; then
      consecutive=$((consecutive + 1))
      if (( consecutive >= 2 )); then
        return
      fi
    else
      consecutive=0
    fi
    sleep 1
  done
  die "timed out waiting for operator HTTP on localhost:${PORT_FORWARD_PORT}"
}

admission_url() {
  printf 'http://127.0.0.1:%s/v1/schedules/%s/default/admissions' "${PORT_FORWARD_PORT}" "${NAMESPACE}"
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
