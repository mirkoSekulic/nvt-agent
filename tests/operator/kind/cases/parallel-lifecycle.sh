#!/usr/bin/env bash

case_validate_config() {
  PARALLELISM="${PARALLELISM:-3}"
  COMPLETED_TTL_SECONDS="${COMPLETED_TTL_SECONDS:-10}"
  ACTIVE_DEADLINE_SECONDS="${ACTIVE_DEADLINE_SECONDS:-600}"
  SMOKE_DELAY_SECONDS="${SMOKE_DELAY_SECONDS:-10}"
  PAYLOAD_PY="${SCRIPT_DIR}/agentrun-payload.py"

  require_positive_integer PARALLELISM "${PARALLELISM}"
  require_non_negative_integer COMPLETED_TTL_SECONDS "${COMPLETED_TTL_SECONDS}"
  require_non_negative_integer ACTIVE_DEADLINE_SECONDS "${ACTIVE_DEADLINE_SECONDS}"
  require_non_negative_integer SMOKE_DELAY_SECONDS "${SMOKE_DELAY_SECONDS}"
}

case_render() {
  validate_payload_generation
  validate_chart_render --set "agentSchedule.maxParallelism=${PARALLELISM}"
}

case_kind_setup() {
  make -C "${ROOT}" \
    CLUSTER="${CLUSTER}" \
    NAMESPACE="${NAMESPACE}" \
    CREATE_CLUSTER="${CREATE_CLUSTER}" \
    ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT}" \
    OPERATOR_KIND_HELM_ARGS="--set agentSchedule.maxParallelism=${PARALLELISM}" \
    operator-kind-setup
}

case_run() {
  submit_parallel_admissions
  assert_overflow_rejected
  wait_for_runs_completed
  wait_for_case_pods_deleted
}

generate_payload() {
  local run_name="$1"
  local work_id="$2"
  local output="$3"

  "${PAYLOAD_PY}" \
    --run-name "${run_name}" \
    --work-id "${work_id}" \
    --namespace "${NAMESPACE}" \
    --active-deadline-seconds "${ACTIVE_DEADLINE_SECONDS}" \
    --completed-ttl-seconds "${COMPLETED_TTL_SECONDS}" \
    --smoke-delay-seconds "${SMOKE_DELAY_SECONDS}" \
    >"${output}"
}

validate_payload_generation() {
  local payload="${SMOKE_TMPDIR}/payload.json"
  log "validating parallel-lifecycle admission payload"
  generate_payload "smoke-1" "smoke-1" "${payload}"
  python3 - "${payload}" "${NAMESPACE}" "smoke-1" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as file:
    body = json.load(file)

namespace = sys.argv[2]
run_name = sys.argv[3]
agent_run = body["agentRun"]
runtime = agent_run["spec"]["agent"]["config"]["runtime"]
plugins = agent_run["spec"]["agent"]["config"]["plugins"]
event_webhook = next(plugin for plugin in plugins if plugin["name"] == "event-webhook")
smoke_complete = next(plugin for plugin in plugins if plugin["name"] == "smoke-complete")

assert agent_run["metadata"]["name"] == run_name
assert agent_run["spec"]["runtime"]["type"] == "codex"
assert runtime["command"] == "bash"
assert runtime["args"] == ["-lc", 'echo "nvt smoke agent ready"; sleep infinity']
assert event_webhook["config"]["url"] == f"http://nvt-operator:8082/v1/agentruns/{namespace}/{run_name}/events"
assert event_webhook["config"]["auth"]["env"] == "NVT_OPERATOR_CALLBACK_TOKEN"
assert "plugin.smoke." in event_webhook["config"]["filters"]
assert smoke_complete["config"]["event"] == "plugin.smoke.completed"
assert agent_run["spec"]["lifecycle"]["completeOn"] == ["plugin.smoke.completed"]
PY
}

post_case_admission() {
  local run_name="$1"
  local work_id="$2"
  local body="${SMOKE_TMPDIR}/${run_name}.json"
  local response="${SMOKE_TMPDIR}/${run_name}.response.json"
  local status_file="${SMOKE_TMPDIR}/${run_name}.status"

  generate_payload "${run_name}" "${work_id}" "${body}"
  post_schedule_admission "${body}" "${response}" "${status_file}"
}

submit_parallel_admissions() {
  log "submitting ${PARALLELISM} parallel-lifecycle admissions"
  for i in $(seq 1 "${PARALLELISM}"); do
    post_case_admission "smoke-${i}" "smoke-${i}"
    assert_admitted "smoke-${i}"
  done
}

assert_admitted() {
  local run_name="$1"
  local response="${SMOKE_TMPDIR}/${run_name}.response.json"
  local status
  status="$(cat "${SMOKE_TMPDIR}/${run_name}.status")"
  [[ "${status}" == "201" ]] || die "expected ${run_name} admission HTTP 201, got ${status}: $(cat "${response}")"

  python3 - "${response}" "${NAMESPACE}" "${run_name}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as file:
    body = json.load(file)
if body.get("scheduled") is not True:
    raise SystemExit(f"expected scheduled=true, got {body}")
run = body.get("agentRun") or {}
if run.get("namespace") != sys.argv[2] or run.get("name") != sys.argv[3]:
    raise SystemExit(f"unexpected agentRun response: {body}")
PY
}

assert_overflow_rejected() {
  local response="${SMOKE_TMPDIR}/smoke-overflow.response.json"
  local status

  log "checking maxParallelism overflow rejection"
  post_case_admission "smoke-overflow" "smoke-overflow"
  status="$(cat "${SMOKE_TMPDIR}/smoke-overflow.status")"
  [[ "${status}" == "429" ]] || die "expected overflow HTTP 429, got ${status}: $(cat "${response}")"

  python3 - "${response}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as file:
    body = json.load(file)
if body.get("scheduled") is not False or body.get("reason") != "max-parallelism-reached":
    raise SystemExit(f"unexpected overflow response: {body}")
PY
}

wait_for_runs_completed() {
  for i in $(seq 1 "${PARALLELISM}"); do
    wait_for_agentrun_exists "smoke-${i}"
  done
  for i in $(seq 1 "${PARALLELISM}"); do
    wait_for_phase_any "smoke-${i}" "${RUN_TIMEOUT_SECONDS}" Running Completed
  done
  for i in $(seq 1 "${PARALLELISM}"); do
    wait_for_phase_any "smoke-${i}" "${RUN_TIMEOUT_SECONDS}" Completed
  done
}

wait_for_case_pods_deleted() {
  local cleanup_timeout=$((COMPLETED_TTL_SECONDS + CLEANUP_TIMEOUT_SECONDS))
  for i in $(seq 1 "${PARALLELISM}"); do
    wait_for_pod_deleted "smoke-${i}-agent" "${cleanup_timeout}"
  done
}
