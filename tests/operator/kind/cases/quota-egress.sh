#!/usr/bin/env bash

# Quota smoke (docs/phase5-6b-observability-pr-plan.md item 3): a mediated
# grant with quota.requests: N is enforced at the sidecar — the (N+1)th
# proxied request fails closed with 429. Runs same-Pod on kindnet (quota is
# enforced in egressd regardless of placement) against the hermetic echo
# fixture, so no Calico cluster is needed.

QUOTA_LIMIT=2

case_validate_config() {
  ACTIVE_DEADLINE_SECONDS="${ACTIVE_DEADLINE_SECONDS:-600}"
  RUN_NAME="${RUN_NAME:-quota-smoke}"
  require_non_negative_integer ACTIVE_DEADLINE_SECONDS "${ACTIVE_DEADLINE_SECONDS}"
}

case_render() {
  validate_payload_generation
  validate_chart_render --set agentSchedule.maxParallelism=4
}

case_kind_setup() {
  make -C "${ROOT}" CLUSTER="${CLUSTER}" CREATE_CLUSTER="${CREATE_CLUSTER}" operator-kind-cluster
  kubectl_smoke create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl_smoke apply -f -
  kubectl_smoke -n "${NAMESPACE}" create secret generic nvt-smoke-broker-env \
    --from-literal=NVT_SMOKE_STATIC_TOKEN=nvt-smoke-fixture-token \
    --dry-run=client -o yaml | kubectl_smoke apply -f -
  write_broker_providers_values "${SMOKE_TMPDIR}/broker-providers.yaml"
  deploy_echo_fixture
  make -C "${ROOT}" \
    CLUSTER="${CLUSTER}" NAMESPACE="${NAMESPACE}" CREATE_CLUSTER="${CREATE_CLUSTER}" \
    ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT}" \
    OPERATOR_KIND_HELM_ARGS="--set agentSchedule.maxParallelism=4 -f ${SMOKE_TMPDIR}/broker-providers.yaml" \
    operator-kind-setup
}

write_broker_providers_values() {
  local output="$1"
  cat >"${output}" <<YAML
broker:
  envSecretName: nvt-smoke-broker-env
  config:
    providers:
      - name: static-bearer-warmup
        plugin: token
        config:
          token-env: NVT_SMOKE_STATIC_TOKEN
          injection-hosts:
            - nvt-smoke-echo.${NAMESPACE}.svc.cluster.local
        allow:
          repositories:
            - example/*
      - name: static-bearer-quota
        plugin: token
        config:
          token-env: NVT_SMOKE_STATIC_TOKEN
          injection-hosts:
            - nvt-smoke-echo.${NAMESPACE}.svc.cluster.local
        allow:
          repositories:
            - example/*
YAML
}

payload_file() { printf '%s/%s.json' "${SMOKE_TMPDIR}" "$1"; }

generate_payload() {
  local variant="$1"
  local output="$2"
  python3 - "${RUN_NAME}-${variant}" "${ACTIVE_DEADLINE_SECONDS}" "${NAMESPACE}" "${QUOTA_LIMIT}" >"${output}" <<'PY'
import json
import sys

run_name = sys.argv[1]
active_deadline_seconds = int(sys.argv[2])
namespace = sys.argv[3]
quota_limit = int(sys.argv[4])

echo = f"nvt-smoke-echo.{namespace}.svc.cluster.local:443"
# Warmup route (no quota) on 8471 lets the smoke wait for broker readiness
# without spending the quota route. The quota route is on 8472.
warmup_grant = {
    "provider": "static-bearer-warmup",
    "repositories": ["example/repo"],
    "materialization": "header-inject",
    "egressHosts": [echo],
    "allowInsecureUpstream": True,
}
quota_grant = {
    "provider": "static-bearer-quota",
    "repositories": ["example/repo"],
    "materialization": "header-inject",
    "egressHosts": [echo],
    "allowInsecureUpstream": True,
    "quota": {"requests": quota_limit},
}
spec = {
    "runtime": {"type": "codex", "autonomy": "trusted-local"},
    "image": "nvt-agent-runtime:latest",
    "egress": "mediated",
    "workspace": {"mode": "Ephemeral"},
    "broker": {"grants": [warmup_grant, quota_grant]},
    "agent": {
        "config": {
            "runtime": {"command": "bash", "args": ["-lc", 'echo "quota smoke ready"; sleep infinity']},
            "tools": {"packages": [], "mise": [], "additional-paths": [], "shell": []},
            "code-server": {"extensions": []},
        }
    },
    "ttl": {"activeDeadlineSeconds": active_deadline_seconds},
}
payload = {
    "work": {"id": run_name, "title": run_name},
    "agentRun": {"apiVersion": "nvt.dev/v1alpha1", "kind": "AgentRun",
                 "metadata": {"name": run_name}, "spec": spec},
}
json.dump(payload, sys.stdout, separators=(",", ":"))
sys.stdout.write("\n")
PY
}

validate_payload_generation() {
  log "validating quota-egress admission payload"
  generate_payload valid "$(payload_file valid)"
  python3 - "$(payload_file valid)" "${QUOTA_LIMIT}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as file:
    grants = json.load(file)["agentRun"]["spec"]["broker"]["grants"]
assert [g["provider"] for g in grants] == ["static-bearer-warmup", "static-bearer-quota"]
assert "quota" not in grants[0]
assert grants[1]["quota"] == {"requests": int(sys.argv[2])}
assert grants[1]["allowInsecureUpstream"] is True
PY
}

case_run() {
  local body="${SMOKE_TMPDIR}/valid.json"
  local response="${SMOKE_TMPDIR}/valid.response.json"
  local status_file="${SMOKE_TMPDIR}/valid.status"
  generate_payload valid "${body}"
  log "submitting quota-egress admission"
  post_schedule_admission "${body}" "${response}" "${status_file}"
  [[ "$(cat "${status_file}")" == "201" ]] || die "expected 201, got $(cat "${status_file}"): $(cat "${response}")"
  wait_for_agentrun_exists "${RUN_NAME}-valid"
  wait_for_phase_any "${RUN_NAME}-valid" "${RUN_TIMEOUT_SECONDS}" Running

  # The broker agents ConfigMap projects ~1min after Pod start, so egressd's
  # first fetches can be unauthorized. Warm up on the quota-free route (8471)
  # until the mediated path is authorized, so failed startup requests never
  # consume the quota route (8472).
  wait_for_route_ready "${RUN_NAME}-valid" 8471
  assert_quota_enforced "${RUN_NAME}-valid" 8472
}

# curl_egress issues a request from the agent container through a same-Pod
# egressd route (plain-HTTP localhost listener) and prints the HTTP status.
curl_egress() {
  local run="$1" port="$2"
  kubectl_smoke exec "${run}-agent" -n "${NAMESPACE}" -c agent -- \
    curl -s -o /dev/null -w '%{http_code}' --max-time 15 "http://127.0.0.1:${port}/echo-${RANDOM}"
}

wait_for_route_ready() {
  local run="$1" port="$2"
  local deadline=$((SECONDS + RUN_TIMEOUT_SECONDS)) code
  while (( SECONDS < deadline )); do
    code="$(curl_egress "${run}" "${port}")"
    [[ "${code}" == "200" ]] && { log "warmup route ${port} ready (broker authorized)"; return; }
    sleep 3
  done
  die "warmup route ${port} never became ready (last ${code})"
}

assert_quota_enforced() {
  local run="$1" port="$2"
  log "asserting per-grant request quota (limit ${QUOTA_LIMIT}) is enforced at egressd"
  local i code
  for (( i = 1; i <= QUOTA_LIMIT; i++ )); do
    code="$(curl_egress "${run}" "${port}")"
    [[ "${code}" == "200" ]] || die "request ${i}/${QUOTA_LIMIT} within quota returned ${code}, want 200"
  done
  code="$(curl_egress "${run}" "${port}")"
  [[ "${code}" == "429" ]] || die "request beyond quota returned ${code}, want 429"
  # And it stays closed.
  code="$(curl_egress "${run}" "${port}")"
  [[ "${code}" == "429" ]] || die "quota must stay closed after breach, got ${code}"
}
