#!/usr/bin/env bash

# Revocation smoke (protocol/injection.md): revoke a
# grant through the SUPPORTED path — patch the AgentRun spec to drop a grant —
# and observe egressd deny that grant's route within the bound, while a second
# grant keeps working. Do NOT edit the broker agents ConfigMap directly: the
# operator's policy reconcile would re-add the grant and race the test.
#
# Same-Pod on kindnet against the hermetic echo fixture. The two grants share
# the echo upstream but are distinct capabilities, so route 8471 (main) and
# route 8472 (revoked) are independent.

case_validate_config() {
  ACTIVE_DEADLINE_SECONDS="${ACTIVE_DEADLINE_SECONDS:-900}"
  RUN_NAME="${RUN_NAME:-revocation-smoke}"
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
    OPERATOR_KIND_HELM_ARGS="--set agentSchedule.maxParallelism=4 --set egress.allowInsecureUpstreams=true -f ${SMOKE_TMPDIR}/broker-providers.yaml" \
    operator-kind-setup
}

write_broker_providers_values() {
  local output="$1"
  cat >"${output}" <<YAML
broker:
  envSecretName: nvt-smoke-broker-env
  config:
    providers:
      - name: static-bearer-main
        plugin: token
        config:
          token-env: NVT_SMOKE_STATIC_TOKEN
          injection-hosts:
            - nvt-smoke-echo.${NAMESPACE}.svc.cluster.local
        allow:
          repositories:
            - example/*
      - name: static-bearer-b
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
  local output="$1"
  python3 - "${RUN_NAME}-valid" "${ACTIVE_DEADLINE_SECONDS}" "${NAMESPACE}" >"${output}" <<'PY'
import json
import sys

run_name = sys.argv[1]
active_deadline_seconds = int(sys.argv[2])
namespace = sys.argv[3]
echo = f"nvt-smoke-echo.{namespace}.svc.cluster.local:443"

def grant(provider):
    return {
        "provider": provider,
        "repositories": ["example/repo"],
        "materialization": "header-inject",
        "egressHosts": [echo],
        "allowInsecureUpstream": True,
    }

spec = {
    "runtime": {"type": "codex", "autonomy": "trusted-local"},
    "image": "nvt-agent-runtime:latest",
    "egress": "mediated",
    "workspace": {"mode": "Ephemeral"},
    "broker": {"grants": [grant("static-bearer-main"), grant("static-bearer-b")]},
    "agent": {
        "config": {
            "runtime": {"command": "bash", "args": ["-lc", 'echo "revocation smoke ready"; sleep infinity']},
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
  log "validating revocation admission payload"
  generate_payload "$(payload_file valid)"
  python3 - "$(payload_file valid)" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as file:
    grants = json.load(file)["agentRun"]["spec"]["broker"]["grants"]
assert [g["provider"] for g in grants] == ["static-bearer-main", "static-bearer-b"]
PY
}

case_run() {
  local body="${SMOKE_TMPDIR}/valid.json"
  generate_payload "${body}"
  log "submitting revocation admission"
  post_schedule_admission "${body}" "${SMOKE_TMPDIR}/valid.response.json" "${SMOKE_TMPDIR}/valid.status"
  [[ "$(cat "${SMOKE_TMPDIR}/valid.status")" == "201" ]] || die "expected 201, got $(cat "${SMOKE_TMPDIR}/valid.status")"
  wait_for_agentrun_exists "${RUN_NAME}-valid"
  wait_for_phase_any "${RUN_NAME}-valid" "${RUN_TIMEOUT_SECONDS}" Running

  # The broker agents ConfigMap projects ~1min after Pod start, so egressd's
  # first fetches can be unauthorized. Wait until the mediated path is
  # authorized (either route becoming 200 proves broker readiness).
  wait_for_route_ready "${RUN_NAME}-valid" 8471

  # Both routes work before revocation. Fresh path each call = cache miss, so
  # egressd refetches from the broker every time (no stale cache masking).
  assert_route_status "${RUN_NAME}-valid" 8471 200 "main route before revocation"
  assert_route_status "${RUN_NAME}-valid" 8472 200 "route-b before revocation"

  log "revoking static-bearer-b via AgentRun spec patch"
  kubectl_smoke patch agentrun "${RUN_NAME}-valid" -n "${NAMESPACE}" --type=merge \
    -p '{"spec":{"broker":{"grants":[{"provider":"static-bearer-main","repositories":["example/repo"],"materialization":"header-inject","egressHosts":["nvt-smoke-echo.'"${NAMESPACE}"'.svc.cluster.local:443"],"allowInsecureUpstream":true}]}}}'

  # Bound = operator reconcile + kubelet ConfigMap projection (~1min worst
  # case) + egressd cache clamp. Poll the revoked route until it fails closed.
  wait_for_route_denied "${RUN_NAME}-valid" 8472 180
  # The surviving grant keeps working throughout — revocation is per grant.
  assert_route_status "${RUN_NAME}-valid" 8471 200 "main route after revocation"
}

route_status() {
  local run="$1" port="$2"
  # Unique path per call forces a broker refetch (cache miss).
  local path="/probe-${port}-${RANDOM}${RANDOM}"
  kubectl_smoke exec "${run}-agent" -n "${NAMESPACE}" -c agent -- \
    curl -s -o /dev/null -w '%{http_code}' --max-time 15 "http://127.0.0.1:${port}${path}"
}

assert_route_status() {
  local run="$1" port="$2" want="$3" label="$4"
  local code
  code="$(route_status "${run}" "${port}")"
  [[ "${code}" == "${want}" ]] || die "${label}: route ${port} returned ${code}, want ${want}"
}

wait_for_route_ready() {
  local run="$1" port="$2"
  local deadline=$((SECONDS + RUN_TIMEOUT_SECONDS)) code
  while (( SECONDS < deadline )); do
    code="$(route_status "${run}" "${port}")"
    [[ "${code}" == "200" ]] && { log "route ${port} ready (broker authorized)"; return; }
    sleep 3
  done
  die "route ${port} never became ready (last ${code})"
}

wait_for_route_denied() {
  local run="$1" port="$2" timeout="$3"
  local deadline=$((SECONDS + timeout)) code
  while (( SECONDS < deadline )); do
    code="$(route_status "${run}" "${port}")"
    if [[ "${code}" == "502" ]]; then
      log "route ${port} denied (revocation propagated) after $(( SECONDS - (deadline - timeout) ))s"
      return
    fi
    sleep 3
  done
  die "revoked route ${port} still served (last ${code}) after ${timeout}s"
}
