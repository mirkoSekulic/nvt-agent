#!/usr/bin/env bash

# Enforcement smoke (docs/phase5-6a-enforcement-pr-plan.md §5): a mediated
# run with egressEnforcement cannot reach arbitrary hosts. Requires the
# Calico cluster (operator-kind-cluster-enforced); on kindnet the policies
# are inert and the denied assertions would fail.

case_validate_config() {
  ACTIVE_DEADLINE_SECONDS="${ACTIVE_DEADLINE_SECONDS:-900}"
  RUN_NAME="${RUN_NAME:-enforced-smoke}"
  require_non_negative_integer ACTIVE_DEADLINE_SECONDS "${ACTIVE_DEADLINE_SECONDS}"
  # The enforcement cluster is separate from the kindnet smoke cluster: the
  # denied assertions require an enforcing CNI.
  if [[ "${CLUSTER}" == "nvt-smoke" ]]; then
    CLUSTER="nvt-smoke-enforced"
    KUBECTL_CONTEXT="kind-${CLUSTER}"
  fi
}

case_render() {
  validate_payload_generation
  validate_chart_render --set agentSchedule.maxParallelism=4
}

case_kind_setup() {
  make -C "${ROOT}" \
    CLUSTER="${CLUSTER}" \
    CREATE_CLUSTER="${CREATE_CLUSTER}" \
    ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT}" \
    operator-kind-cluster-enforced

  kubectl_smoke create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl_smoke apply -f -
  kubectl_smoke -n "${NAMESPACE}" create secret generic nvt-smoke-broker-env \
    --from-literal=NVT_SMOKE_STATIC_TOKEN=nvt-smoke-fixture-token \
    --dry-run=client -o yaml | kubectl_smoke apply -f -
  write_broker_providers_values "${SMOKE_TMPDIR}/broker-providers.yaml"
  ECHO_EXPECTED_CREDENTIAL_SHA256="$(printf '%s' 'Bearer nvt-smoke-fixture-token' | sha256sum | cut -d' ' -f1)"
  deploy_echo_fixture

  make -C "${ROOT}" \
    CLUSTER="${CLUSTER}" \
    NAMESPACE="${NAMESPACE}" \
    CREATE_CLUSTER="${CREATE_CLUSTER}" \
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
      - name: git-app
        plugin: token
        config:
          token-env: NVT_SMOKE_STATIC_TOKEN
          injection-hosts:
            - github.com
        allow:
          repositories:
            - example/*
YAML
}

case_run() {
  submit_rejected_admission "direct-enforcement" "egressEnforcement"
  submit_valid_admission valid
  submit_valid_admission probe-a
  submit_valid_admission probe-b

  # The completion-driven run proves DNS, broker, and the operator callback
  # all work under the default-deny policy.
  wait_for_phase_any "${RUN_NAME}-valid" "${RUN_TIMEOUT_SECONDS}" Completed Failed
  local phase
  phase="$(agentrun_phase "${RUN_NAME}-valid")"
  [[ "${phase}" == "Completed" ]] || die "enforced run ended in phase ${phase}"

  wait_for_phase_any "${RUN_NAME}-probe-a" "${RUN_TIMEOUT_SECONDS}" Running
  wait_for_phase_any "${RUN_NAME}-probe-b" "${RUN_TIMEOUT_SECONDS}" Running
  assert_enforced_shape "${RUN_NAME}-probe-a"
  assert_conditions "${RUN_NAME}-probe-a"
  assert_ca_published_matches_mounted "${RUN_NAME}-probe-a"
  assert_direct_egress_denied "${RUN_NAME}-probe-a"
  assert_egressd_path_allowed "${RUN_NAME}-probe-a"
  assert_cross_run_isolated "${RUN_NAME}-probe-a" "${RUN_NAME}-probe-b"
  assert_dind_spawned_egress "${RUN_NAME}-probe-a"
  assert_gc_leaves_no_orphans "${RUN_NAME}-probe-b"
}

payload_file() {
  printf '%s/%s.json' "${SMOKE_TMPDIR}" "$1"
}

generate_payload() {
  local variant="$1"
  local output="$2"

  python3 - "${variant}" "${RUN_NAME}-${variant}" "${ACTIVE_DEADLINE_SECONDS}" "${NAMESPACE}" >"${output}" <<'PY'
import json
import sys

variant = sys.argv[1]
run_name = sys.argv[2]
active_deadline_seconds = int(sys.argv[3])
namespace = sys.argv[4]

grant = {
    "provider": "static-bearer-main",
    "repositories": ["example/repo"],
    "materialization": "header-inject",
    # Hermetic in-cluster echo fixture reached over plain HTTP on :443 (the
    # port the enforced egressd egress policy allows). allowInsecureUpstream
    # is dev/test-only and required because an in-cluster fixture cannot
    # present a publicly-trusted TLS cert.
    "egressHosts": [f"nvt-smoke-echo.{namespace}.svc.cluster.local:443"],
    "allowInsecureUpstream": True,
}
git_grant = {
    "provider": "git-app",
    "repositories": ["example/repo"],
    "materialization": "header-inject",
    "egressHosts": ["github.com:443"],
    "git": True,
    "permissions": {"contents": "read"},
}
plugins = [
    {
        "name": "event-webhook",
        "source": "builtin",
        "when": "after-agent",
        "restart": "always",
        "config": {
            "url": f"http://nvt-operator:8082/v1/agentruns/{namespace}/{run_name}/events",
            "auth": {"type": "bearer-env", "env": "NVT_OPERATOR_CALLBACK_TOKEN"},
            "filters": ["plugin.smoke."],
            "delivery": {"retry": {"backoff-seconds": 1}},
        },
    },
    {
        "name": "smoke-complete",
        "source": "builtin",
        "when": "after-agent",
        "restart": "never",
        "config": {
            "delaySeconds": 1,
            "event": "plugin.smoke.completed",
            "payload": {"ok": True},
        },
    },
]
spec = {
    "runtime": {"type": "codex", "autonomy": "trusted-local"},
    "image": "nvt-agent-runtime:latest",
    "egress": "mediated",
    "egressEnforcement": True,
    "workspace": {"mode": "Ephemeral"},
    "broker": {"grants": [grant, git_grant]},
    "agent": {
        "config": {
            "runtime": {
                "command": "bash",
                "args": ["-lc", 'echo "enforced smoke ready"; sleep infinity'],
            },
            "plugins": plugins,
            "tools": {"packages": [], "mise": [], "additional-paths": [], "shell": []},
            "code-server": {"extensions": []},
        }
    },
    "lifecycle": {"completeOn": ["plugin.smoke.completed"], "failOn": []},
    "ttl": {"activeDeadlineSeconds": active_deadline_seconds},
}

if variant == "direct-enforcement":
    spec["egress"] = "direct"
    spec["broker"] = None
elif variant in {"probe-a", "probe-b"}:
    # Probe runs stay Running: no completion plugin, just the session.
    spec["agent"]["config"]["plugins"] = []
    spec["lifecycle"] = {"completeOn": [], "failOn": []}
elif variant != "valid":
    raise SystemExit(f"unknown variant {variant}")

payload = {
    "work": {"id": run_name, "title": run_name},
    "agentRun": {
        "apiVersion": "nvt.dev/v1alpha1",
        "kind": "AgentRun",
        "metadata": {"name": run_name},
        "spec": spec,
    },
}
json.dump(payload, sys.stdout, separators=(",", ":"))
sys.stdout.write("\n")
PY
}

validate_payload_generation() {
  log "validating enforced-egress admission payloads"
  for variant in valid probe-a direct-enforcement; do
    generate_payload "${variant}" "$(payload_file "${variant}")"
  done
  python3 - "$(payload_file valid)" "$(payload_file direct-enforcement)" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as file:
    valid = json.load(file)["agentRun"]["spec"]
assert valid["egress"] == "mediated"
assert valid["egressEnforcement"] is True
assert "egressAllowInsecureBroker" not in valid
assert valid["lifecycle"]["completeOn"] == ["plugin.smoke.completed"]

with open(sys.argv[2], "r", encoding="utf-8") as file:
    rejected = json.load(file)["agentRun"]["spec"]
assert rejected["egress"] == "direct"
assert rejected["egressEnforcement"] is True
PY
}

post_variant_admission() {
  local variant="$1"
  local body
  body="$(payload_file "${variant}")"
  generate_payload "${variant}" "${body}"
  post_schedule_admission "${body}" "${SMOKE_TMPDIR}/${variant}.response.json" "${SMOKE_TMPDIR}/${variant}.status"
}

submit_rejected_admission() {
  local variant="$1"
  local expected="$2"
  local status

  log "checking enforced-egress rejection for ${variant}"
  post_variant_admission "${variant}"
  status="$(cat "${SMOKE_TMPDIR}/${variant}.status")"
  [[ "${status}" == "400" ]] || die "expected ${variant} admission HTTP 400, got ${status}: $(cat "${SMOKE_TMPDIR}/${variant}.response.json")"
  grep -q "${expected}" "${SMOKE_TMPDIR}/${variant}.response.json" || die "rejection response does not name ${expected}"
  if kubectl_smoke get agentrun "${RUN_NAME}-${variant}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    die "rejected ${variant} admission created an AgentRun"
  fi
}

submit_valid_admission() {
  local variant="$1"
  local status

  log "submitting enforced-egress admission ${variant}"
  post_variant_admission "${variant}"
  status="$(cat "${SMOKE_TMPDIR}/${variant}.status")"
  [[ "${status}" == "201" ]] || die "expected ${variant} admission HTTP 201, got ${status}: $(cat "${SMOKE_TMPDIR}/${variant}.response.json")"
  wait_for_agentrun_exists "${RUN_NAME}-${variant}"
}

agent_exec() {
  local run="$1"
  shift
  kubectl_smoke exec "${run}-agent" -n "${NAMESPACE}" -c agent -- "$@"
}

assert_enforced_shape() {
  local run="$1"
  local pod_json="${SMOKE_TMPDIR}/${run}-pod.json"

  kubectl_smoke get pod "${run}-agent" -n "${NAMESPACE}" -o json >"${pod_json}"
  kubectl_smoke get pod "${run}-egressd" -n "${NAMESPACE}" >/dev/null || die "missing egressd Pod for ${run}"
  kubectl_smoke get service "${run}-egressd" -n "${NAMESPACE}" >/dev/null || die "missing egressd Service for ${run}"
  kubectl_smoke get configmap "${run}-egress-ca" -n "${NAMESPACE}" >/dev/null || die "missing egress CA ConfigMap for ${run}"
  kubectl_smoke get networkpolicy "${run}-agent" -n "${NAMESPACE}" >/dev/null || die "missing agent NetworkPolicy for ${run}"
  kubectl_smoke get networkpolicy "${run}-egressd" -n "${NAMESPACE}" >/dev/null || die "missing egressd NetworkPolicy for ${run}"

  python3 - "${pod_json}" "${run}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as file:
    pod = json.load(file)
run = sys.argv[2]
labels = pod["metadata"]["labels"]
if labels.get("nvt.dev/agentrun") != run or labels.get("nvt.dev/role") != "agent":
    raise SystemExit(f"agent pod missing pairing labels: {labels}")
containers = {container["name"] for container in pod["spec"]["containers"]}
if "egressd" in containers:
    raise SystemExit("enforcement agent pod must not carry a same-Pod egressd sidecar")
volumes = {volume["name"]: volume for volume in pod["spec"].get("volumes", [])}
ca_volume = volumes.get("egress-ca")
if not ca_volume or ca_volume.get("configMap", {}).get("name") != f"{run}-egress-ca":
    raise SystemExit(f"agent CA volume must come from the published ConfigMap: {ca_volume}")
PY
}

assert_conditions() {
  local run="$1"
  local conditions
  conditions="$(kubectl_smoke get agentrun "${run}" -n "${NAMESPACE}" -o jsonpath='{range .status.conditions[*]}{.type}={.status}{"\n"}{end}')"
  for condition in BrokerPolicyReady EgressdCreated EgressdReady EgressCAPublished; do
    grep -q "^${condition}=True$" <<<"${conditions}" || die "condition ${condition} not True for ${run}: ${conditions}"
  done
}

assert_ca_published_matches_mounted() {
  local run="$1"
  local published mounted
  published="$(kubectl_smoke get configmap "${run}-egress-ca" -n "${NAMESPACE}" -o jsonpath='{.data.ca\.crt}')"
  mounted="$(agent_exec "${run}" cat /nvt-egress-ca/ca.crt)"
  [[ "${published}" == "${mounted}" ]] || die "mounted CA differs from the published ConfigMap for ${run}"
  if grep -q "PRIVATE KEY" <<<"${published}"; then
    die "published CA ConfigMap carries private key material"
  fi
}

# curl exit 7 (refused) or 28 (timeout) means the connection never happened —
# enforcement, not an application-level 401 (non-possession).
assert_connect_fails() {
  local description="$1"
  shift
  local exit_code=0
  "$@" >/dev/null 2>&1 || exit_code=$?
  case "${exit_code}" in
    7|28) ;;
    0) die "${description}: connection unexpectedly succeeded" ;;
    *) die "${description}: expected connect failure (curl exit 7/28), got exit ${exit_code}" ;;
  esac
}

assert_direct_egress_denied() {
  local run="$1"
  log "asserting direct egress is denied from ${run}"
  assert_connect_fails "agent direct egress by IP" \
    agent_exec "${run}" curl -sS --max-time 5 https://1.1.1.1
  assert_connect_fails "agent direct egress by name" \
    agent_exec "${run}" curl -sS --max-time 5 https://example.com
}

assert_egressd_path_allowed() {
  local run="$1"
  log "asserting the agent reaches its paired egressd through the Service"
  # A real request from inside the agent container, resolved through kube-dns
  # and verified against the published CA. The hermetic echo fixture reflects
  # the request egressd forwarded. It compares a one-way credential digest and
  # never reflects the injected value back into the untrusted Agent Pod.
  local response
  response="$(agent_exec "${run}" curl -sS --fail-with-body \
    --cacert /nvt-egress-ca/ca.crt --max-time 15 "https://${run}-egressd:8471/echo")" \
    || die "agent -> egressd -> upstream request failed"
  grep -q '"authenticated":true' <<<"${response}" || die "echo fixture did not see an injected credential header: ${response}"
  grep -q '"credential_match":true' <<<"${response}" || die "echo fixture did not receive the exact injected bearer: ${response}"
  grep -q '"path":"/echo"' <<<"${response}" || die "echo fixture did not reflect the request path: ${response}"
  if ! grep -q '"placeholder_seen":false' <<<"${response}"; then
    die "placeholder reached upstream through egressd: ${response}"
  fi
}

assert_cross_run_isolated() {
  local run_a="$1"
  local run_b="$2"
  log "asserting cross-run isolation: ${run_a} cannot reach ${run_b}'s egressd"
  local pod_ip
  pod_ip="$(kubectl_smoke get pod "${run_b}-egressd" -n "${NAMESPACE}" -o jsonpath='{.status.podIP}')"
  [[ -n "${pod_ip}" ]] || die "no pod IP for ${run_b}-egressd"
  # Pod IP is the stronger proof: policy without kube-proxy in the way.
  assert_connect_fails "cross-run egressd by Pod IP" \
    agent_exec "${run_a}" curl -sS -k --max-time 5 "https://${pod_ip}:8471/"
  assert_connect_fails "cross-run egressd by Service name" \
    agent_exec "${run_a}" curl -sS -k --max-time 5 "https://${run_b}-egressd:8471/"
}

assert_dind_spawned_egress() {
  local run="$1"
  log "asserting dind-spawned container egress is fenced (FORWARD path)"
  # Build a probe image from the dind container's own Alpine rootfs (no
  # registry pull — the fence blocks it). Its traffic exits the Pod through
  # the docker bridge and hits the CNI like everything else.
  kubectl_smoke exec "${run}-agent" -n "${NAMESPACE}" -c docker -- \
    sh -c 'tar -C / -cf /tmp/probe-rootfs.tar bin lib usr && docker import /tmp/probe-rootfs.tar probe:latest' \
    >/dev/null || die "building the dind probe image failed"
  # Positive control: the paired egressd CA endpoint is reachable from the
  # spawned container, so a failure below is the policy, not broken tooling.
  kubectl_smoke exec "${run}-agent" -n "${NAMESPACE}" -c docker -- \
    docker run --rm probe:latest /bin/busybox wget -q -T 5 -O- \
    "http://${run}-egressd.${NAMESPACE}.svc.cluster.local:8470/healthz" \
    | grep -q ok || die "dind-spawned container cannot reach the allowed egressd endpoint"
  if kubectl_smoke exec "${run}-agent" -n "${NAMESPACE}" -c docker -- \
    docker run --rm probe:latest /bin/busybox wget -q -T 5 -O /dev/null http://1.1.1.1 >/dev/null 2>&1; then
    die "dind-spawned container reached the internet; the FORWARD path is not fenced"
  fi
}

assert_gc_leaves_no_orphans() {
  local run="$1"
  log "asserting deletion of ${run} leaves no orphaned objects"
  kubectl_smoke delete agentrun "${run}" -n "${NAMESPACE}" --timeout=60s >/dev/null
  local deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    local leftovers
    leftovers="$(kubectl_smoke get pods,services,configmaps,secrets,networkpolicies \
      -n "${NAMESPACE}" -l "nvt.dev/agentrun=${run}" -o name 2>/dev/null)"
    if [[ -z "${leftovers}" ]]; then
      return
    fi
    sleep 2
  done
  die "orphaned objects after deleting ${run}: ${leftovers}"
}
