#!/usr/bin/env bash

case_validate_config() {
  ACTIVE_DEADLINE_SECONDS="${ACTIVE_DEADLINE_SECONDS:-600}"
  RUN_NAME="${RUN_NAME:-mediated-smoke}"
  require_non_negative_integer ACTIVE_DEADLINE_SECONDS "${ACTIVE_DEADLINE_SECONDS}"
}

case_render() {
  validate_payload_generation
  validate_chart_render --set agentSchedule.maxParallelism=4
}

case_kind_setup() {
  make -C "${ROOT}" \
    CLUSTER="${CLUSTER}" \
    NAMESPACE="${NAMESPACE}" \
    CREATE_CLUSTER="${CREATE_CLUSTER}" \
    ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT}" \
    OPERATOR_KIND_HELM_ARGS="--set agentSchedule.maxParallelism=4" \
    operator-kind-setup
}

case_run() {
  submit_rejected_admission "runtime-auth" "spec.runtimeAuth"
  submit_rejected_admission "missing-egress-hosts" "egressHosts"
  submit_rejected_admission "file-bundle" "file-bundle"
  submit_valid_admission
  assert_mediated_pod_shape
}

payload_file() {
  local variant="$1"
  printf '%s/%s.json' "${SMOKE_TMPDIR}" "${variant}"
}

generate_payload() {
  local variant="$1"
  local output="$2"

  python3 - "${variant}" "${RUN_NAME}-${variant}" "${ACTIVE_DEADLINE_SECONDS}" >"${output}" <<'PY'
import json
import sys

variant = sys.argv[1]
run_name = sys.argv[2]
active_deadline_seconds = int(sys.argv[3])

grant = {
    "provider": "static-bearer-main",
    "repositories": ["example/repo"],
    "materialization": "header-inject",
    "egressHosts": ["api.example.test:443"],
}
git_grant = {
    "provider": "git-app",
    "repositories": ["example/repo"],
    "materialization": "header-inject",
    "egressHosts": ["github.com:443"],
    "git": True,
    "permissions": {"contents": "read"},
}
spec = {
    "runtime": {"type": "codex", "autonomy": "trusted-local"},
    "image": "nvt-agent-runtime:latest",
    "egress": "mediated",
    "egressAllowInsecureBroker": True,
    "workspace": {"mode": "Ephemeral"},
    "broker": {"grants": [grant, git_grant]},
    "agent": {
        "config": {
            "runtime": {
                "command": "bash",
                "args": ["-lc", 'echo "mediated smoke ready"; sleep infinity'],
            },
            "tools": {"packages": [], "mise": [], "additional-paths": [], "shell": []},
            "code-server": {"extensions": []},
        }
    },
    "ttl": {"activeDeadlineSeconds": active_deadline_seconds},
}

if variant == "runtime-auth":
    spec["runtimeAuth"] = {"secretName": "codex-auth"}
elif variant == "missing-egress-hosts":
    spec["broker"]["grants"] = [{
        "provider": "static-bearer-main",
        "repositories": ["example/repo"],
        "materialization": "header-inject",
    }]
elif variant == "file-bundle":
    spec["broker"]["grants"] = [{
        "provider": "bundle-main",
        "repositories": ["example/repo"],
        "materialization": "file-bundle",
    }]
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
  log "validating mediated-egress admission payloads"
  for variant in valid runtime-auth missing-egress-hosts file-bundle; do
    generate_payload "${variant}" "$(payload_file "${variant}")"
  done
  python3 - "$(payload_file valid)" "$(payload_file runtime-auth)" "$(payload_file missing-egress-hosts)" "$(payload_file file-bundle)" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as file:
    valid = json.load(file)["agentRun"]["spec"]
assert valid["egress"] == "mediated"
assert valid["egressAllowInsecureBroker"] is True
grant = valid["broker"]["grants"][0]
assert grant["provider"] == "static-bearer-main"
assert grant["materialization"] == "header-inject"
assert grant["egressHosts"] == ["api.example.test:443"]
git_grant = valid["broker"]["grants"][1]
assert git_grant["provider"] == "git-app"
assert git_grant["git"] is True
assert git_grant["egressHosts"] == ["github.com:443"]
assert git_grant["permissions"] == {"contents": "read"}

with open(sys.argv[2], "r", encoding="utf-8") as file:
    runtime_auth = json.load(file)["agentRun"]["spec"]
assert runtime_auth["runtimeAuth"]["secretName"] == "codex-auth"

with open(sys.argv[3], "r", encoding="utf-8") as file:
    missing_hosts = json.load(file)["agentRun"]["spec"]
assert "egressHosts" not in missing_hosts["broker"]["grants"][0]

with open(sys.argv[4], "r", encoding="utf-8") as file:
    file_bundle = json.load(file)["agentRun"]["spec"]
assert file_bundle["broker"]["grants"][0]["materialization"] == "file-bundle"
PY
}

post_variant_admission() {
  local variant="$1"
  local body
  local response="${SMOKE_TMPDIR}/${variant}.response.json"
  local status_file="${SMOKE_TMPDIR}/${variant}.status"

  body="$(payload_file "${variant}")"
  generate_payload "${variant}" "${body}"
  post_schedule_admission "${body}" "${response}" "${status_file}"
}

submit_rejected_admission() {
  local variant="$1"
  local expected="$2"
  local response="${SMOKE_TMPDIR}/${variant}.response.json"
  local status

  log "checking mediated-egress rejection for ${variant}"
  post_variant_admission "${variant}"
  status="$(cat "${SMOKE_TMPDIR}/${variant}.status")"
  [[ "${status}" == "400" ]] || die "expected ${variant} admission HTTP 400, got ${status}: $(cat "${response}")"

  python3 - "${response}" "${expected}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as file:
    body = json.load(file)
text = json.dumps(body, sort_keys=True)
if body.get("scheduled") is not False or sys.argv[2] not in text:
    raise SystemExit(f"unexpected rejection response: {body}")
PY

  if kubectl_smoke get agentrun "${RUN_NAME}-${variant}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    die "rejected ${variant} admission created an AgentRun"
  fi
}

submit_valid_admission() {
  local response="${SMOKE_TMPDIR}/valid.response.json"
  local status

  log "submitting valid mediated-egress admission"
  post_variant_admission valid
  status="$(cat "${SMOKE_TMPDIR}/valid.status")"
  [[ "${status}" == "201" ]] || die "expected valid admission HTTP 201, got ${status}: $(cat "${response}")"
  wait_for_agentrun_exists "${RUN_NAME}-valid"
}

wait_for_case_pod() {
  local pod_name="${RUN_NAME}-valid-agent"
  local deadline=$((SECONDS + RUN_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    if kubectl_smoke get pod "${pod_name}" -n "${NAMESPACE}" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  die "timed out waiting for Pod ${pod_name}"
}

assert_mediated_pod_shape() {
  local pod_name="${RUN_NAME}-valid-agent"
  local pod_json="${SMOKE_TMPDIR}/mediated-pod.json"

  wait_for_case_pod
  kubectl_smoke get pod "${pod_name}" -n "${NAMESPACE}" -o json >"${pod_json}"
  python3 - "${pod_json}" "${RUN_NAME}-valid-egress-token" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as file:
    pod = json.load(file)
egress_secret = sys.argv[2]
containers = {container["name"]: container for container in pod["spec"]["containers"]}
if "agent" not in containers or "egressd" not in containers:
    raise SystemExit(f"expected agent and egressd containers, got {sorted(containers)}")

agent = containers["agent"]
egressd = containers["egressd"]
for env in agent.get("env", []):
    if env.get("name") == "NVT_EGRESS_BROKER_TOKEN":
        raise SystemExit("agent env contains NVT_EGRESS_BROKER_TOKEN")
    secret_ref = ((env.get("valueFrom") or {}).get("secretKeyRef") or {})
    if secret_ref.get("name") == egress_secret:
        raise SystemExit(f"agent env references egress token Secret {egress_secret}")

egress_env = {
    env.get("name"): ((env.get("valueFrom") or {}).get("secretKeyRef") or {})
    for env in egressd.get("env", [])
}
broker_token_ref = egress_env.get("NVT_BROKER_TOKEN")
if not broker_token_ref or broker_token_ref.get("name") != egress_secret or broker_token_ref.get("key") != "NVT_EGRESS_BROKER_TOKEN":
    raise SystemExit(f"egressd missing egress broker token ref: {egress_env}")

# Phase 4 git grant shape: shared CA volume carries the certificate only;
# the agent mounts it read-only, egressd writable, and the agent is told
# where to find ca.crt. The CA private key has no volume to leak through.
volumes = {volume["name"]: volume for volume in pod["spec"].get("volumes", [])}
ca_volume = volumes.get("egress-ca")
if not ca_volume or "emptyDir" not in ca_volume:
    raise SystemExit(f"expected egress-ca emptyDir volume, got {sorted(volumes)}")

agent_mounts = {mount["name"]: mount for mount in agent.get("volumeMounts", [])}
agent_ca_mount = agent_mounts.get("egress-ca")
if not agent_ca_mount or agent_ca_mount.get("readOnly") is not True or agent_ca_mount.get("mountPath") != "/nvt-egress-ca":
    raise SystemExit(f"agent CA mount must be read-only at /nvt-egress-ca: {agent_ca_mount}")

egressd_mounts = {mount["name"]: mount for mount in egressd.get("volumeMounts", [])}
egressd_ca_mount = egressd_mounts.get("egress-ca")
if not egressd_ca_mount or egressd_ca_mount.get("readOnly") is True:
    raise SystemExit(f"egressd CA mount must be writable: {egressd_ca_mount}")

agent_plain_env = {env.get("name"): env.get("value") for env in agent.get("env", [])}
if agent_plain_env.get("NVT_EGRESS_CA_FILE") != "/nvt-egress-ca/ca.crt":
    raise SystemExit(f"agent env missing NVT_EGRESS_CA_FILE: {agent_plain_env}")
PY
}
