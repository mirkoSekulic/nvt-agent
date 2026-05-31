#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="$(mktemp -d)"
WORKDIR_CREATED=1

cleanup() {
  if [[ "${WORKDIR_CREATED}" == "1" && -n "${WORKDIR}" ]]; then
    rm -rf "${WORKDIR}"
  fi
}
trap cleanup EXIT

render="${WORKDIR}/job.json"

NAME=demo-1 \
  NAMESPACE=nvt \
  ACTIVE_DEADLINE_SECONDS=600 \
  COMPLETED_TTL_SECONDS=10 \
  SMOKE_DELAY_SECONDS=7 \
  bash "${SCRIPT_DIR}/smoke-scheduler-job.sh" render >"${render}"

python3 - "${render}" <<'PY'
import json
import sys

job = json.load(open(sys.argv[1], "r", encoding="utf-8"))

assert job["apiVersion"] == "batch/v1"
assert job["kind"] == "Job"
assert job["metadata"]["name"] == "smoke-scheduler-demo-1"
assert job["metadata"]["namespace"] == "nvt"
assert job["spec"]["backoffLimit"] == 0
assert job["spec"]["template"]["spec"]["restartPolicy"] == "Never"

container = job["spec"]["template"]["spec"]["containers"][0]
assert container["name"] == "scheduler"
assert container["image"] == "nvt-agent-runtime:latest"
env = {entry["name"]: entry["value"] for entry in container["env"]}
assert env["ADMISSION_URL"] == "http://nvt-operator:8082/v1/schedules/nvt/default/runs"

payload = json.loads(env["ADMISSION_PAYLOAD"])
assert payload["work"]["id"] == "smoke:demo-1"
agent_run = payload["agentRun"]
assert agent_run["metadata"]["name"] == "demo-1"
spec = agent_run["spec"]
assert spec["workspace"]["mode"] == "Ephemeral"
assert spec["broker"]["grants"] == []
assert spec["agent"]["config"]["runtime"]["command"] == "bash"
assert spec["agent"]["config"]["runtime"]["args"] == ["-lc", "echo ready; sleep infinity"]
plugins = spec["agent"]["config"]["plugins"]
assert [plugin["name"] for plugin in plugins] == ["event-webhook", "smoke-complete"]
assert plugins[0]["config"]["url"] == "http://nvt-operator:8082/v1/agentruns/nvt/demo-1/events"
assert plugins[1]["config"]["delaySeconds"] == 7
assert plugins[1]["config"]["event"] == "plugin.smoke.completed"
assert spec["lifecycle"]["completeOn"] == ["plugin.smoke.completed"]
assert spec["ttl"]["completedTTLSeconds"] == 10
PY

if NAME=Upper bash "${SCRIPT_DIR}/smoke-scheduler-job.sh" render >"${WORKDIR}/bad.out" 2>"${WORKDIR}/bad.err"; then
  echo "expected invalid NAME to fail" >&2
  exit 1
fi
grep -q "NAME must be a Kubernetes DNS label" "${WORKDIR}/bad.err"

fake_kubectl="${WORKDIR}/kubectl"
cat >"${fake_kubectl}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >"${KUBECTL_ARGS_LOG}"
cat >"${KUBECTL_STDIN_LOG}"
SH
chmod +x "${fake_kubectl}"

KUBECTL_ARGS_LOG="${WORKDIR}/kubectl.args"
KUBECTL_STDIN_LOG="${WORKDIR}/kubectl.stdin"
export KUBECTL_ARGS_LOG KUBECTL_STDIN_LOG

NAME=demo-2 \
  NAMESPACE=nvt \
  KUBECTL="${fake_kubectl}" \
  KUBECTL_CONTEXT=kind-test \
  bash "${SCRIPT_DIR}/smoke-scheduler-job.sh" apply

grep -q -- '--context kind-test -n nvt create -f -' "${KUBECTL_ARGS_LOG}"
python3 - "${KUBECTL_STDIN_LOG}" <<'PY'
import json
import sys

job = json.load(open(sys.argv[1], "r", encoding="utf-8"))
assert job["metadata"]["name"] == "smoke-scheduler-demo-2"
PY

echo "operator smoke scheduler Job render test passed"
