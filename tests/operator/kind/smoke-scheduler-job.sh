#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

MODE="${1:-apply}"
NAME="${NAME:-}"
CLUSTER="${CLUSTER:-nvt-smoke}"
NAMESPACE="${NAMESPACE:-nvt}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-kind-${CLUSTER}}"
SCHEDULER_IMAGE="${SCHEDULER_IMAGE:-nvt-agent-runtime:latest}"
ACTIVE_DEADLINE_SECONDS="${ACTIVE_DEADLINE_SECONDS:-600}"
COMPLETED_TTL_SECONDS="${COMPLETED_TTL_SECONDS:-10}"
SMOKE_DELAY_SECONDS="${SMOKE_DELAY_SECONDS:-10}"
KUBECTL="${KUBECTL:-kubectl}"
TMPDIR_OWNED=""
TMPDIR_OWNED_CREATED=0

cleanup() {
  if [[ "${TMPDIR_OWNED_CREATED}" == "1" && -n "${TMPDIR_OWNED}" ]]; then
    rm -rf "${TMPDIR_OWNED}"
  fi
}
trap cleanup EXIT

die() {
  printf '[operator-smoke-schedule] ERROR: %s\n' "$*" >&2
  exit 1
}

require_non_negative_integer() {
  local name="$1"
  local value="$2"
  [[ "${value}" =~ ^[0-9]+$ ]] || die "${name} must be an integer greater than or equal to 0"
}

validate_name() {
  [[ -n "${NAME}" ]] || die 'NAME is required, for example: make operator-smoke-schedule NAME=demo-1'
  [[ "${NAME}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] ||
    die "NAME must be a Kubernetes DNS label: lowercase letters, numbers, and hyphens; got ${NAME}"
  local job_name="smoke-scheduler-${NAME}"
  [[ "${#job_name}" -le 63 ]] || die "smoke scheduler Job name ${job_name} is longer than 63 characters"
}

render_job() {
  TMPDIR_OWNED="$(mktemp -d)"
  TMPDIR_OWNED_CREATED=1

  local payload_file="${TMPDIR_OWNED}/payload.json"
  local job_file="${TMPDIR_OWNED}/job.json"

  "${SCRIPT_DIR}/agentrun-payload.py" \
    --run-name "${NAME}" \
    --work-id "smoke:${NAME}" \
    --namespace "${NAMESPACE}" \
    --active-deadline-seconds "${ACTIVE_DEADLINE_SECONDS}" \
    --completed-ttl-seconds "${COMPLETED_TTL_SECONDS}" \
    --smoke-delay-seconds "${SMOKE_DELAY_SECONDS}" \
    --runtime-script 'echo ready; sleep infinity' \
    >"${payload_file}"

  python3 - "${payload_file}" "${job_file}" "${NAME}" "${NAMESPACE}" "${SCHEDULER_IMAGE}" <<'PY'
import json
import sys

payload_path = sys.argv[1]
job_path = sys.argv[2]
name = sys.argv[3]
namespace = sys.argv[4]
image = sys.argv[5]
payload = json.load(open(payload_path, "r", encoding="utf-8"))
admission_url = f"http://nvt-operator:8082/v1/schedules/{namespace}/default/admissions"

scheduler_script = r'''
import os
import sys
import urllib.error
import urllib.request

body = os.environ["ADMISSION_PAYLOAD"].encode("utf-8")
request = urllib.request.Request(
    os.environ["ADMISSION_URL"],
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(request, timeout=30) as response:
        status = response.status
        response_body = response.read().decode("utf-8", errors="replace")
except urllib.error.HTTPError as error:
    status = error.code
    response_body = error.read().decode("utf-8", errors="replace")

print(response_body)
if status != 201:
    print(f"expected admission HTTP 201, got {status}", file=sys.stderr)
    sys.exit(1)
'''.strip()

job = {
    "apiVersion": "batch/v1",
    "kind": "Job",
    "metadata": {
        "name": f"smoke-scheduler-{name}",
        "namespace": namespace,
        "labels": {
            "app.kubernetes.io/name": "nvt-smoke-scheduler",
            "app.kubernetes.io/component": "operator-smoke-schedule",
            "nvt.dev/smoke-agentrun": name,
        },
    },
    "spec": {
        "backoffLimit": 0,
        "ttlSecondsAfterFinished": 300,
        "template": {
            "metadata": {
                "labels": {
                    "app.kubernetes.io/name": "nvt-smoke-scheduler",
                    "app.kubernetes.io/component": "operator-smoke-schedule",
                    "nvt.dev/smoke-agentrun": name,
                },
            },
            "spec": {
                "restartPolicy": "Never",
                "containers": [
                    {
                        "name": "scheduler",
                        "image": image,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python3", "-c", scheduler_script],
                        "env": [
                            {"name": "ADMISSION_URL", "value": admission_url},
                            {"name": "ADMISSION_PAYLOAD", "value": json.dumps(payload, separators=(",", ":"))},
                        ],
                    }
                ],
            },
        },
    },
}

with open(job_path, "w", encoding="utf-8") as file:
    json.dump(job, file, indent=2)
    file.write("\n")
PY

  cat "${job_file}"
}

main() {
  validate_name
  require_non_negative_integer ACTIVE_DEADLINE_SECONDS "${ACTIVE_DEADLINE_SECONDS}"
  require_non_negative_integer COMPLETED_TTL_SECONDS "${COMPLETED_TTL_SECONDS}"
  require_non_negative_integer SMOKE_DELAY_SECONDS "${SMOKE_DELAY_SECONDS}"

  case "${MODE}" in
    render)
      render_job
      ;;
    apply)
      render_job | "${KUBECTL}" --context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" create -f -
      ;;
    *)
      die "mode must be render or apply, got ${MODE}"
      ;;
  esac
}

main "$@"
