#!/usr/bin/env bash
set -Eeuo pipefail

CONTEXT="${KATA_DIND_CONTEXT:-}"
NAMESPACE="${KATA_DIND_NAMESPACE:-nvt}"
RUNTIME_CLASS="${KATA_DIND_RUNTIME_CLASS:-kata-vm-isolation}"
RUNTIME_IMAGE="${KATA_DIND_RUNTIME_IMAGE:-}"
STORAGE_CLASS="${KATA_DIND_STORAGE_CLASS:-}"
DOCKER_SIZE="${KATA_DIND_DOCKER_SIZE:-30Gi}"
TOLERATIONS_JSON="${KATA_DIND_TOLERATIONS_JSON:-[]}"
RUN_NAME="${KATA_DIND_RUN_NAME:-kata-dind-overlay2-smoke}"
TIMEOUT="${KATA_DIND_TIMEOUT:-15m}"
KEEP="${KATA_DIND_KEEP:-0}"
PGADMIN_IMAGE="${KATA_DIND_XATTR_IMAGE:-dpage/pgadmin4@sha256:8c128407f45f1c582eda69e71da1a393237388469052e3cc1e6ae4a475e12b70}"
POD_NAME="${RUN_NAME}-agent"
WORKSPACE_PVC_NAME="${RUN_NAME}-workspace"
DOCKER_PVC_NAME="${RUN_NAME}-docker"

die() {
  printf '[kata-dind-overlay2] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -n "${RUNTIME_IMAGE}" ]] || die "KATA_DIND_RUNTIME_IMAGE must name the coordinated runtime image under test"
[[ "${RUNTIME_IMAGE}" =~ ^[^[:space:]]+$ ]] || die "KATA_DIND_RUNTIME_IMAGE must be a single image reference"
[[ "${RUN_NAME}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || die "KATA_DIND_RUN_NAME must be a normalized Kubernetes name"
[[ "${RUNTIME_CLASS}" =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] || die "KATA_DIND_RUNTIME_CLASS must be normalized"
[[ -z "${STORAGE_CLASS}" || "${STORAGE_CLASS}" =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] || die "KATA_DIND_STORAGE_CLASS must be normalized"
[[ "${DOCKER_SIZE}" =~ ^[0-9]+([.][0-9]+)?([KMGTPE]i?)?$ ]] || die "KATA_DIND_DOCKER_SIZE must be a simple positive Kubernetes quantity"
[[ "${PGADMIN_IMAGE}" =~ @sha256:[0-9a-f]{64}$ ]] || die "KATA_DIND_XATTR_IMAGE must use an immutable sha256 digest"

if ! TOLERATIONS_JSON="$(python3 - "${TOLERATIONS_JSON}" <<'PY'
import json
import sys

value = json.loads(sys.argv[1])
if not isinstance(value, list) or len(value) > 32:
    raise ValueError("tolerations must be a JSON array with at most 32 entries")
allowed = {"key", "operator", "value", "effect", "tolerationSeconds"}
for item in value:
    if not isinstance(item, dict) or set(item) - allowed:
        raise ValueError("each toleration must contain only Kubernetes toleration fields")
    for key in ("key", "operator", "value", "effect"):
        if key in item and not isinstance(item[key], str):
            raise ValueError(f"toleration {key} must be a string")
    if item.get("operator", "Equal") not in ("Equal", "Exists"):
        raise ValueError("toleration operator must be Equal or Exists")
    if item.get("effect", "") not in ("", "NoSchedule", "PreferNoSchedule", "NoExecute"):
        raise ValueError("toleration effect is invalid")
    if "tolerationSeconds" in item and (isinstance(item["tolerationSeconds"], bool) or not isinstance(item["tolerationSeconds"], int) or item["tolerationSeconds"] < 0):
        raise ValueError("tolerationSeconds must be a non-negative integer")
print(json.dumps(value, separators=(",", ":")))
PY
)"; then
  die "KATA_DIND_TOLERATIONS_JSON must be a valid bounded Kubernetes toleration array"
fi

k() {
  if [[ -n "${CONTEXT}" ]]; then
    kubectl --context "${CONTEXT}" "$@"
  else
    kubectl "$@"
  fi
}

storage_class_line=""
if [[ -n "${STORAGE_CLASS}" ]]; then
  storage_class_line="  storageClassName: ${STORAGE_CLASS}"
fi

render_agent_run() {
  cat <<YAML
apiVersion: nvt.dev/v1alpha1
kind: AgentRun
metadata:
  name: ${RUN_NAME}
spec:
  runtime:
    type: codex
    autonomy: trusted-local
  runtimeClassName: ${RUNTIME_CLASS}
  image: ${RUNTIME_IMAGE}
  workspace:
    mode: Persistent
    size: 30Gi
    dockerSize: ${DOCKER_SIZE}
${storage_class_line}
  tolerations: ${TOLERATIONS_JSON}
  agent:
    config:
      runtime:
        command: bash
        args: [-lc, "sleep infinity"]
      plugins: []
      tools:
        packages: []
        mise: []
        additional-paths: []
        shell: []
YAML
}

if [[ "${KATA_DIND_RENDER_ONLY:-0}" == 1 ]]; then
  render_agent_run
  exit 0
fi

cleanup() {
  local status=$?
  if [[ "${status}" != 0 ]]; then
    k -n "${NAMESPACE}" describe "agentrun/${RUN_NAME}" >&2 || true
    k -n "${NAMESPACE}" describe "pod/${POD_NAME}" >&2 || true
    k -n "${NAMESPACE}" logs "pod/${POD_NAME}" -c docker --tail=300 >&2 || true
  fi
  if [[ "${KEEP}" != 1 ]]; then
    k -n "${NAMESPACE}" delete "agentrun/${RUN_NAME}" --ignore-not-found --wait=true >/dev/null || true
    for claim in "${WORKSPACE_PVC_NAME}" "${DOCKER_PVC_NAME}"; do
      if k -n "${NAMESPACE}" get "pvc/${claim}" >/dev/null 2>&1; then
        k -n "${NAMESPACE}" wait --for=delete "pvc/${claim}" --timeout="${TIMEOUT}" >/dev/null || {
          printf '[kata-dind-overlay2] ERROR: lifecycle-owned PVC %s was not deleted\n' "${claim}" >&2
          status=1
        }
      fi
    done
  fi
  if [[ "${status}" == 0 && "${KEEP}" != 1 ]]; then
    printf '[kata-dind-overlay2] overlay2, xattr image pull, BuildKit, privilege, and cleanup checks passed\n'
  elif [[ "${status}" == 0 ]]; then
    printf '[kata-dind-overlay2] runtime checks passed; resources retained by KATA_DIND_KEEP=1\n'
  fi
  exit "${status}"
}
trap cleanup EXIT

k get "runtimeclass/${RUNTIME_CLASS}" >/dev/null || die "RuntimeClass ${RUNTIME_CLASS} is unavailable"
k -n "${NAMESPACE}" get deployment/nvt-operator >/dev/null || die "nvt operator is not installed in ${NAMESPACE}"

printf '[kata-dind-overlay2] creating persistent AgentRun %s with RuntimeClass %s\n' "${RUN_NAME}" "${RUNTIME_CLASS}"
render_agent_run | k -n "${NAMESPACE}" apply -f -

k -n "${NAMESPACE}" wait --for=create "pod/${POD_NAME}" --timeout="${TIMEOUT}" >/dev/null
k -n "${NAMESPACE}" wait --for=condition=Ready "pod/${POD_NAME}" --timeout="${TIMEOUT}" >/dev/null

pod_json="$(mktemp)"
k -n "${NAMESPACE}" get "pod/${POD_NAME}" -o json >"${pod_json}"
python3 - "${pod_json}" "${RUNTIME_CLASS}" "${WORKSPACE_PVC_NAME}" "${DOCKER_PVC_NAME}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    pod = json.load(source)
assert pod["spec"].get("runtimeClassName") == sys.argv[2]
volumes = {volume["name"]: volume for volume in pod["spec"].get("volumes", [])}
assert volumes["workspace"]["persistentVolumeClaim"]["claimName"] == sys.argv[3]
assert volumes["docker-storage"]["persistentVolumeClaim"]["claimName"] == sys.argv[4]
containers = pod["spec"].get("initContainers", []) + pod["spec"].get("containers", [])
for container in containers:
    security = container.get("securityContext", {})
    privileged = security.get("privileged") is True
    added = security.get("capabilities", {}).get("add", [])
    if container["name"] == "docker":
        assert privileged, container
        assert any(mount.get("name") == "docker-storage" and mount.get("mountPath") == "/var/lib/nvt-dind" for mount in container.get("volumeMounts", [])), container
    else:
        assert not privileged, container
        assert "SYS_ADMIN" not in added and "SETFCAP" not in added, container
        assert all(mount.get("name") != "docker-storage" for mount in container.get("volumeMounts", [])), container
        assert all(mount.get("mountPath") != "/var/lib/nvt-dind" for mount in container.get("volumeMounts", [])), container
PY
rm -f "${pod_json}"

printf '[kata-dind-overlay2] verifying overlay2 and pinned xattr-bearing OCI image\n'
k -n "${NAMESPACE}" exec "pod/${POD_NAME}" -c agent -- sh -eu -c '
  test "$(docker info --format "{{.Driver}}")" = overlay2
  test ! -e /var/lib/nvt-dind
  docker pull "$1"
  docker run --rm --entrypoint getcap "$1" /usr/bin/python3.12 \
    | grep -F "cap_net_bind_service=eip"
' sh "${PGADMIN_IMAGE}"

printf '[kata-dind-overlay2] running BuildKit copy/hash build\n'
k -n "${NAMESPACE}" exec "pod/${POD_NAME}" -c agent -- sh -eu -c '
  build=/workspace/.nvt-kata-buildkit-smoke
  rm -rf "$build"
  mkdir -p "$build/generated/nested"
  printf "generated locale payload\n" >"$build/generated/nested/locale_en-US.json"
  printf "FROM scratch\nCOPY generated/ /generated/\n" >"$build/Dockerfile"
  DOCKER_BUILDKIT=1 docker build --progress=plain -t nvt-kata-buildkit-smoke:local "$build"
  docker image inspect nvt-kata-buildkit-smoke:local >/dev/null
  container="$(docker create nvt-kata-buildkit-smoke:local)"
  docker cp "$container:/generated/nested/locale_en-US.json" "$build/copied-locale.json"
  docker rm "$container" >/dev/null
  test "$(sha256sum "$build/generated/nested/locale_en-US.json" | cut -d" " -f1)" = \
    "$(sha256sum "$build/copied-locale.json" | cut -d" " -f1)"
  rm -rf "$build"
'

printf '[kata-dind-overlay2] recording persistent Docker state and restarting the native sidecar\n'
marker_image="nvt-kata-dind-marker:${RUN_NAME}"
k -n "${NAMESPACE}" exec "pod/${POD_NAME}" -c agent -- sh -eu -c '
  marker=/workspace/.nvt-kata-dind-marker
  rm -rf "$marker"
  mkdir -p "$marker"
  printf "persistent marker %s\n" "$2" >"$marker/value"
  printf "FROM scratch\nCOPY value /marker/value\nLABEL nvt.smoke.marker=%s\n" "$2" >"$marker/Dockerfile"
  DOCKER_BUILDKIT=1 docker build -q -t "$1" "$marker" >/dev/null
  docker image inspect "$1" --format "{{ index .Config.Labels \"nvt.smoke.marker\" }}" | grep -Fx "$2"
  rm -rf "$marker"
' sh "${marker_image}" "${RUN_NAME}"

filesystem_uuid_before="$(k -n "${NAMESPACE}" exec "pod/${POD_NAME}" -c docker -- \
  blkid -s UUID -o value /var/lib/nvt-dind/docker-data.ext4)"
[[ -n "${filesystem_uuid_before}" ]] || die "Docker backing filesystem has no UUID"
restart_before="$(k -n "${NAMESPACE}" get "pod/${POD_NAME}" -o \
  jsonpath='{.status.initContainerStatuses[?(@.name=="docker")].restartCount}')"
[[ "${restart_before}" =~ ^[0-9]+$ ]] || die "Docker native sidecar restart count is unavailable"

# The native sidecar uses restartPolicy Always. Terminating dockerd exercises
# the supported in-Pod restart path without making the AgentRun terminal.
k -n "${NAMESPACE}" exec "pod/${POD_NAME}" -c docker -- sh -c 'kill -TERM 1' >/dev/null 2>&1 || true

deadline=$((SECONDS + 900))
restart_after=""
ready_after=""
while (( SECONDS < deadline )); do
  status="$(k -n "${NAMESPACE}" get "pod/${POD_NAME}" -o \
    jsonpath='{.status.initContainerStatuses[?(@.name=="docker")].restartCount}:{.status.initContainerStatuses[?(@.name=="docker")].ready}' 2>/dev/null || true)"
  restart_after="${status%%:*}"
  ready_after="${status#*:}"
  if [[ "${restart_after}" =~ ^[0-9]+$ ]] && (( restart_after > restart_before )) && [[ "${ready_after}" == true ]]; then
    break
  fi
  sleep 2
done
[[ "${restart_after}" =~ ^[0-9]+$ ]] && (( restart_after > restart_before )) && [[ "${ready_after}" == true ]] || \
  die "Docker native sidecar did not complete persistent recovery within 15 minutes"

filesystem_uuid_after="$(k -n "${NAMESPACE}" exec "pod/${POD_NAME}" -c docker -- \
  blkid -s UUID -o value /var/lib/nvt-dind/docker-data.ext4)"
[[ "${filesystem_uuid_after}" == "${filesystem_uuid_before}" ]] || die "Docker backing filesystem was reformatted during restart"
k -n "${NAMESPACE}" exec "pod/${POD_NAME}" -c agent -- sh -eu -c '
  test "$(docker info --format "{{.Driver}}")" = overlay2
  test "$(docker image inspect "$1" --format "{{ index .Config.Labels \"nvt.smoke.marker\" }}")" = "$2"
' sh "${marker_image}" "${RUN_NAME}"

printf '[kata-dind-overlay2] runtime checks passed; deleting the AgentRun to verify both PVCs are cleaned up\n'
