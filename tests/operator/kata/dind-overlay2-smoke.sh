#!/usr/bin/env bash
set -Eeuo pipefail

CONTEXT="${KATA_DIND_CONTEXT:-$(kubectl config current-context)}"
NAMESPACE="${KATA_DIND_NAMESPACE:-nvt}"
RUNTIME_CLASS="${KATA_DIND_RUNTIME_CLASS:-kata-vm-isolation}"
RUNTIME_IMAGE="${KATA_DIND_RUNTIME_IMAGE:-}"
STORAGE_CLASS="${KATA_DIND_STORAGE_CLASS:-}"
RUN_NAME="${KATA_DIND_RUN_NAME:-kata-dind-overlay2-smoke}"
TIMEOUT="${KATA_DIND_TIMEOUT:-15m}"
KEEP="${KATA_DIND_KEEP:-0}"
PGADMIN_IMAGE="${KATA_DIND_XATTR_IMAGE:-dpage/pgadmin4@sha256:8c128407f45f1c582eda69e71da1a393237388469052e3cc1e6ae4a475e12b70}"
POD_NAME="${RUN_NAME}-agent"
PVC_NAME="${RUN_NAME}-workspace"

die() {
  printf '[kata-dind-overlay2] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -n "${RUNTIME_IMAGE}" ]] || die "KATA_DIND_RUNTIME_IMAGE must name the coordinated runtime image under test"
[[ "${RUN_NAME}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || die "KATA_DIND_RUN_NAME must be a normalized Kubernetes name"
[[ "${PGADMIN_IMAGE}" =~ @sha256:[0-9a-f]{64}$ ]] || die "KATA_DIND_XATTR_IMAGE must use an immutable sha256 digest"

k() {
  kubectl --context "${CONTEXT}" "$@"
}

cleanup() {
  local status=$?
  if [[ "${status}" != 0 ]]; then
    k -n "${NAMESPACE}" describe "agentrun/${RUN_NAME}" >&2 || true
    k -n "${NAMESPACE}" describe "pod/${POD_NAME}" >&2 || true
    k -n "${NAMESPACE}" logs "pod/${POD_NAME}" -c docker --tail=300 >&2 || true
  fi
  if [[ "${KEEP}" != 1 ]]; then
    k -n "${NAMESPACE}" delete "agentrun/${RUN_NAME}" --ignore-not-found --wait=true >/dev/null || true
    if k -n "${NAMESPACE}" get "pvc/${PVC_NAME}" >/dev/null 2>&1; then
      k -n "${NAMESPACE}" wait --for=delete "pvc/${PVC_NAME}" --timeout="${TIMEOUT}" >/dev/null || {
        printf '[kata-dind-overlay2] ERROR: lifecycle-owned PVC was not deleted\n' >&2
        status=1
      }
    fi
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

storage_class_line=""
if [[ -n "${STORAGE_CLASS}" ]]; then
  storage_class_line="  storageClassName: ${STORAGE_CLASS}"
fi

printf '[kata-dind-overlay2] creating persistent AgentRun %s with RuntimeClass %s\n' "${RUN_NAME}" "${RUNTIME_CLASS}"
k -n "${NAMESPACE}" apply -f - <<YAML
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
${storage_class_line}
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

k -n "${NAMESPACE}" wait --for=create "pod/${POD_NAME}" --timeout="${TIMEOUT}" >/dev/null
k -n "${NAMESPACE}" wait --for=condition=Ready "pod/${POD_NAME}" --timeout="${TIMEOUT}" >/dev/null

pod_json="$(mktemp)"
k -n "${NAMESPACE}" get "pod/${POD_NAME}" -o json >"${pod_json}"
python3 - "${pod_json}" "${RUNTIME_CLASS}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    pod = json.load(source)
assert pod["spec"].get("runtimeClassName") == sys.argv[2]
containers = pod["spec"].get("initContainers", []) + pod["spec"].get("containers", [])
for container in containers:
    security = container.get("securityContext", {})
    privileged = security.get("privileged") is True
    added = security.get("capabilities", {}).get("add", [])
    if container["name"] == "docker":
        assert privileged, container
        assert any(mount.get("mountPath") == "/var/lib/nvt-dind" for mount in container.get("volumeMounts", [])), container
    else:
        assert not privileged, container
        assert "SYS_ADMIN" not in added and "SETFCAP" not in added, container
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

printf '[kata-dind-overlay2] runtime checks passed; deleting the AgentRun to verify PVC cleanup\n'
