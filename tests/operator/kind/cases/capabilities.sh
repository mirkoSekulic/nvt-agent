#!/usr/bin/env bash

# Agent-container Linux capability smoke. Standard Kind proves the actual
# attach operation in CI. A cluster that provides Kata can run the identical
# case with CAPABILITIES_RUNTIME_CLASS=kata-vm-isolation.

case_validate_config() {
  CAPABILITIES_RUNTIME_CLASS="${CAPABILITIES_RUNTIME_CLASS:-}"
  CAPABILITIES_TIMEOUT_SECONDS="${CAPABILITIES_TIMEOUT_SECONDS:-180}"
  require_positive_integer CAPABILITIES_TIMEOUT_SECONDS "${CAPABILITIES_TIMEOUT_SECONDS}"
  if [[ -n "${CAPABILITIES_RUNTIME_CLASS}" && ! "${CAPABILITIES_RUNTIME_CLASS}" =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]]; then
    die "CAPABILITIES_RUNTIME_CLASS must be a normalized Kubernetes name"
  fi
}

case_render() {
  validate_chart_render --set agentSchedule.maxParallelism=1
  bash -n "${BASH_SOURCE[0]}"
}

case_kind_setup() {
  make -C "${ROOT}" \
    CLUSTER="${CLUSTER}" \
    NAMESPACE="${NAMESPACE}" \
    CREATE_CLUSTER="${CREATE_CLUSTER}" \
    ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT}" \
    operator-kind-setup
}

case_run() {
  apply_capability_run
  wait_for_phase_any capabilities-smoke "${CAPABILITIES_TIMEOUT_SECONDS}" Running Failed
  if [[ "$(agentrun_phase capabilities-smoke)" == "Failed" ]]; then
    die "capability attach AgentRun failed during startup"
  fi
  wait_for_attach_marker
  assert_agent_only_capability
}

apply_capability_run() {
  local runtime_class=""
  if [[ -n "${CAPABILITIES_RUNTIME_CLASS}" ]]; then
    runtime_class="  runtimeClassName: ${CAPABILITIES_RUNTIME_CLASS}"
  fi
  log "creating SYS_PTRACE attach smoke${CAPABILITIES_RUNTIME_CLASS:+ with RuntimeClass ${CAPABILITIES_RUNTIME_CLASS}}"
  kubectl_smoke apply -f - <<YAML
apiVersion: nvt.dev/v1alpha1
kind: AgentRun
metadata:
  name: capabilities-smoke
  namespace: ${NAMESPACE}
spec:
  runtime:
    type: codex
    autonomy: trusted-local
    user: root
    container:
      capabilities:
        add: [SYS_PTRACE]
${runtime_class}
  image: nvt-agent-runtime:latest
  workspace:
    mode: Ephemeral
  agent:
    config:
      runtime:
        command: bash
        args:
          - -lc
          - |
            set -eu
            sleep 300 &
            target=\$!
            python3 - "\$target" <<'PY'
            import ctypes
            import os
            import sys

            target = int(sys.argv[1])
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.ptrace(16, target, None, None) == -1:  # PTRACE_ATTACH
                raise OSError(ctypes.get_errno(), "PTRACE_ATTACH failed")
            _, status = os.waitpid(target, 0)
            if not os.WIFSTOPPED(status):
                raise RuntimeError("attached process did not stop")
            if libc.ptrace(17, target, None, None) == -1:  # PTRACE_DETACH
                raise OSError(ctypes.get_errno(), "PTRACE_DETACH failed")
            with open("/workspace/sys-ptrace-attach.ok", "w", encoding="utf-8") as marker:
                marker.write("attached\n")
            PY
            kill "\$target"
            wait "\$target" || true
            sleep infinity
      plugins: []
      tools:
        packages: []
        mise: []
        additional-paths: []
        shell: []
YAML
}

wait_for_attach_marker() {
  local deadline=$((SECONDS + CAPABILITIES_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    if kubectl_smoke exec capabilities-smoke-agent -n "${NAMESPACE}" -c agent -- \
      sh -c 'test -s /workspace/sys-ptrace-attach.ok' >/dev/null 2>&1; then
      return
    fi
    if [[ "$(agentrun_phase capabilities-smoke)" == "Failed" ]]; then
      die "capability attach AgentRun failed before producing its marker"
    fi
    sleep 2
  done
  die "timed out waiting for successful PTRACE_ATTACH marker"
}

assert_agent_only_capability() {
  local pod_json="${SMOKE_TMPDIR}/capabilities-pod.json"
  kubectl_smoke get pod capabilities-smoke-agent -n "${NAMESPACE}" -o json >"${pod_json}"
  python3 - "${pod_json}" "${CAPABILITIES_RUNTIME_CLASS}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as file:
    pod = json.load(file)

expected_runtime_class = sys.argv[2] or None
assert pod["spec"].get("runtimeClassName") == expected_runtime_class
containers = pod["spec"].get("initContainers", []) + pod["spec"].get("containers", [])
for container in containers:
    added = container.get("securityContext", {}).get("capabilities", {}).get("add", [])
    if container["name"] == "agent":
        assert added == ["SYS_PTRACE"], container
        assert container.get("securityContext", {}).get("privileged") is not True
    else:
        assert "SYS_PTRACE" not in added, container
PY
}
