#!/usr/bin/env bash

# Profiled admission authentication smoke. The fixture clients use explicit
# projected ServiceAccount token volumes so the operator exercises the real
# Kubernetes TokenReview API and audience validation.

case_validate_config() {
  PROFILE_AUTH_TIMEOUT_SECONDS="${PROFILE_AUTH_TIMEOUT_SECONDS:-90}"
  require_positive_integer PROFILE_AUTH_TIMEOUT_SECONDS "${PROFILE_AUTH_TIMEOUT_SECONDS}"
}

case_render() {
  validate_chart_render --set agentSchedule.maxParallelism=4
}

case_kind_setup() {
  make -C "${ROOT}" \
    CLUSTER="${CLUSTER}" \
    CREATE_CLUSTER="${CREATE_CLUSTER}" \
    operator-kind-cluster

  # This focused case needs only the operator and the producer admission fixture.
  # The accepted AgentRun snapshot is asserted without starting an agent Pod.
  make -C "${ROOT}" operator-build
  build_profile_auth_client
  kind load docker-image nvt-operator:latest --name "${CLUSTER}"
  kind load docker-image nvt-profile-auth-client:latest --name "${CLUSTER}"
  wait_for_profile_auth_api

  helm upgrade --install nvt "${ROOT}/charts/nvt" \
    --kube-context "${KUBECTL_CONTEXT}" \
    -n "${NAMESPACE}" \
    --create-namespace \
    --timeout "${ROLLOUT_TIMEOUT}" \
    --set agentSchedule.maxParallelism=4
  kubectl_smoke rollout status deployment/nvt-operator -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"
}

build_profile_auth_client() {
  local arch
  arch="$(go env GOARCH)"
  (
    cd "${ROOT}/producers/github-comments"
    CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build \
      -trimpath -ldflags='-s -w' \
      -o "${SMOKE_TMPDIR}/profile-auth-client" \
      ./testfixture/profile-auth-client
  )
  docker build -t nvt-profile-auth-client:latest -f - "${SMOKE_TMPDIR}" <<'DOCKERFILE'
FROM scratch
COPY profile-auth-client /profile-auth-client
USER 65532:65532
ENTRYPOINT ["/profile-auth-client"]
DOCKERFILE
}

wait_for_profile_auth_api() {
  local deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    if kubectl_smoke get --raw=/readyz >/dev/null 2>&1; then
      return
    fi
    sleep 2
  done
  die "timed out waiting for Kubernetes API after image loading"
}

case_run() {
  apply_profiled_schedule_and_clients
  wait_for_fixture_job profile-auth-allowed
  wait_for_fixture_job profile-auth-unlisted
  assert_profiled_run_snapshot
}

apply_profiled_schedule_and_clients() {
  log "installing profiled AgentSchedule and projected-token clients"
  kubectl_smoke apply -f - <<YAML
apiVersion: nvt.dev/v1alpha1
kind: AgentSchedule
metadata:
  name: default
  namespace: ${NAMESPACE}
spec:
  maxParallelism: 4
  allowedProducers:
    - system:serviceaccount:${NAMESPACE}:profile-auth-allowed
  template:
    image: nvt-profile-auth-client:latest
    workspace:
      mode: Ephemeral
    agent:
      config:
        plugins: []
        tools:
          packages: []
          mise: []
          additional-paths: []
          shell: []
  profiles:
    - name: default-profile
      runtime:
        type: codex
        autonomy: trusted-local
      agentRuntimeConfig:
        command: bash
        args: ["-lc", "echo profile-auth-ready; sleep infinity"]
      egress: direct
  profileSelection:
    defaultProfile: default-profile
    onNoMatch: useDefault
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: profile-auth-allowed
  namespace: ${NAMESPACE}
automountServiceAccountToken: false
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: profile-auth-unlisted
  namespace: ${NAMESPACE}
automountServiceAccountToken: false
---
apiVersion: batch/v1
kind: Job
metadata:
  name: profile-auth-allowed
  namespace: ${NAMESPACE}
spec:
  backoffLimit: 0
  template:
    spec:
      serviceAccountName: profile-auth-allowed
      automountServiceAccountToken: false
      securityContext:
        fsGroup: 65532
      restartPolicy: Never
      containers:
        - name: client
          image: nvt-profile-auth-client:latest
          imagePullPolicy: IfNotPresent
          env:
            - name: MODE
              value: allowed
            - name: ADMISSION_URL
              value: http://nvt-operator:8082/v1/schedules/${NAMESPACE}/default/admissions
          volumeMounts:
            - name: producer-tokens
              mountPath: /var/run/nvt-tokens
              readOnly: true
      volumes:
        - name: producer-tokens
          projected:
            defaultMode: 0440
            sources:
              - serviceAccountToken:
                  path: correct
                  audience: nvt-operator
                  expirationSeconds: 600
              - serviceAccountToken:
                  path: wrong-audience
                  audience: wrong-audience
                  expirationSeconds: 600
---
apiVersion: batch/v1
kind: Job
metadata:
  name: profile-auth-unlisted
  namespace: ${NAMESPACE}
spec:
  backoffLimit: 0
  template:
    spec:
      serviceAccountName: profile-auth-unlisted
      automountServiceAccountToken: false
      securityContext:
        fsGroup: 65532
      restartPolicy: Never
      containers:
        - name: client
          image: nvt-profile-auth-client:latest
          imagePullPolicy: IfNotPresent
          env:
            - name: MODE
              value: unlisted
            - name: ADMISSION_URL
              value: http://nvt-operator:8082/v1/schedules/${NAMESPACE}/default/admissions
          volumeMounts:
            - name: producer-token
              mountPath: /var/run/nvt-token
              readOnly: true
      volumes:
        - name: producer-token
          projected:
            defaultMode: 0440
            sources:
              - serviceAccountToken:
                  path: token
                  audience: nvt-operator
                  expirationSeconds: 600
YAML
}

wait_for_fixture_job() {
  local name="$1"
  local deadline=$((SECONDS + PROFILE_AUTH_TIMEOUT_SECONDS))
  local succeeded failed
  while (( SECONDS < deadline )); do
    succeeded="$(kubectl_smoke get job "${name}" -n "${NAMESPACE}" -o jsonpath='{.status.succeeded}' 2>/dev/null || true)"
    failed="$(kubectl_smoke get job "${name}" -n "${NAMESPACE}" -o jsonpath='{.status.failed}' 2>/dev/null || true)"
    if [[ "${succeeded}" == "1" ]]; then
      log "${name} completed"
      return
    fi
    if [[ -n "${failed}" && "${failed}" != "0" ]]; then
      kubectl_smoke logs "job/${name}" -n "${NAMESPACE}" >&2 || true
      die "${name} failed"
    fi
    sleep 2
  done
  kubectl_smoke logs "job/${name}" -n "${NAMESPACE}" >&2 || true
  die "timed out waiting for ${name}"
}

assert_profiled_run_snapshot() {
  local runs="${SMOKE_TMPDIR}/profile-auth-runs.json"
  kubectl_smoke get agentruns -n "${NAMESPACE}" -l nvt.dev/schedule=default -o json >"${runs}"
  python3 - "${runs}" "${NAMESPACE}" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], "r", encoding="utf-8"))
runs = document["items"]
assert len(runs) == 1, document["items"]
run = runs[0]
spec = run["spec"]
provenance = spec["profileProvenance"]
assert provenance["authenticatedProducer"] == f"system:serviceaccount:{sys.argv[2]}:profile-auth-allowed"
assert provenance["selectedProfile"] == "default-profile"
assert provenance["principal"]["issuer"] == "https://github.com"
assert provenance["principal"]["subject"] == "424242"
assert provenance["principal"]["displayName"] == "octocat"
assert spec["agent"]["config"]["runtime"]["command"] == "bash"

work_ids = {
    item.get("metadata", {}).get("annotations", {}).get("nvt.dev/work-id")
    for item in document["items"]
}
assert "profile-auth-injected" not in work_ids
PY
}
