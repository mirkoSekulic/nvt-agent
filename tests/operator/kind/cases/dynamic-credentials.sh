#!/usr/bin/env bash

# Dynamic principal credential E2E. This composes the existing account API,
# exact-principal operator resolver, real TokenReview producer admission, and
# enforced forward-proxy injection. Credential bytes exist only in a local
# synthetic portal-completion request and broker custody.

# Reuse the hermetic upstream, DNS rewrite, and proxy observation helpers.
# shellcheck source=tests/operator/kind/cases/forward-proxy-egress.sh
source "${SCRIPT_DIR}/cases/forward-proxy-egress.sh"

case_validate_config() {
  DYNAMIC_TIMEOUT_SECONDS="${DYNAMIC_TIMEOUT_SECONDS:-180}"
  require_positive_integer DYNAMIC_TIMEOUT_SECONDS "${DYNAMIC_TIMEOUT_SECONDS}"
  if [[ "${CLUSTER}" == "nvt-smoke" ]]; then
    CLUSTER="nvt-smoke-dynamic-credentials"
    KUBECTL_CONTEXT="kind-${CLUSTER}"
  fi
}

case_render() {
  validate_chart_render -f "${ROOT}/tests/operator/helm/dynamic-principal-values.yaml"
}

case_kind_setup() {
  need_command openssl
  make -C "${ROOT}" \
    CLUSTER="${CLUSTER}" CREATE_CLUSTER="${CREATE_CLUSTER}" ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT}" \
    operator-kind-cluster-enforced

  kubectl_smoke create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl_smoke apply -f -
  openssl rand -base64 48 >"${SMOKE_TMPDIR}/dynamic-assertion-key"
  chmod 0600 "${SMOKE_TMPDIR}/dynamic-assertion-key"
  kubectl_smoke -n "${NAMESPACE}" create secret generic nvt-dynamic-assertions \
    --from-file=NVT_DYNAMIC_ACCOUNT_ASSERTION_KEY="${SMOKE_TMPDIR}/dynamic-assertion-key" \
    --dry-run=client -o yaml | kubectl_smoke apply -f -

  deploy_echo_fixture
  install_fixture_dns_rewrite
  build_dynamic_profile_auth_client
  kind load docker-image nvt-profile-auth-client:latest --name "${CLUSTER}"
  write_dynamic_values "${SMOKE_TMPDIR}/dynamic-values.yaml"

  make -C "${ROOT}" \
    CLUSTER="${CLUSTER}" NAMESPACE="${NAMESPACE}" CREATE_CLUSTER="${CREATE_CLUSTER}" \
    ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT}" \
    OPERATOR_KIND_HELM_ARGS="--set egress.allowInsecureUpstreams=true -f ${SMOKE_TMPDIR}/dynamic-values.yaml" \
    operator-kind-setup
}

build_dynamic_profile_auth_client() {
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

write_dynamic_values() {
  local output="$1"
  cat >"${output}" <<YAML
broker:
  envSecretName: nvt-dynamic-assertions
  dynamicAccountAssertionRotationEpoch: kind-1
  persistence:
    enabled: true
  config:
    providers: []
    dynamic-accounts:
      enabled: true
      state-dir: /state/principal-accounts
      authentication:
        hmac-key-env: NVT_DYNAMIC_ACCOUNT_ASSERTION_KEY
      provider-templates:
        - name: dynamic-oauth
          plugin: codex-oauth
          credential-config-key: auth-file
          config:
            injection-hosts: [${FIXTURE_HOST}]
          allow:
            repositories: [fixture/profile-auth]
      credential-templates:
        - name: dynamic-work
          label: Dynamic work
          enrollment-adapter: synthetic-kind-adapter
          provider-template: dynamic-oauth
operator:
  principalAccounts:
    enabled: true
    brokerURL: https://nvt-broker:7347
    ca:
      existingSecret: nvt-broker-tls
      key: ca.crt
    authentication:
      existingSecret: nvt-dynamic-assertions
      key: NVT_DYNAMIC_ACCOUNT_ASSERTION_KEY
agentSchedule:
  maxParallelism: 4
  template:
    image: nvt-agent-runtime:latest
    workspace:
      mode: Ephemeral
    agent:
      config:
        plugins: []
        tools: {packages: [], mise: [], additional-paths: [], shell: []}
        code-server: {extensions: []}
  profiles:
    - name: dynamic-work
      runtime:
        type: codex
        autonomy: trusted-local
      agentRuntimeConfig:
        command: bash
        args: ["-lc", "echo dynamic-principal-ready; sleep infinity"]
        proxy:
          provider: \$principal-account
      egress: mediated
      egressEnforcement: true
      egressTransport: forward-proxy
      broker:
        grants:
          - provider: \$principal-account
            repositories: [fixture/profile-auth]
            materialization: header-inject
            egressHosts: [${FIXTURE_HOST}:443]
            allowInsecureUpstream: true
  principalCredentialSelection:
    enabled: true
    onNoMatch: deny
    templateProfiles:
      - template: dynamic-work
        profile: dynamic-work
  workflowProfiles:
    - name: implement
      workspaceInstructions: Complete the authorized work.
  producerPolicies:
    - identity: system:serviceaccount:${NAMESPACE}:profile-auth-allowed
      workflows: [implement]
      defaultWorkflow: implement
      allowedPrincipalIssuers: [https://github.com]
YAML
}

case_run() {
  complete_synthetic_portal_enrollment
  apply_dynamic_producer
  wait_for_dynamic_job
  local run
  run="$(wait_for_dynamic_run)"
  wait_for_phase_any "${run}" "${RUN_TIMEOUT_SECONDS}" Running
  wait_for_proxy_ready "${run}"
  assert_proxy_injects "${run}"
  assert_dynamic_snapshot "${run}"
  assert_dynamic_secret_absence "${run}"
}

complete_synthetic_portal_enrollment() {
  log "completing synthetic portal-to-broker enrollment"
  kubectl_smoke -n "${NAMESPACE}" get secret nvt-broker-tls -o jsonpath='{.data.ca\.crt}' | base64 -d >"${SMOKE_TMPDIR}/broker-ca.crt"
  kubectl_smoke -n "${NAMESPACE}" port-forward service/nvt-broker 17347:7347 >"${SMOKE_TMPDIR}/broker-forward.log" 2>&1 &
  CASE_PORT_FORWARD_PID=$!
  sleep 1
  kill -0 "${CASE_PORT_FORWARD_PID}" 2>/dev/null || die "broker port-forward failed"

  python3 - "${SMOKE_TMPDIR}" <<'PY'
import base64
import hashlib
import hmac
import json
import os
import pathlib
import time

directory = pathlib.Path(os.sys.argv[1])
key = (directory / "dynamic-assertion-key").read_bytes()
claims = {
    "audience": "nvt.broker.principal-accounts/v1",
    "expires_at": int(time.time()) + 60,
    "issuer": "https://github.com",
    "subject": "424242",
    "version": 1,
}
raw = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
token = base64.urlsafe_b64encode(raw).rstrip(b"=").decode() + "." + base64.urlsafe_b64encode(hmac.digest(key, raw, "sha256")).rstrip(b"=").decode()
header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
payload = base64.urlsafe_b64encode(json.dumps({"exp": int(time.time()) + 3600}, separators=(",", ":")).encode()).rstrip(b"=").decode()
needle = "DYNAMIC-KIND-CREDENTIAL-SECRET-NEEDLE"
credential = json.dumps({"tokens": {"access_token": f"{header}.{payload}.signature", "refresh_token": needle, "id_token": needle}}, separators=(",", ":")).encode()
request = {
    "template": "dynamic-work",
    "operation_id": "kind-enrollment-1",
    "credential_base64": base64.b64encode(credential).decode(),
}
(directory / "enrollment.json").write_text(json.dumps(request, separators=(",", ":")), encoding="utf-8")
(directory / "credential-needle").write_text(needle + "\n", encoding="utf-8")
config = "\n".join([
    'silent', 'show-error',
    'url = "https://nvt-broker:7347/v1/principal-accounts/complete-enrollment"',
    'resolve = "nvt-broker:7347:127.0.0.1"',
    f'cacert = "{directory / "broker-ca.crt"}"',
    f'header = "Authorization: NVT-Principal-v1 {token}"',
    'header = "Content-Type: application/json"',
    f'data-binary = "@{directory / "enrollment.json"}"',
    f'output = "{directory / "enrollment-response.json"}"',
    f'write-out = "%{{http_code}}"',
])
(directory / "enrollment.curl").write_text(config + "\n", encoding="utf-8")
PY
  local status
  status="$(NO_PROXY=nvt-broker,127.0.0.1 HTTPS_PROXY= HTTP_PROXY= ALL_PROXY= curl --config "${SMOKE_TMPDIR}/enrollment.curl")"
  [[ "${status}" == "200" ]] || die "dynamic enrollment failed with HTTP ${status}"
  python3 - "${SMOKE_TMPDIR}/enrollment-response.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value == {"ok": True, "state": "ready", "template": "dynamic-work", "generation": 1}, value
PY
  kill "${CASE_PORT_FORWARD_PID}" >/dev/null 2>&1 || true
  wait "${CASE_PORT_FORWARD_PID}" >/dev/null 2>&1 || true
  CASE_PORT_FORWARD_PID=""
}

apply_dynamic_producer() {
  kubectl_smoke apply -f - <<YAML
apiVersion: v1
kind: ServiceAccount
metadata:
  name: profile-auth-allowed
  namespace: ${NAMESPACE}
automountServiceAccountToken: false
---
apiVersion: batch/v1
kind: Job
metadata:
  name: dynamic-profile-producer
  namespace: ${NAMESPACE}
spec:
  backoffLimit: 0
  template:
    spec:
      serviceAccountName: profile-auth-allowed
      automountServiceAccountToken: false
      securityContext: {fsGroup: 65532}
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
              - serviceAccountToken: {path: correct, audience: nvt-operator, expirationSeconds: 600}
              - serviceAccountToken: {path: wrong-audience, audience: wrong-audience, expirationSeconds: 600}
YAML
}

wait_for_dynamic_job() {
  local deadline=$((SECONDS + DYNAMIC_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    [[ "$(kubectl_smoke -n "${NAMESPACE}" get job dynamic-profile-producer -o jsonpath='{.status.succeeded}' 2>/dev/null || true)" == "1" ]] && return
    if [[ -n "$(kubectl_smoke -n "${NAMESPACE}" get job dynamic-profile-producer -o jsonpath='{.status.failed}' 2>/dev/null || true)" ]]; then
      kubectl_smoke -n "${NAMESPACE}" logs job/dynamic-profile-producer >&2 || true
      die "dynamic producer failed"
    fi
    sleep 2
  done
  die "dynamic producer timed out"
}

wait_for_dynamic_run() {
  local deadline=$((SECONDS + DYNAMIC_TIMEOUT_SECONDS)) run
  while (( SECONDS < deadline )); do
    run="$(kubectl_smoke -n "${NAMESPACE}" get agentruns -l nvt.dev/schedule=default -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    [[ -n "${run}" ]] && { printf '%s\n' "${run}"; return; }
    sleep 2
  done
  die "dynamic AgentRun was not created"
}

assert_dynamic_snapshot() {
  local run="$1" output="${SMOKE_TMPDIR}/dynamic-run.json"
  kubectl_smoke -n "${NAMESPACE}" get agentrun "${run}" -o json >"${output}"
  python3 - "${output}" <<'PY'
import json, re, sys
run = json.load(open(sys.argv[1], encoding="utf-8"))
spec = run["spec"]
provenance = spec["profileProvenance"]
credential = provenance["principalCredential"]
assert provenance["principal"] == {"issuer": "https://github.com", "subject": "424242", "displayName": "octocat"}
assert provenance["selectedProfile"] == "dynamic-work"
assert credential["template"] == "dynamic-work" and credential["generation"] == 1
assert re.fullmatch(r"dpa_[A-Za-z0-9_-]{32}", credential["providerInstanceID"])
assert spec["broker"]["grants"][0]["provider"] == credential["providerInstanceID"]
assert spec["agent"]["config"]["runtime"]["proxy"]["provider"] == credential["providerInstanceID"]
PY
}

assert_dynamic_secret_absence() {
  local run="$1" observations="${SMOKE_TMPDIR}/observable.txt"
  {
    cat "${SMOKE_TMPDIR}/enrollment-response.json"
    kubectl_smoke -n "${NAMESPACE}" get agentrun "${run}" -o yaml
    kubectl_smoke -n "${NAMESPACE}" get pod "${run}-agent" -o yaml
    kubectl_smoke -n "${NAMESPACE}" get configmaps -o yaml
    kubectl_smoke -n "${NAMESPACE}" get events -o yaml
    kubectl_smoke -n "${NAMESPACE}" logs deployment/nvt-operator --all-containers
    kubectl_smoke -n "${NAMESPACE}" logs deployment/nvt-broker --all-containers
    kubectl_smoke -n "${NAMESPACE}" logs "${run}-agent" --all-containers
  } >"${observations}"
  if grep -Fq -f "${SMOKE_TMPDIR}/credential-needle" "${observations}"; then
    die "dynamic credential appeared in an observable surface"
  fi
  if kubectl_smoke -n "${NAMESPACE}" exec "${run}-agent" -c agent -- \
    tar -C / -cf - root/.nvt-agent workspace 2>/dev/null | \
    grep -a -Fq -f "${SMOKE_TMPDIR}/credential-needle"; then
    die "dynamic credential appeared in an agent file"
  fi
  log "dynamic credential remained broker-owned"
}
