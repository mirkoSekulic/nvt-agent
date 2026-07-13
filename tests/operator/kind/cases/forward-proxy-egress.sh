#!/usr/bin/env bash

# Forward-proxy smoke (docs/transparent-egress-architecture.md): a
# mediated + enforced run with spec.egressForwardProxy reaches an allowlisted
# upstream through HTTPS_PROXY with no base-url override — egressd TLS-terminates
# the CONNECT under the per-agent CA, injects the broker credential, and
# re-originates to the pinned upstream. A non-allowlisted host is refused at
# CONNECT (not a 401), and forward-proxy without enforcement is rejected at
# admission. Requires the Calico cluster (the fence is load-bearing here).
#
# The allowlisted upstream is a fixture hostname (echo.nvt-fixture.test) that a
# CoreDNS rewrite resolves to the in-cluster echo Service. A real .svc host
# would land in the operator-computed NO_PROXY and bypass the proxy, so a
# proxy-mediated upstream must look external.

FIXTURE_HOST="echo.nvt-fixture.test"

case_validate_config() {
  ACTIVE_DEADLINE_SECONDS="${ACTIVE_DEADLINE_SECONDS:-900}"
  RUN_NAME="${RUN_NAME:-forward-proxy-smoke}"
  require_non_negative_integer ACTIVE_DEADLINE_SECONDS "${ACTIVE_DEADLINE_SECONDS}"
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
  deploy_echo_fixture
  install_fixture_dns_rewrite

  make -C "${ROOT}" \
    CLUSTER="${CLUSTER}" \
    NAMESPACE="${NAMESPACE}" \
    CREATE_CLUSTER="${CREATE_CLUSTER}" \
    ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT}" \
    OPERATOR_KIND_HELM_ARGS="--set agentSchedule.maxParallelism=4 --set egress.allowInsecureUpstreams=true -f ${SMOKE_TMPDIR}/broker-providers.yaml" \
    operator-kind-setup
}

# install_fixture_dns_rewrite makes echo.nvt-fixture.test resolve to the echo
# Service so egressd can re-originate to the pinned upstream. The rewrite is
# cluster-wide (both the agent and egressd resolve through kube-dns).
install_fixture_dns_rewrite() {
  local target="nvt-smoke-echo.${NAMESPACE}.svc.cluster.local"
  log "rewriting ${FIXTURE_HOST} -> ${target} in CoreDNS"
  local corefile
  corefile="$(kubectl_smoke -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}')"
  if [[ "${corefile}" != *"${FIXTURE_HOST}"* ]]; then
    corefile="${corefile/rewrite name/rewrite name ${FIXTURE_HOST} ${target}$'\n'    rewrite name}"
    if [[ "${corefile}" != *"${FIXTURE_HOST}"* ]]; then
      # No existing rewrite line: inject one after "ready".
      corefile="${corefile/ready/ready
    rewrite name ${FIXTURE_HOST} ${target}}"
    fi
    kubectl_smoke -n kube-system create configmap coredns \
      --from-literal=Corefile="${corefile}" --dry-run=client -o yaml | kubectl_smoke -n kube-system apply -f -
    kubectl_smoke -n kube-system rollout restart deployment/coredns
    kubectl_smoke -n kube-system rollout status deployment/coredns --timeout="${ROLLOUT_TIMEOUT}"
  fi
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
            - ${FIXTURE_HOST}
        allow:
          repositories:
            - example/*
YAML
}

payload_file() { printf '%s/%s.json' "${SMOKE_TMPDIR}" "$1"; }

generate_payload() {
  local variant="$1"
  local output="$2"
  python3 - "${variant}" "${RUN_NAME}-${variant}" "${ACTIVE_DEADLINE_SECONDS}" "${FIXTURE_HOST}" >"${output}" <<'PY'
import json
import sys

variant = sys.argv[1]
run_name = sys.argv[2]
active_deadline_seconds = int(sys.argv[3])
fixture_host = sys.argv[4]

grant = {
    "provider": "static-bearer-main",
    "repositories": ["example/repo"],
    "materialization": "header-inject",
    "egressHosts": [f"{fixture_host}:443"],
    "allowInsecureUpstream": True,
}
spec = {
    "runtime": {"type": "codex", "autonomy": "trusted-local"},
    "image": "nvt-agent-runtime:latest",
    "egress": "mediated",
    "egressEnforcement": True,
    "egressForwardProxy": True,
    "workspace": {"mode": "Ephemeral"},
    "broker": {"grants": [grant]},
    "agent": {
        "config": {
            "runtime": {
                "command": "bash",
                "args": ["-lc", 'echo "forward-proxy smoke ready"; sleep infinity'],
                "proxy": {"provider": "static-bearer-main"},
            },
            "tools": {"packages": [], "mise": [], "additional-paths": [], "shell": []},
            "code-server": {"extensions": []},
        }
    },
    "ttl": {"activeDeadlineSeconds": active_deadline_seconds},
}

if variant == "no-enforcement":
    spec["egressEnforcement"] = False

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
  log "validating forward-proxy admission payload"
  generate_payload valid "$(payload_file valid)"
  python3 - "$(payload_file valid)" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as file:
    spec = json.load(file)["agentRun"]["spec"]
assert spec["egress"] == "mediated"
assert spec["egressEnforcement"] is True
assert spec["egressForwardProxy"] is True
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
  local variant="$1" expected="$2" status
  log "checking forward-proxy rejection for ${variant}"
  post_variant_admission "${variant}"
  status="$(cat "${SMOKE_TMPDIR}/${variant}.status")"
  [[ "${status}" == "400" ]] || die "expected ${variant} admission HTTP 400, got ${status}: $(cat "${SMOKE_TMPDIR}/${variant}.response.json")"
  grep -q "${expected}" "${SMOKE_TMPDIR}/${variant}.response.json" || die "rejection response does not name ${expected}"
  if kubectl_smoke get agentrun "${RUN_NAME}-${variant}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    die "rejected ${variant} admission created an AgentRun"
  fi
}

submit_valid_admission() {
  local variant="$1" status
  log "submitting forward-proxy admission ${variant}"
  post_variant_admission "${variant}"
  status="$(cat "${SMOKE_TMPDIR}/${variant}.status")"
  [[ "${status}" == "201" ]] || die "expected ${variant} admission HTTP 201, got ${status}: $(cat "${SMOKE_TMPDIR}/${variant}.response.json")"
  wait_for_agentrun_exists "${RUN_NAME}-${variant}"
}

case_run() {
  # Forward-proxy without enforcement is rejected at admission, naming the field.
  submit_rejected_admission "no-enforcement" "egressForwardProxy"

  submit_valid_admission valid
  wait_for_phase_any "${RUN_NAME}-valid" "${RUN_TIMEOUT_SECONDS}" Running

  # The mediated path is authorized once the broker agents ConfigMap projects;
  # poll the proxy route until the injected request succeeds.
  wait_for_proxy_ready "${RUN_NAME}-valid"

  # A plain HTTPS request through HTTPS_PROXY only (no --cacert, no base-url):
  # egressd's MITM leaf is trusted via the system store, and the fixture sees
  # the injected credential the agent never held.
  assert_proxy_injects "${RUN_NAME}-valid"

  # A non-allowlisted host is refused at CONNECT (proxy error), not a 401.
  assert_non_allowlisted_denied "${RUN_NAME}-valid"
}

# curl_via_proxy issues an HTTPS request from the agent through HTTPS_PROXY and
# prints "<http_code> <authenticated>" where authenticated reflects whether the
# upstream saw a credential header (the echo fixture reflects it).
curl_via_proxy() {
  local run="$1" host="$2"
  kubectl_smoke exec "${run}-agent" -n "${NAMESPACE}" -c agent -- \
    bash -lc "source ~/.nvt-agent/env 2>/dev/null; curl -s -o /tmp/body -w '%{http_code}' --max-time 15 https://${host}/echo-\${RANDOM} && python3 -c 'import json;print(json.load(open(\"/tmp/body\")).get(\"authenticated\"))' 2>/dev/null || true"
}

wait_for_proxy_ready() {
  local run="$1"
  local deadline=$((SECONDS + RUN_TIMEOUT_SECONDS)) out
  while (( SECONDS < deadline )); do
    out="$(curl_via_proxy "${run}" "${FIXTURE_HOST}" || true)"
    [[ "${out}" == 200* ]] && { log "forward-proxy route ready"; return; }
    sleep 3
  done
  die "forward-proxy route never became ready (last: ${out})"
}

assert_proxy_injects() {
  local run="$1"
  local out
  out="$(curl_via_proxy "${run}" "${FIXTURE_HOST}")"
  [[ "${out}" == 200* ]] || die "forward-proxy request returned ${out}, want 200"
  [[ "${out}" == *True* ]] || die "fixture did not see the injected credential: ${out}"
  log "forward-proxy injected the credential the agent never held"
}

assert_non_allowlisted_denied() {
  local run="$1" code
  # example.com is not an inject route; the proxy resolves nothing — it denies
  # the CONNECT. curl fails (non-2xx / exit non-zero), never a 401.
  code="$(kubectl_smoke exec "${run}-agent" -n "${NAMESPACE}" -c agent -- \
    bash -lc "source ~/.nvt-agent/env 2>/dev/null; curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://example.com/ || echo failed")"
  if [[ "${code}" == "200" || "${code}" == "401" ]]; then
    die "non-allowlisted host was not refused at CONNECT (got ${code})"
  fi
  log "non-allowlisted host refused at CONNECT (${code})"
}
