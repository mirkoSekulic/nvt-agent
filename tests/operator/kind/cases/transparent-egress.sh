#!/usr/bin/env bash

# Transparent enforced TCP acceptance gate. Reuse the hermetic broker/echo
# setup from the explicit forward-proxy case, then select the transparent
# transport and exercise both local listeners plus the CNI fence.

# shellcheck source=tests/operator/kind/cases/forward-proxy-egress.sh
source "${SCRIPT_DIR}/cases/forward-proxy-egress.sh"

eval "$(declare -f generate_payload | sed '1s/generate_payload/base_generate_payload/')"

case_validate_config() {
  ACTIVE_DEADLINE_SECONDS="${ACTIVE_DEADLINE_SECONDS:-1200}"
  RUN_NAME="${RUN_NAME:-transparent-egress-smoke}"
  require_non_negative_integer ACTIVE_DEADLINE_SECONDS "${ACTIVE_DEADLINE_SECONDS}"
  if [[ "${CLUSTER}" == "nvt-smoke" ]]; then
    CLUSTER="nvt-smoke-transparent"
    KUBECTL_CONTEXT="kind-${CLUSTER}"
  fi
}

case_kind_setup() {
  FIXTURE_TOKEN="fixture-${RANDOM}-${RANDOM}"
  make -C "${ROOT}" CLUSTER="${CLUSTER}" CREATE_CLUSTER="${CREATE_CLUSTER}" \
    ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT}" operator-kind-cluster-enforced
  kubectl_smoke create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl_smoke apply -f -
  ECHO_EXPECTED_CREDENTIAL_SHA256="$(printf 'Bearer %s' "${FIXTURE_TOKEN}" | sha256sum | cut -d' ' -f1)"
  printf 'NVT_SMOKE_STATIC_TOKEN=%s\n' "${FIXTURE_TOKEN}" | \
    kubectl_smoke -n "${NAMESPACE}" create secret generic nvt-smoke-broker-env \
    --from-env-file=/dev/stdin \
    --dry-run=client -o yaml | kubectl_smoke apply -f -
  unset FIXTURE_TOKEN
  write_broker_providers_values "${SMOKE_TMPDIR}/broker-providers.yaml"
  deploy_echo_fixture
  local fixture_label
  fixture_label="$(printf '%s' "${FIXTURE_HOST}" | sha256sum | cut -c1-32)"
  kubectl_smoke patch deployment "${ECHO_FIXTURE_NAME}" -n "${NAMESPACE}" --type merge \
    -p '{"spec":{"template":{"metadata":{"labels":{"nvt.dev/egress-host":"'"${fixture_label}"'"}}}}}'
  kubectl_smoke -n "${NAMESPACE}" rollout status "deployment/${ECHO_FIXTURE_NAME}" --timeout="${ROLLOUT_TIMEOUT}"
  install_fixture_dns_rewrite
  make -C "${ROOT}" CLUSTER="${CLUSTER}" NAMESPACE="${NAMESPACE}" CREATE_CLUSTER="${CREATE_CLUSTER}" \
    ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT}" \
    OPERATOR_KIND_HELM_ARGS="--set agentSchedule.maxParallelism=4 --set egress.allowInsecureUpstreams=true --set egress.networkPolicyCapable=true -f ${SMOKE_TMPDIR}/broker-providers.yaml" \
    operator-kind-setup
}

write_broker_providers_values() {
  cat >"$1" <<YAML
broker:
  envSecretName: nvt-smoke-broker-env
  config:
    providers:
      - name: static-bearer-main
        plugin: token
        config: {token-env: NVT_SMOKE_STATIC_TOKEN, injection-hosts: [${FIXTURE_HOST}]}
        allow: {repositories: [example/*]}
      - name: static-bearer-alt
        plugin: token
        config: {token-env: NVT_SMOKE_STATIC_TOKEN, injection-hosts: [${FIXTURE_HOST}]}
        allow: {repositories: [example/*]}
YAML
}

generate_payload() {
  local variant="$1" output="$2"
  base_generate_payload valid "${output}"
  python3 - "${variant}" "${output}" <<'PY'
import json, sys
variant, path = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as f:
    payload = json.load(f)
spec = payload["agentRun"]["spec"]
spec["egressTransport"] = "transparent"
payload["work"]["id"] = payload["agentRun"]["metadata"]["name"] = payload["agentRun"]["metadata"]["name"].rsplit("-", 1)[0] + "-" + variant
if variant == "no-enforcement":
    spec["egressEnforcement"] = False
elif variant == "ambiguous":
    second = dict(spec["broker"]["grants"][0])
    second["provider"] = "static-bearer-alt"
    spec["broker"]["grants"].append(second)
with open(path, "w", encoding="utf-8") as f:
    json.dump(payload, f, separators=(",", ":")); f.write("\n")
PY
}

validate_payload_generation() {
  generate_payload valid "$(payload_file valid)"
  python3 - "$(payload_file valid)" <<'PY'
import json, sys
spec=json.load(open(sys.argv[1], encoding="utf-8"))["agentRun"]["spec"]
assert spec["egressTransport"] == "transparent"
assert spec["egressEnforcement"] is True
PY
}

agent_exec() {
  kubectl_smoke exec "$1-agent" -n "${NAMESPACE}" -c agent -- "${@:2}"
}

wait_for_published_service() {
  local run="$1" port="$2" expected="$3" body="" attempt
  for attempt in $(seq 1 50); do
    body="$(agent_exec "${run}" curl --noproxy '*' -sS --max-time 1 "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "${body}" == "${expected}" ]]; then
      return 0
    fi
    sleep 0.2
  done
  die "agent could not reach expected response from DinD-published port ${port}"
}

case_run() {
  submit_rejected_admission no-enforcement egressTransport
  submit_valid_admission valid
  submit_valid_admission other
  submit_valid_admission ambiguous
  local run="${RUN_NAME}-valid"
  wait_for_phase_any "${run}" "${RUN_TIMEOUT_SECONDS}" Running
  wait_for_phase_any "${RUN_NAME}-other" "${RUN_TIMEOUT_SECONDS}" Running
  wait_for_phase_any "${RUN_NAME}-ambiguous" "${RUN_TIMEOUT_SECONDS}" Running
  wait_for_proxy_ready "${run}"

  # Proxy-aware path through captured's explicit listener.
  assert_proxy_injects "${run}"
  agent_exec "${run}" bash -lc \
    'source ~/.nvt-agent/env 2>/dev/null
     test -z "${HTTP_PROXY:-}" && test -z "${http_proxy:-}"
     test -n "${HTTPS_PROXY:-}" && test -n "${https_proxy:-}"'

  # Plain HTTP intentionally has no explicit proxy variable. curl/apt-like
  # traffic connects normally, is captured by OUTPUT, and is permitted on 80.
  agent_exec "${run}" env -u HTTP_PROXY -u http_proxy -u ALL_PROXY -u all_proxy \
    curl --fail -sS --max-time 20 -A 'Debian APT-HTTP/1.3' http://example.com/ >/dev/null

  # Proxy-unaware path: remove every proxy variable; OUTPUT capture still
  # reaches the same injected fixture.
  local body
  body="$(agent_exec "${run}" env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
    curl -sS --fail --max-time 20 "https://${FIXTURE_HOST}/transparent")"
  grep -q '"credential_match":true' <<<"${body}" || die "proxy-unaware request did not carry the exact fixture credential: ${body}"
  grep -q '"placeholder_seen":false' <<<"${body}" || die "placeholder reached the fixture: ${body}"

  # A raw TCP connect (no HTTP proxy semantics) must traverse captured and
  # egressd. TLS bytes remain opaque for this unmatched public host.
  agent_exec "${run}" bash -lc 'timeout 10 bash -c "exec 3<>/dev/tcp/example.com/443; exec 3>&-"'

  # A child container in DinD traverses PREROUTING capture as well.
  agent_exec "${run}" docker run --rm docker:27-dind wget -q -T 15 -O- https://example.com >/dev/null

  # Pod-side traffic to Docker-published services must stay local. Exercise
  # both Docker's default bridge and a Compose-style bridge created after
  # net-init; the latter proves interface-prefix matching is not a startup
  # snapshot. The agent and containers share this Pod network namespace.
  agent_exec "${run}" docker run -d --rm --name nvt-local-default \
    -p 127.0.0.1:18080:18080 docker:27-dind \
    sh -ec 'mkdir -p /tmp/www; echo default-bridge-ok >/tmp/www/index.html; exec httpd -f -p 18080 -h /tmp/www'
  wait_for_published_service "${run}" 18080 default-bridge-ok
  agent_exec "${run}" docker network create nvt_issue143_default >/dev/null
  agent_exec "${run}" docker run -d --rm --name nvt-local-compose \
    --network nvt_issue143_default -p 127.0.0.1:18081:18080 docker:27-dind \
    sh -ec 'mkdir -p /tmp/www; echo compose-bridge-ok >/tmp/www/index.html; exec httpd -f -p 18080 -h /tmp/www'
  wait_for_published_service "${run}" 18081 compose-bridge-ok

  # The local OUTPUT bypass does not apply to DinD-originated connections:
  # they enter PREROUTING and remain subject to destination denial.
  if agent_exec "${run}" docker run --rm docker:27-dind wget -q -T 5 -O- http://169.254.169.254/; then
    die "DinD container bypassed metadata destination denial"
  fi

  # Private and metadata destinations are denied by egressd even through the
  # explicit local listener.
  for target in 10.0.0.1 169.254.169.254; do
    if agent_exec "${run}" curl -sS --max-time 5 --proxy http://127.0.0.1:15002 "https://${target}/"; then
      die "private destination ${target} unexpectedly succeeded"
    fi
  done

  # Cross-run egressd access is outside the paired NetworkPolicy selector.
  if agent_exec "${run}" env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
    curl --fail --noproxy '*' -sS --max-time 5 "http://${RUN_NAME}-other-egressd:8473/"; then
    die "cross-run egressd access unexpectedly succeeded"
  fi

  # Two providers share the fixture host. With proxy variables removed there
  # is no selector, so transparent routing must fail closed rather than guess.
  if agent_exec "${RUN_NAME}-ambiguous" env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
    curl -sS --max-time 10 "https://${FIXTURE_HOST}/ambiguous"; then
    die "ambiguous transparent provider selection unexpectedly succeeded"
  fi

  # Prove the broker's provider secret is not projected into the Agent Pod,
  # without printing its runtime-generated value. Also scan readable files for
  # private-key material; only matching file names can reach the test log.
  if agent_exec "${run}" sh -ec 'env | cut -d= -f1 | grep -qx NVT_SMOKE_STATIC_TOKEN'; then
    die "provider credential environment variable found in Agent Pod"
  fi
  if kubectl_smoke get pod "${run}-agent" -n "${NAMESPACE}" -o json | grep -q nvt-smoke-broker-env; then
    die "provider credential secret projected into Agent Pod"
  fi
  if agent_exec "${run}" sh -ec 'find / -xdev -maxdepth 5 -type f -readable -exec grep -Il "PRIVATE KEY" {} + 2>/dev/null' | grep -q .; then
    die "CA private key found in Agent Pod"
  fi

  # Stop reconciliation, remove the paired egressd, and prove capture never
  # falls back to the Agent Pod's direct internet path.
  kubectl_smoke scale deployment/nvt-operator -n "${NAMESPACE}" --replicas=0
  kubectl_smoke wait -n "${NAMESPACE}" --for=delete pod -l app.kubernetes.io/name=nvt-operator --timeout="${ROLLOUT_TIMEOUT}"
  kubectl_smoke delete pod "${run}-egressd" -n "${NAMESPACE}" --wait=true
  if agent_exec "${run}" env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
    curl --fail -sS --max-time 5 https://example.com/; then
    die "egressd outage fell back to direct internet"
  fi
  kubectl_smoke scale deployment/nvt-operator -n "${NAMESPACE}" --replicas=1
  kubectl_smoke rollout status deployment/nvt-operator -n "${NAMESPACE}" --timeout="${ROLLOUT_TIMEOUT}"

  # Flush local capture from a privileged DinD child. The CNI remains the
  # enforcement boundary, so this cannot restore direct external egress.
  agent_exec "${run}" docker run --rm --privileged --network host docker:27-dind \
    sh -ec 'iptables -t nat -F NVT_CAPTURE; ! wget -q -T 5 -O- https://example.com'

  log "transparent enforced acceptance passed"
}
