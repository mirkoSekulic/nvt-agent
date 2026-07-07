#!/usr/bin/env bash
set -euo pipefail

# Manual, opt-in real-Codex forward-proxy proof
# (docs/real-codex-forward-proxy-proof.md). NOT run in CI: it needs real host
# Codex auth. It stands up a Calico kind cluster, seeds the broker with the
# host Codex credential, runs `codex exec` inside a mediated + enforced +
# forward-proxy AgentRun whose codex-main grant is materialization
# placeholder-file, and records evidence under an ignored output directory.
#
# Usage:
#   make phase6-real-codex-proof            # uses ~/.codex
#   CODEX_AUTH_SOURCE=/path/to/.codex make phase6-real-codex-proof
#
# Requires: kind, kubectl, helm, docker, and a working host Codex login.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CLUSTER="${CLUSTER:-nvt-codex-proof}"
NAMESPACE="${NAMESPACE:-nvt}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-kind-${CLUSTER}}"
CODEX_AUTH_SOURCE="${CODEX_AUTH_SOURCE:-${HOME}/.codex}"
CODEX_AUTH_SECRET="${CODEX_AUTH_SECRET:-codex-auth}"
ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT:-300s}"
# Unique per invocation so a rerun always creates a fresh AgentRun/pod (an
# apply over the previous run's still-sleeping pod would not start a new turn).
RUN_NAME="${RUN_NAME:-real-codex-proof-$(date +%s)}"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT}/.phase6-out/real-codex-proof}"
# A fixed-per-run nonce the model must echo back; passed in so the script stays
# reproducible (no Date/Random at import time in the harness values file).
PROOF_NONCE="${PROOF_NONCE:-NVT_CODEX_PROOF_$(date +%s)}"

KUBECTL=(kubectl --context "${KUBECTL_CONTEXT}")

log() { printf '[phase6-real-codex-proof] %s\n' "$*"; }
die() { printf '[phase6-real-codex-proof] ERROR: %s\n' "$*" >&2; exit 1; }

[[ -d "${CODEX_AUTH_SOURCE}" ]] || die "CODEX_AUTH_SOURCE must be an existing Codex auth dir: ${CODEX_AUTH_SOURCE}"
[[ -f "${CODEX_AUTH_SOURCE}/auth.json" ]] || die "missing ${CODEX_AUTH_SOURCE}/auth.json — log into Codex first"

mkdir -p "${OUTPUT_DIR}"
SUMMARY="${OUTPUT_DIR}/summary.txt"
: >"${SUMMARY}"

# 1 + 2: Calico cluster + namespace + images.
log "creating Calico kind cluster ${CLUSTER} and loading images"
make -C "${ROOT}" CLUSTER="${CLUSTER}" KUBECTL_CONTEXT="${KUBECTL_CONTEXT}" ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT}" operator-kind-cluster-enforced
make -C "${ROOT}" CLUSTER="${CLUSTER}" operator-kind-images
"${KUBECTL[@]}" create namespace "${NAMESPACE}" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f -

# 3: filtered codex-auth Secret from the host (never printed).
log "seeding Secret ${NAMESPACE}/${CODEX_AUTH_SECRET} from ${CODEX_AUTH_SOURCE}"
CODEX_AUTH_SOURCE="${CODEX_AUTH_SOURCE}" CODEX_AUTH_SECRET="${CODEX_AUTH_SECRET}" \
  NAMESPACE="${NAMESPACE}" CLUSTER="${CLUSTER}" KUBECTL_CONTEXT="${KUBECTL_CONTEXT}" \
  bash "${ROOT}/scripts/operator-codex-auth-secret.sh"

# 4: install nvt with broker persistence + codex-main provider config.
VALUES="${OUTPUT_DIR}/values.yaml"
cat >"${VALUES}" <<YAML
broker:
  persistence:
    enabled: true
    seedSecretName: ${CODEX_AUTH_SECRET}
    seedTargetDir: codex
  config:
    providers:
      - name: codex-main
        plugin: codex-oauth
        config:
          auth-file: /state/codex/auth.json
          injection-hosts:
            - chatgpt.com
            - api.openai.com
            - auth.openai.com
          placeholder-file:
            path: .codex/auth.json
            hosts:
              - chatgpt.com
              - api.openai.com
              - auth.openai.com
            id-token-claims:
              - claim: chatgpt_account_id
                claim-path:
                  - https://api.openai.com/auth
                  - chatgpt_account_id
          injection-claim-headers:
            - header: ChatGPT-Account-ID
              claim-path:
                - https://api.openai.com/auth
                - chatgpt_account_id
        allow:
          repositories:
            - example/*
egress:
  allowInsecureUpstreams: false
YAML
log "installing chart with broker persistence + codex-main provider"
make -C "${ROOT}" CLUSTER="${CLUSTER}" NAMESPACE="${NAMESPACE}" KUBECTL_CONTEXT="${KUBECTL_CONTEXT}" \
  ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT}" OPERATOR_KIND_HELM_ARGS="-f ${VALUES}" operator-kind-setup

# 5: submit a forward-proxy placeholder-file AgentRun that runs codex exec.
RUN_YAML="${OUTPUT_DIR}/agentrun.yaml"
python3 - "${RUN_NAME}" "${NAMESPACE}" "${PROOF_NONCE}" >"${RUN_YAML}" <<'PY'
import json
import sys

run_name, namespace, nonce = sys.argv[1], sys.argv[2], sys.argv[3]
prompt = f"Reply with exactly this token and nothing else: {nonce}"
spec = {
    "runtime": {"type": "codex", "autonomy": "trusted-local"},
    "image": "nvt-agent-runtime:latest",
    "egress": "mediated",
    "egressEnforcement": True,
    "egressForwardProxy": True,
    "workspace": {"mode": "Ephemeral"},
    "broker": {"grants": [{
        "provider": "codex-main",
        "repositories": ["example/repo"],
        "materialization": "placeholder-file",
        "egressHosts": ["chatgpt.com:443", "api.openai.com:443", "auth.openai.com:443"],
    }]},
    "agent": {"config": {
        "runtime": {"command": "bash", "args": ["-lc",
            f'codex exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check '
            f'--output-last-message /tmp/last-message {json.dumps(prompt)} '
            f'>/tmp/codex.stdout 2>/tmp/codex.stderr; echo done; sleep infinity']},
        "tools": {"packages": [], "mise": [], "additional-paths": [], "shell": []},
        "code-server": {"extensions": []},
    }},
    "ttl": {"activeDeadlineSeconds": 1800},
}
doc = {"apiVersion": "nvt.dev/v1alpha1", "kind": "AgentRun",
       "metadata": {"name": run_name, "namespace": namespace}, "spec": spec}
print(json.dumps(doc))
PY
log "submitting forward-proxy placeholder-file AgentRun ${RUN_NAME}"
# Defensive even with a unique name: if an explicit RUN_NAME is reused, delete
# the prior AgentRun and wait for its agent pod to clear so the new run is not
# racing a stale, still-sleeping pod.
if "${KUBECTL[@]}" -n "${NAMESPACE}" get agentrun "${RUN_NAME}" >/dev/null 2>&1; then
  log "deleting pre-existing AgentRun ${RUN_NAME}"
  "${KUBECTL[@]}" -n "${NAMESPACE}" delete agentrun "${RUN_NAME}" --wait=true --timeout="${ROLLOUT_TIMEOUT}" || true
  "${KUBECTL[@]}" -n "${NAMESPACE}" wait --for=delete "pod/${RUN_NAME}-agent" --timeout="${ROLLOUT_TIMEOUT}" 2>/dev/null || true
fi
"${KUBECTL[@]}" apply -f "${RUN_YAML}"

# 6: wait for the agent Pod and the codex turn to finish.
log "waiting for agent Pod ${RUN_NAME}-agent"
"${KUBECTL[@]}" -n "${NAMESPACE}" wait --for=condition=Ready "pod/${RUN_NAME}-agent" --timeout="${ROLLOUT_TIMEOUT}" || true
log "waiting for codex exec to complete (up to 10m)"
deadline=$(( $(date +%s) + 600 ))
while (( $(date +%s) < deadline )); do
  if "${KUBECTL[@]}" -n "${NAMESPACE}" exec "${RUN_NAME}-agent" -c agent -- test -f /tmp/last-message 2>/dev/null; then
    break
  fi
  sleep 5
done

# 7: collect evidence.
collect() {
  local label="$1"; shift
  "${KUBECTL[@]}" -n "${NAMESPACE}" exec "${RUN_NAME}-agent" -c agent -- "$@" >"${OUTPUT_DIR}/${label}" 2>/dev/null || true
}
log "collecting evidence into ${OUTPUT_DIR}"
collect codex.stdout cat /tmp/codex.stdout
collect codex.stderr cat /tmp/codex.stderr
collect last-message cat /tmp/last-message
collect agent-auth.json cat "/root/.codex/auth.json"
collect proxy-env bash -lc 'env | grep -Ei "PROXY" | sort'
"${KUBECTL[@]}" -n "${NAMESPACE}" logs "${RUN_NAME}-egressd" >"${OUTPUT_DIR}/egressd.log" 2>/dev/null || true
"${KUBECTL[@]}" -n "${NAMESPACE}" logs deployment/nvt-broker >"${OUTPUT_DIR}/broker.log" 2>/dev/null || true
"${KUBECTL[@]}" -n "${NAMESPACE}" exec deployment/nvt-broker -- cat /state/audit.jsonl >"${OUTPUT_DIR}/broker-audit.jsonl" 2>/dev/null || true
# Copy the agent home Codex/proof files for an offline secret scan.
"${KUBECTL[@]}" -n "${NAMESPACE}" cp "${RUN_NAME}-agent:/root/.codex" "${OUTPUT_DIR}/agent-codex" -c agent 2>/dev/null || true

# 8: secret scan — the real host access/refresh tokens must not appear.
log "scanning copied agent files and collected evidence for host Codex token material"
SCAN_RESULT="clean"
# Scan the copied agent Codex dir plus every collected evidence file (codex
# stdout/stderr, proxy env, egressd + broker logs) for the real host tokens.
python3 - "${CODEX_AUTH_SOURCE}/auth.json" \
  "${OUTPUT_DIR}/agent-codex" \
  "${OUTPUT_DIR}/agent-auth.json" \
  "${OUTPUT_DIR}/codex.stdout" \
  "${OUTPUT_DIR}/codex.stderr" \
  "${OUTPUT_DIR}/last-message" \
  "${OUTPUT_DIR}/proxy-env" \
  "${OUTPUT_DIR}/egressd.log" \
  "${OUTPUT_DIR}/broker.log" \
  "${OUTPUT_DIR}/broker-audit.jsonl" \
  >"${OUTPUT_DIR}/secret-scan.txt" 2>&1 <<'PY' || SCAN_RESULT="FAIL"
import json
import os
import sys

auth_path, *scan_targets = sys.argv[1:]
with open(auth_path, "r", encoding="utf-8") as handle:
    tokens = json.load(handle).get("tokens", {})
needles = [v for k, v in tokens.items() if isinstance(v, str) and v and k in ("access_token", "refresh_token", "id_token")]
placeholder = "NVT-PLACEHOLDER-NOT-A-KEY"
needles = [n for n in needles if n and n != placeholder]

hits = []
scanned = 0
for target in scan_targets:
    if os.path.isfile(target):
        files = [target]
    else:
        files = [os.path.join(dp, f) for dp, _, fs in os.walk(target) for f in fs]
    for path in files:
        scanned += 1
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                text = handle.read()
        except OSError:
            continue
        for needle in needles:
            if needle in text:
                hits.append(os.path.basename(path))
print("secret_hits", sorted(set(hits)))
print("files_scanned", scanned)
if hits:
    raise SystemExit(1)
PY

# 9: emit the summary.
last_message="$(cat "${OUTPUT_DIR}/last-message" 2>/dev/null || true)"
normal_turn="FAIL"
[[ "${last_message}" == *"${PROOF_NONCE}"* ]] && normal_turn="PASS"
websocket="unproven"
if grep -qi "Falling back from WebSockets" "${OUTPUT_DIR}/codex.stderr" 2>/dev/null; then
  websocket="fallback-to-https (WSS unproven)"
elif grep -Eq '"status"[[:space:]]*:[[:space:]]*101' "${OUTPUT_DIR}/broker-audit.jsonl" 2>/dev/null; then
  websocket="PASS (101 Switching Protocols audited)"
fi
{
  echo "nonce:          ${PROOF_NONCE}"
  echo "normal_turn:    ${normal_turn}"
  echo "websocket:      ${websocket}"
  echo "refresh:        unproven (not forced this run)"
  echo "secret_scan:    ${SCAN_RESULT}"
  echo "evidence_dir:   ${OUTPUT_DIR}"
} | tee "${SUMMARY}"

[[ "${normal_turn}" == "PASS" && "${SCAN_RESULT}" == "clean" ]] || die "proof did not pass — see ${OUTPUT_DIR}"
if [[ "${websocket}" == PASS* ]]; then
  log "real Codex forward-proxy proof PASSED (normal turn + WebSocket; refresh remains unproven)"
else
  log "real Codex forward-proxy proof PASSED (normal turn; WebSocket/refresh remain unproven)"
fi
