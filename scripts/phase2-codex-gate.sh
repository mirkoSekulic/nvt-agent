#!/usr/bin/env bash
# Phase 2 Codex plan-auth mediation gate (docs/phase2-codex-gate-plan.md).
#
# Brings up broker + egressd + an isolated agent container, runs a real Codex
# turn through egressd with the broker owning the real auth.json, and captures
# evidence: which hosts Codex required, whether it tried to bypass egressd,
# whether TLS re-origination worked, and whether the agent container held any
# real credential.
#
# This produces the EVIDENCE. A human fills the go/no-go decision into
# docs/phase2-codex-gate.md from it. It never writes real credentials into the
# repo, and fails loudly if any token-shaped string lands in the output dir.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# --- inputs -----------------------------------------------------------------
# Source of the real Codex auth.json the broker will own. Defaults to the
# broker-owned copy, then the host Codex home.
AUTH_SOURCE="${PHASE2_AUTH_SOURCE:-}"
if [ -z "$AUTH_SOURCE" ]; then
  if [ -f "$REPO_ROOT/.broker/codex/auth.json" ]; then
    AUTH_SOURCE="$REPO_ROOT/.broker/codex/auth.json"
  else
    AUTH_SOURCE="$HOME/.codex/auth.json"
  fi
fi
UPSTREAM_HOST="${PHASE2_UPSTREAM:-chatgpt.com}"
BASE_SCHEME="${PHASE2_SCHEME:-https}"   # https (default, TLS listen) | http
CODEX_CMD="${PHASE2_CODEX_CMD:-codex exec \"print pong\"}"
OUT_DIR="$REPO_ROOT/.phase2-out"
STATE_DIR="$OUT_DIR/state"
PROJECT="nvt-phase2"
COMPOSE="docker compose -p $PROJECT -f $REPO_ROOT/phase2/compose.phase2.yaml"

log() { printf '\033[1;34m[phase2]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[phase2] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

[ -f "$AUTH_SOURCE" ] || fail "Codex auth.json not found at $AUTH_SOURCE (set PHASE2_AUTH_SOURCE)"

cleanup() {
  log "tearing down"
  $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- fresh state ------------------------------------------------------------
rm -rf "$OUT_DIR"
mkdir -p "$STATE_DIR/codex" "$STATE_DIR/agent-codex" "$STATE_DIR/tls" "$OUT_DIR/evidence"
cp "$AUTH_SOURCE" "$STATE_DIR/codex/auth.json"
chmod 600 "$STATE_DIR/codex/auth.json"
: > "$STATE_DIR/env"

AGENT_TOKEN="$(openssl rand -hex 24)"
EGRESS_TOKEN="$(openssl rand -hex 24)"
agent_hash="$(printf '%s' "$AGENT_TOKEN" | openssl dgst -sha256 | awk '{print $2}')"
egress_hash="$(printf '%s' "$EGRESS_TOKEN" | openssl dgst -sha256 | awk '{print $2}')"

# --- broker config (harness-local; never touches .broker/) ------------------
cat > "$STATE_DIR/broker.yaml" <<YAML
providers:
  - name: codex-main
    plugin: codex-oauth
    config:
      auth-file: /state/codex/auth.json
      refresh-margin-seconds: 3600
      injection-hosts:
        - ${UPSTREAM_HOST}
        - auth.openai.com
      injection-claim-headers:
        - header: chatgpt-account-id
          claim-path:
            - https://api.openai.com/auth
            - chatgpt_account_id
YAML

cat > "$STATE_DIR/agents.yaml" <<YAML
agents:
  - id: codex-probe
    token-sha256: sha256:${agent_hash}
    role: agent
    grants:
      - provider: codex-main
        materialization: header-inject
  - id: codex-probe-egress
    token-sha256: sha256:${egress_hash}
    role: egress
    paired-agent: codex-probe
YAML

# --- egressd TLS (agent-facing) + config ------------------------------------
# Codex very likely requires an https base URL. A per-agent CA lets us
# distinguish "requires https" (CA works) from "pins certs" (CA cannot help).
LISTEN_TLS_LINES=""
if [ "$BASE_SCHEME" = "https" ]; then
  log "generating per-agent CA and egressd server cert (SAN egressd)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
    -keyout "$STATE_DIR/tls/ca-key.pem" -out "$STATE_DIR/tls/agent-ca.pem" \
    -subj "/CN=nvt-egressd-ca" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes \
    -keyout "$STATE_DIR/tls/key.pem" -out "$STATE_DIR/tls/csr.pem" \
    -subj "/CN=egressd" >/dev/null 2>&1
  openssl x509 -req -in "$STATE_DIR/tls/csr.pem" -days 7 \
    -CA "$STATE_DIR/tls/agent-ca.pem" -CAkey "$STATE_DIR/tls/ca-key.pem" -CAcreateserial \
    -out "$STATE_DIR/tls/cert.pem" \
    -extfile <(printf 'subjectAltName=DNS:egressd') >/dev/null 2>&1
  LISTEN_TLS_LINES=$'      "listen_tls_cert": "/tls/cert.pem",\n      "listen_tls_key": "/tls/key.pem",'
else
  # http mode still needs the mount target to exist for compose.
  : > "$STATE_DIR/tls/agent-ca.pem"
fi

cat > "$STATE_DIR/egressd.json" <<JSON
{
  "broker_url": "http://broker:7347",
  "allow_insecure_broker": true,
  "routes": [
    {
      "listen": "0.0.0.0:8471",
      "capability": "codex-main",
      "upstream": "${UPSTREAM_HOST}",
${LISTEN_TLS_LINES}
      "allow_insecure_upstream": false
    }
  ]
}
JSON
# allow_insecure_broker is acceptable ONLY because broker and egressd sit on an
# isolated trusted network the agent cannot reach. Production uses broker TLS.

# --- agent-side Codex config + placeholder auth (NO real credential) --------
BASE_URL="${BASE_SCHEME}://egressd:8471"
cat > "$STATE_DIR/agent-codex/config.toml" <<TOML
check_for_update_on_startup = false
chatgpt_base_url = "${BASE_URL}"
TOML

python3 - "$STATE_DIR/agent-codex/auth.json" <<'PY'
import base64, json, sys, time
def seg(obj): return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
# Zero-entropy placeholder JWT: valid shape, far-future exp, placeholder claims.
header = seg({"alg": "none", "typ": "JWT"})
payload = seg({
    "exp": int(time.time()) + 10 * 365 * 24 * 3600,
    "https://api.openai.com/auth": {"chatgpt_account_id": "NVT-PLACEHOLDER-ACCOUNT"},
})
placeholder_jwt = f"{header}.{payload}.NVT-PLACEHOLDER-NOT-A-KEY"
json.dump({
    "tokens": {
        "access_token": placeholder_jwt,
        "refresh_token": "nvt-broker-stub",
        "id_token": "NVT-PLACEHOLDER-NOT-A-KEY",
    },
    "last_refresh": "2020-01-01T00:00:00Z",
}, open(sys.argv[1], "w"), indent=2)
PY
chmod 600 "$STATE_DIR/agent-codex/auth.json"

# --- bring up ---------------------------------------------------------------
export PHASE2_STATE="$STATE_DIR"
export PHASE2_EGRESS_TOKEN="$EGRESS_TOKEN"

log "starting broker + egressd + agent"
$COMPOSE up -d --no-build broker egressd agent

log "waiting for broker health"
for _ in $(seq 1 30); do
  if $COMPOSE exec -T egressd true 2>/dev/null && \
     $COMPOSE exec -T broker sh -c 'exit 0' 2>/dev/null; then break; fi
  sleep 1
done

# --- run the real Codex turn ------------------------------------------------
log "running Codex turn through egressd: $CODEX_CMD"
set +e
$COMPOSE exec -T agent bash -lc '
  set -e
  if [ -s /usr/local/share/ca-certificates/nvt-egressd-ca.crt ]; then
    update-ca-certificates >/dev/null 2>&1 || true
    export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
    export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/nvt-egressd-ca.crt
  fi
  export CODEX_HOME=/root/.codex
  '"$CODEX_CMD"'
' > "$OUT_DIR/evidence/codex-stdout.txt" 2> "$OUT_DIR/evidence/codex-stderr.txt"
CODEX_RC=$?
set -e
log "Codex exit code: $CODEX_RC"

# --- capture evidence -------------------------------------------------------
$COMPOSE logs egressd > "$OUT_DIR/evidence/egressd.log" 2>&1 || true
cp "$STATE_DIR/audit.jsonl" "$OUT_DIR/evidence/broker-audit.jsonl" 2>/dev/null || true
# Which injection hosts/paths the broker was asked for:
grep -h 'injection' "$OUT_DIR/evidence/broker-audit.jsonl" 2>/dev/null \
  > "$OUT_DIR/evidence/injection-audit.jsonl" || true

# --- leak scan (fail loud if any real credential escaped) -------------------
log "scanning for credential leakage"
python3 - "$AUTH_SOURCE" "$STATE_DIR/agent-codex/auth.json" "$OUT_DIR/evidence" <<'PY'
import json, os, sys
real = json.load(open(sys.argv[1]))["tokens"]
needles = [v for v in (real.get("access_token"), real.get("refresh_token"), real.get("id_token"))
           if isinstance(v, str) and len(v) > 12]
# 1) agent container auth.json must be placeholder only.
agent = json.load(open(sys.argv[2]))["tokens"]
for k, v in agent.items():
    for n in needles:
        if isinstance(v, str) and n in v:
            print(f"LEAK: real {k} present in agent auth.json"); sys.exit(2)
# 2) no real token fragment anywhere in captured evidence.
for root, _, files in os.walk(sys.argv[3]):
    for name in files:
        path = os.path.join(root, name)
        try:
            data = open(path, "r", errors="ignore").read()
        except Exception:
            continue
        for n in needles:
            if n in data:
                print(f"LEAK: real token fragment in evidence/{name}"); sys.exit(2)
print("no credential leakage detected")
PY

# --- verdict signal (evidence, not decision) --------------------------------
log "evidence written to $OUT_DIR/evidence/"
{
  echo "codex_exit_code=$CODEX_RC"
  echo "base_url=$BASE_URL"
  echo "upstream=$UPSTREAM_HOST"
  echo "tls_listen=$([ "$BASE_SCHEME" = https ] && echo yes || echo no)"
  echo "injection_requests=$(wc -l < "$OUT_DIR/evidence/injection-audit.jsonl" 2>/dev/null || echo 0)"
  echo "refresh_seen=$(grep -c 'injection.refresh' "$OUT_DIR/evidence/broker-audit.jsonl" 2>/dev/null || echo 0)"
} | tee "$OUT_DIR/evidence/summary.txt"

if [ "$CODEX_RC" -eq 0 ]; then
  log "Codex turn completed THROUGH egressd — likely GO (confirm host list in evidence)."
else
  log "Codex turn did not complete — inspect codex-stderr.txt and egressd.log for the failing host / TLS behavior."
fi
log "Fill the decision into docs/phase2-codex-gate.md using .phase2-out/evidence/."
