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
CODEX_CMD="${PHASE2_CODEX_CMD:-codex exec --skip-git-repo-check \"print pong\"}"
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
# Force real refresh: set the margin beyond the token's remaining lifetime so
# the first injection always exercises the real refresh flow, regardless of how
# much life the source token has left. Fallback is 10y if exp can't be read.
REFRESH_MARGIN="$(python3 - "$AUTH_SOURCE" <<'PY'
import base64, json, sys, time
try:
    token = json.load(open(sys.argv[1]))["tokens"]["access_token"]
    seg = token.split(".")[1]
    seg += "=" * ((4 - len(seg) % 4) % 4)
    exp = int(json.loads(base64.urlsafe_b64decode(seg.encode()))["exp"])
    print(max(exp - int(time.time()), 0) + 86400)
except Exception:
    print(315360000)
PY
)"
log "refresh-margin-seconds=$REFRESH_MARGIN (forces real refresh on first injection)"

cat > "$STATE_DIR/broker.yaml" <<YAML
providers:
  - name: codex-main
    plugin: codex-oauth
    config:
      auth-file: /state/codex/auth.json
      refresh-margin-seconds: ${REFRESH_MARGIN}
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
  LISTEN_TLS_LINES=$'      "listen_tls_cert": "/config/tls/cert.pem",\n      "listen_tls_key": "/config/tls/key.pem",'
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
# Phase 2 gates chatgpt_base_url plan-auth traffic by default. To also exercise
# the API-style path, set PHASE2_MODEL_PROVIDER_BASE (e.g. the egressd route
# with a /v1 suffix) — recorded as a separate finding in the gate doc.
if [ -n "${PHASE2_MODEL_PROVIDER_BASE:-}" ]; then
  cat >> "$STATE_DIR/agent-codex/config.toml" <<TOML

[model_providers.openai]
base_url = "${PHASE2_MODEL_PROVIDER_BASE}"
TOML
  log "model_providers.openai.base_url=${PHASE2_MODEL_PROVIDER_BASE}"
fi

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
        "id_token": placeholder_jwt,
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
  egressd_container="$($COMPOSE ps -q egressd 2>/dev/null || true)"
  if [ -n "$egressd_container" ] && \
     [ "$(docker inspect -f '{{.State.Running}}' "$egressd_container" 2>/dev/null || true)" = "true" ] && \
     $COMPOSE exec -T broker sh -c 'exit 0' 2>/dev/null; then break; fi
  sleep 1
done

# --- run the real Codex turn ------------------------------------------------
log "running Codex turn through egressd: $CODEX_CMD"
# Sample process args in the agent container during the run so a token that
# ever appears on a command line is captured (it must not — egressd injects it).
touch "$OUT_DIR/.running"
(
  while [ -f "$OUT_DIR/.running" ]; do
    $COMPOSE exec -T agent ps -eo args 2>/dev/null || true
    sleep 0.5
  done
) > "$OUT_DIR/evidence/agent-ps-during.txt" 2>&1 &
PS_SAMPLER=$!

set +e
$COMPOSE exec -T agent bash -lc '
  set -e
  if [ -s /usr/local/share/ca-certificates/nvt-egressd-ca.crt ]; then
    update-ca-certificates >/dev/null 2>&1 || true
    export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
    export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/nvt-egressd-ca.crt
  fi
  export CODEX_HOME=/root/.codex
  '"$CODEX_CMD"' < /dev/null
' > "$OUT_DIR/evidence/codex-stdout.txt" 2> "$OUT_DIR/evidence/codex-stderr.txt"
CODEX_RC=$?
set -e
rm -f "$OUT_DIR/.running"
kill "$PS_SAMPLER" 2>/dev/null || true
wait "$PS_SAMPLER" 2>/dev/null || true
log "Codex exit code: $CODEX_RC"

# Post-run non-possession snapshot of the agent container: env, process table,
# and the entire codex home. Scanned below for real-token fragments.
$COMPOSE exec -T agent bash -lc '
  echo "=== env ==="; env
  echo "=== ps axww ==="; ps axww 2>/dev/null || true
  echo "=== codex home files ==="; find /root/.codex -type f -print -exec cat {} \; 2>/dev/null || true
  echo "=== /root listing ==="; ls -la /root 2>/dev/null || true
' > "$OUT_DIR/evidence/agent-container-scan.txt" 2>&1 || true

# --- capture evidence -------------------------------------------------------
$COMPOSE logs egressd > "$OUT_DIR/evidence/egressd.log" 2>&1 || true
cp "$STATE_DIR/audit.jsonl" "$OUT_DIR/evidence/broker-audit.jsonl" 2>/dev/null || true
# Which injection hosts/paths the broker was asked for:
grep -h 'injection' "$OUT_DIR/evidence/broker-audit.jsonl" 2>/dev/null \
  > "$OUT_DIR/evidence/injection-audit.jsonl" || true

# --- leak scan (fail loud if any real credential escaped) -------------------
# Scans for full tokens AND stable fragments (prefix, middle, suffix), across
# the agent auth.json plus all captured evidence — which now includes the
# agent container's env, process args, and codex home.
log "scanning for credential leakage (full values + fragments)"
python3 - "$AUTH_SOURCE" "$STATE_DIR/agent-codex/auth.json" "$OUT_DIR/evidence" <<'PY'
import json, os, sys

real = json.load(open(sys.argv[1]))["tokens"]

def fragments(value):
    if not isinstance(value, str) or len(value) < 20:
        return set()
    out = {value, value[:24], value[-24:]}
    if len(value) > 64:
        mid = len(value) // 2
        out.add(value[mid:mid + 24])
    return out

needles = set()
for key in ("access_token", "refresh_token", "id_token"):
    needles |= fragments(real.get(key))
if not needles:
    print("WARNING: no real token found in source to scan for", file=sys.stderr)

def scan(label, text):
    for n in needles:
        if n in text:
            print(f"LEAK: real token fragment in {label}")
            sys.exit(2)

# 1) agent container auth.json must be placeholder only (direct check).
agent = json.load(open(sys.argv[2]))["tokens"]
for key, value in agent.items():
    if isinstance(value, str):
        scan(f"agent auth.json[{key}]", value)

# 2) no real token fragment anywhere in captured evidence (env, ps, codex home,
#    egressd log, broker audit, codex stdio).
for root, _, files in os.walk(sys.argv[3]):
    for name in files:
        try:
            data = open(os.path.join(root, name), "r", errors="ignore").read()
        except Exception:
            continue
        scan(f"evidence/{name}", data)

print("no credential leakage detected (agent fs/env/args + evidence)")
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
