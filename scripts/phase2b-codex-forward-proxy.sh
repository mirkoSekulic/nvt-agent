#!/usr/bin/env bash
# Phase 2b Codex CONNECT-only forward proxy harness.
#
# This runs real Codex through egressd as a forward proxy using the existing
# Codex auth.json mounted into the agent container. It proves proxy plumbing
# only. Codex still possesses and uses its normal auth in this harness.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

AUTH_SOURCE="${PHASE2B_AUTH_SOURCE:-}"
if [ -z "$AUTH_SOURCE" ]; then
  if [ -f "$REPO_ROOT/.broker/codex/auth.json" ]; then
    AUTH_SOURCE="$REPO_ROOT/.broker/codex/auth.json"
  else
    AUTH_SOURCE="$HOME/.codex/auth.json"
  fi
fi
CODEX_CMD="${PHASE2B_CODEX_CMD:-codex exec --skip-git-repo-check \"print pong\"}"
OUT_DIR="$REPO_ROOT/.phase2b-out"
STATE_DIR="$OUT_DIR/state"
PROJECT="nvt-phase2b"
COMPOSE="docker compose -p $PROJECT -f $REPO_ROOT/phase2/compose.phase2b.yaml"

log() { printf '\033[1;34m[phase2b]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[phase2b] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

[ -f "$AUTH_SOURCE" ] || fail "Codex auth.json not found at $AUTH_SOURCE (set PHASE2B_AUTH_SOURCE)"

cleanup() {
  log "tearing down"
  $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$OUT_DIR"
mkdir -p "$STATE_DIR/agent-codex" "$OUT_DIR/evidence"
cp "$AUTH_SOURCE" "$STATE_DIR/agent-codex/auth.json"
chmod 600 "$STATE_DIR/agent-codex/auth.json"

cat > "$STATE_DIR/agent-codex/config.toml" <<'TOML'
check_for_update_on_startup = false
TOML

cat > "$STATE_DIR/egressd.json" <<'JSON'
{
  "forward_proxy": {
    "listen": "0.0.0.0:8471",
    "allow_hosts": [
      "chatgpt.com",
      "ab.chatgpt.com",
      "github.com",
      "api.openai.com"
    ]
  }
}
JSON

export PHASE2B_STATE="$STATE_DIR"

log "starting egressd forward proxy + isolated agent"
$COMPOSE up -d --no-build egressd agent

for _ in $(seq 1 30); do
  egressd_container="$($COMPOSE ps -q egressd 2>/dev/null || true)"
  if [ -n "$egressd_container" ] &&
     [ "$(docker inspect -f '{{.State.Running}}' "$egressd_container" 2>/dev/null || true)" = "true" ]; then
    break
  fi
  sleep 1
done

log "running Codex through HTTP(S)_PROXY=http://egressd:8471"
set +e
$COMPOSE exec -T agent bash -lc '
  set -e
  export CODEX_HOME=/root/.codex
  export HTTPS_PROXY=http://egressd:8471
  export HTTP_PROXY=http://egressd:8471
  export ALL_PROXY=http://egressd:8471
  export NO_PROXY=localhost,127.0.0.1,::1,broker,egressd
  '"$CODEX_CMD"' < /dev/null
' > "$OUT_DIR/evidence/codex-stdout.txt" 2> "$OUT_DIR/evidence/codex-stderr.txt"
CODEX_RC=$?
set -e

$COMPOSE logs --no-log-prefix egressd > "$OUT_DIR/evidence/egressd.log" 2>&1 || true

if grep -Ei 'authorization|cookie|set-cookie|bearer|token|refresh|access_token|id_token' "$OUT_DIR/evidence/egressd.log" >/dev/null; then
  fail "egressd log contains credential/header-shaped text; inspect $OUT_DIR/evidence/egressd.log"
fi
if ! grep -q 'event=connect .* decision=allow' "$OUT_DIR/evidence/egressd.log"; then
  fail "no allowed CONNECT decision found in egressd log"
fi
if ! grep -q 'pong' "$OUT_DIR/evidence/codex-stdout.txt"; then
  fail "Codex did not print pong; see $OUT_DIR/evidence"
fi

{
  echo "codex_exit_code=$CODEX_RC"
  echo "proxy_url=http://egressd:8471"
  echo "allow_hosts=chatgpt.com,ab.chatgpt.com,github.com,api.openai.com"
  echo "credentialless_codex=no"
  echo "allowed_connects=$(grep -c 'event=connect .* decision=allow' "$OUT_DIR/evidence/egressd.log" 2>/dev/null || echo 0)"
} | tee "$OUT_DIR/evidence/summary.txt"

if [ "$CODEX_RC" -ne 0 ]; then
  fail "Codex exited with $CODEX_RC; see $OUT_DIR/evidence"
fi

log "Phase 2b forward-proxy plumbing passed; evidence written to $OUT_DIR/evidence/"
