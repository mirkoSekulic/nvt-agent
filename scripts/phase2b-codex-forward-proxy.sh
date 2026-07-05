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

OUT_DIR="$REPO_ROOT/.phase2b-out"
STATE_DIR="$OUT_DIR/state"
EVIDENCE_DIR="$OUT_DIR/evidence"
PROJECT="nvt-phase2b"
COMPOSE="docker compose -p $PROJECT -f $REPO_ROOT/phase2/compose.phase2b.yaml"
PROXY_URL="http://egressd:8471"
ALLOW_HOSTS=(chatgpt.com ab.chatgpt.com github.com api.openai.com auth.openai.com)
ALLOW_HOSTS_CSV="$(IFS=,; echo "${ALLOW_HOSTS[*]}")"
NONCE="phase2b-$(date +%s)-$$"
CODEX_RC="not_run"
FAILURE_REASON=""
EGRESSD_LOG="$EVIDENCE_DIR/egressd.log"
CODEX_STDOUT="$EVIDENCE_DIR/codex-stdout.txt"
CODEX_STDERR="$EVIDENCE_DIR/codex-stderr.txt"
CODEX_LAST="$EVIDENCE_DIR/codex-last-message.txt"
SUMMARY="$EVIDENCE_DIR/summary.txt"

log() { printf '\033[1;34m[phase2b]\033[0m %s\n' "$*"; }
fail() {
  FAILURE_REASON="$*"
  printf '\033[1;31m[phase2b] FAIL:\033[0m %s\n' "$*" >&2
  exit 1
}

count_allowed_connects() {
  if [ -f "$EGRESSD_LOG" ]; then
    grep -c 'event=connect .* decision=allow' "$EGRESSD_LOG" || true
  else
    echo 0
  fi
}

capture_egressd_logs() {
  mkdir -p "$EVIDENCE_DIR"
  $COMPOSE logs --no-log-prefix egressd > "$EGRESSD_LOG" 2>&1 || true
}

write_summary() {
  mkdir -p "$EVIDENCE_DIR"
  {
    echo "codex_exit_code=$CODEX_RC"
    echo "proxy_url=$PROXY_URL"
    echo "allow_hosts=$ALLOW_HOSTS_CSV"
    echo "credentialless_codex=no"
    echo "allowed_connects=$(count_allowed_connects)"
    if [ -n "$FAILURE_REASON" ]; then
      echo "failure_reason=$FAILURE_REASON"
    fi
  } > "$SUMMARY"
}

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ -z "$FAILURE_REASON" ]; then
    FAILURE_REASON="unexpected exit $rc"
  fi
  capture_egressd_logs
  write_summary
  log "tearing down"
  $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$STATE_DIR/agent-codex/auth.json"
  exit "$rc"
}
trap cleanup EXIT

rm -rf "$OUT_DIR"
mkdir -p "$STATE_DIR/agent-codex" "$EVIDENCE_DIR"

[ -f "$AUTH_SOURCE" ] || fail "Codex auth.json not found at $AUTH_SOURCE (set PHASE2B_AUTH_SOURCE)"

cp "$AUTH_SOURCE" "$STATE_DIR/agent-codex/auth.json"
chmod 600 "$STATE_DIR/agent-codex/auth.json"

cat > "$STATE_DIR/agent-codex/config.toml" <<'TOML'
check_for_update_on_startup = false
TOML

{
  cat <<'JSON'
{
  "forward_proxy": {
    "listen": "0.0.0.0:8471",
    "allow_hosts": [
JSON
  for index in "${!ALLOW_HOSTS[@]}"; do
    comma=","
    if [ "$index" -eq "$((${#ALLOW_HOSTS[@]} - 1))" ]; then
      comma=""
    fi
    printf '      "%s"%s\n' "${ALLOW_HOSTS[$index]}" "$comma"
  done
  cat <<'JSON'
    ]
  }
}
JSON
} > "$STATE_DIR/egressd.json"

export PHASE2B_STATE="$STATE_DIR"

log "starting egressd forward proxy + isolated agent"
$COMPOSE up -d --no-build egressd agent

for attempt in $(seq 1 30); do
  if $COMPOSE exec -T agent bash -lc '</dev/tcp/egressd/8471' >/dev/null 2>&1; then
    break
  fi
  if [ "$attempt" -eq 30 ]; then
    capture_egressd_logs
    fail "egressd forward proxy did not become reachable at egressd:8471; see $EGRESSD_LOG"
  fi
  sleep 1
done

log "running Codex through HTTP(S)_PROXY=$PROXY_URL"
set +e
$COMPOSE exec -T \
  -e PHASE2B_NONCE="$NONCE" \
  -e PHASE2B_CODEX_CMD="${PHASE2B_CODEX_CMD:-}" \
  agent bash -lc '
  set -e
  export CODEX_HOME=/root/.codex
  export HTTPS_PROXY=http://egressd:8471
  export HTTP_PROXY=http://egressd:8471
  export ALL_PROXY=http://egressd:8471
  export NO_PROXY=localhost,127.0.0.1,::1,broker,egressd
  if [ -n "$PHASE2B_CODEX_CMD" ]; then
    eval "$PHASE2B_CODEX_CMD" < /dev/null
    exit
  fi
  prompt="Reply with exactly this nonce and no other text: ${PHASE2B_NONCE}"
  if codex exec --help 2>&1 | grep -q -- "--output-last-message"; then
    codex exec --skip-git-repo-check --output-last-message /tmp/phase2b-last-message.txt "$prompt" < /dev/null
    cat /tmp/phase2b-last-message.txt
  else
    codex exec --skip-git-repo-check "$prompt" < /dev/null
  fi
' > "$CODEX_STDOUT" 2> "$CODEX_STDERR"
CODEX_RC=$?
set -e

capture_egressd_logs
cp "$CODEX_STDOUT" "$CODEX_LAST"

if grep -Ei '(authorization:|proxy-authorization:|cookie:|set-cookie:|bearer[[:space:]]+[A-Za-z0-9._~+/-]+=*|access_token[=:]|id_token[=:]|refresh_token[=:])' "$EGRESSD_LOG" >/dev/null; then
  fail "egressd log contains credential/header-shaped text; inspect $EGRESSD_LOG"
fi
if ! grep -q 'event=connect .* decision=allow' "$EGRESSD_LOG"; then
  fail "no allowed CONNECT decision found in egressd log"
fi
if [ "$CODEX_RC" -ne 0 ]; then
  fail "Codex exited with $CODEX_RC; see $EVIDENCE_DIR"
fi
if [ "$(awk 'NF { line=$0 } END { print line }' "$CODEX_LAST")" != "$NONCE" ]; then
  fail "Codex final answer did not match nonce $NONCE; see $EVIDENCE_DIR"
fi

write_summary
log "Phase 2b forward-proxy plumbing passed; evidence written to $EVIDENCE_DIR/"
