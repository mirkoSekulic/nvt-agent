#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${NVT_PI_TEST_IMAGE:-nvt-agent-runtime:pi-test}"
CONTAINER="nvt-pi-smoke-$$"
FIXTURE="$(mktemp -d)"
cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$FIXTURE"
}
trap cleanup EXIT
# Only a public CA is copied into the workload. This boot proof makes no model
# request; compatibility.py covers real requests through broker and egressd.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=fixture-ca \
  -keyout "$FIXTURE/key.pem" -out "$FIXTURE/ca.crt" >/dev/null 2>&1
python3 - "$ROOT" "$FIXTURE" <<'PY'
import json,sys,yaml
from pathlib import Path
root,out=map(Path,sys.argv[1:])
r=yaml.safe_load((root/'examples/pi/manifest.example.yaml').read_text())['profiles']['pi-custom']['runtime']
args=['--model',r['model'],'--thinking',r['effort']]
config={'runtime':{'command':'pi','args':args,'resume':{'command':'pi','args':args},'pi':r['pi'],'proxy':{'provider':r['credentialProvider']}},'egress':{'mode':'mediated','transport':'forward-proxy','forward-proxy-url':'http://127.0.0.1:1','grants':[{'provider':r['credentialProvider'],'materialization':'header-inject'}]},'plugins':[{'name':'work-control','source':'builtin'}],'code-server':{'agentTerminal':{'openOnStartup':True}}}
config['preseed']={'files':[{'path':'.nvt-agent/pi/agent/models.json','overwrite':True,'json':{'providers':{'stale':{'apiKey':'FAKE-STALE-PRESEED'}}}}]}
(out/'agent.yaml').write_text(json.dumps(config))
PY
docker create --name "$CONTAINER" --publish '127.0.0.1::4090' \
  --env NVT_AGENT_CONFIG_FILE=/tmp/agent.yaml --env NVT_EGRESS_CA_FILE=/tmp/ca.crt \
  "$IMAGE" >/dev/null
docker cp "$FIXTURE/agent.yaml" "$CONTAINER:/tmp/agent.yaml"
docker cp "$FIXTURE/ca.crt" "$CONTAINER:/tmp/ca.crt"
docker start "$CONTAINER" >/dev/null
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" test -f /root/.nvt-agent/agentd/session-launched 2>/dev/null; then break; fi
  if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" != true ]; then docker logs "$CONTAINER"; exit 1; fi
  sleep 1
done
if ! docker exec "$CONTAINER" test -f /root/.nvt-agent/agentd/session-launched; then
  docker logs "$CONTAINER"
  exit 1
fi
docker exec "$CONTAINER" python3 -c 'import json; from pathlib import Path; p=json.loads(Path("/root/.nvt-agent/pi/agent/models.json").read_text())["providers"]; assert "stale" not in p; assert all(v["apiKey"] == "NVT-PLACEHOLDER-NOT-A-KEY" for v in p.values())'
docker exec "$CONTAINER" pi --version
docker exec "$CONTAINER" tmux capture-pane -p -t agent > "$FIXTURE/terminal.txt"
grep -q 'example-model' "$FIXTURE/terminal.txt"
docker exec "$CONTAINER" bash -lc 'source "$HOME/.nvt-agent/env"; command -v nvt-work; test -s /workspace/AGENTS.md; test -f "$NVT_STATE_DIR/runtime-session.json"'
# Existing gateway proof verifies the real workbench, assets, and WebSocket
# upgrade while Pi runs in the terminal opened by the bundled NVT extension.
PUBLISHED="$(docker port "$CONTAINER" 4090/tcp)"
PORT="${PUBLISHED##*:}"
(cd "$ROOT/gateway" && NVT_GATEWAY_CODE_SERVER_SMOKE_URL="http://127.0.0.1:$PORT" go test -count=1 -run '^TestRealCodeServerPathMode$' ./internal/gateway)
printf '%s\n' 'PASS: full runtime boot, Pi terminal, generated guidance, exported tools, gateway workbench/WebSocket'
