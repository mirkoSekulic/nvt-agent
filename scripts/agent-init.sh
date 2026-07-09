#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --name <name> [--type codex|claude] [--autonomy trusted-local|interactive] [--user root|non-root]" >&2
}

render_template() {
  local template="$1"
  local target="$2"
  python3 - "$template" "$target" <<'PY'
import os
import sys
from pathlib import Path

template = Path(sys.argv[1])
target = Path(sys.argv[2])
content = template.read_text(encoding="utf-8")
for key, value in os.environ.items():
    content = content.replace("{{" + key + "}}", value)
target.write_text(content, encoding="utf-8")
PY
}

name=""
agent_type="codex"
autonomy="trusted-local"
runtime_user="root"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --name)
      if [ "$#" -lt 2 ]; then
        usage
        exit 1
      fi
      name="$2"
      shift 2
      ;;
    --type)
      if [ "$#" -lt 2 ]; then
        usage
        exit 1
      fi
      agent_type="$2"
      shift 2
      ;;
    --autonomy)
      if [ "$#" -lt 2 ]; then
        usage
        exit 1
      fi
      autonomy="$2"
      shift 2
      ;;
    --user)
      if [ "$#" -lt 2 ]; then
        usage
        exit 1
      fi
      runtime_user="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [ -z "$name" ]; then
  usage
  exit 1
fi

case "$agent_type" in
  codex|claude) ;;
  *)
    echo "invalid agent type: $agent_type" >&2
    echo "agent type must be codex or claude" >&2
    exit 1
    ;;
esac

case "$autonomy" in
  trusted-local|interactive) ;;
  *)
    echo "invalid autonomy: $autonomy" >&2
    echo "autonomy must be trusted-local or interactive" >&2
    exit 1
    ;;
esac

# Runtime user mode. Default root is unchanged; non-root runs the agent
# container as uid/gid 1000 with HOME=/home/agent and passwordless sudo.
case "$runtime_user" in
  root)
    agent_run_user="0:0"
    agent_home="/root"
    ;;
  non-root)
    agent_run_user="1000:1000"
    agent_home="/home/agent"
    ;;
  *)
    echo "invalid user: $runtime_user" >&2
    echo "user must be root or non-root" >&2
    exit 1
    ;;
esac

runtime_args="$(python3 - "$agent_type" "$autonomy" <<'PY'
import json
import sys

agent_type, autonomy = sys.argv[1], sys.argv[2]
args = []
if autonomy == "trusted-local":
    if agent_type == "codex":
        args = ["--sandbox", "danger-full-access", "--ask-for-approval", "never"]
    elif agent_type == "claude":
        args = ["--dangerously-skip-permissions"]
    else:
        raise SystemExit(f"unsupported agent type: {agent_type}")

if not args:
    print("[]")
else:
    print()
    for arg in args:
        print(f"    - {json.dumps(arg)}")
PY
)"

agent_preseed="$(python3 - "$agent_type" <<'PY'
import sys

agent_type = sys.argv[1]
if agent_type == "codex":
    print("""preseed:
  files:
    - path: "$HOME/.codex/config.toml"
      mode: "0600"
      overwrite: false
      content: |
        check_for_update_on_startup = false""")
elif agent_type == "claude":
    print("""preseed:
  files:
    - path: "$HOME/.claude/settings.json"
      mode: "0600"
      overwrite: false
      json:
        theme: dark-daltonized
        skipDangerousModePermissionPrompt: true""")
else:
    print("preseed:\n  files: []")
PY
)"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
templates_dir="$repo_root/templates"
broker_dir="$repo_root/.broker"
broker_agents_file="$broker_dir/agents.yaml"

bash "$script_dir/validate-agent-name.sh" "$name"

agent_dir="$repo_root/.agents/$name"
env_file="$agent_dir/env"
agent_config_file="$agent_dir/agent.yaml"
egressd_config_file="$agent_dir/egressd.json"
egressd_env_file="$agent_dir/egressd.env"
egress_ca_dir="$agent_dir/egress-ca"
egress_ca_cert_file="$egress_ca_dir/ca.crt"
egress_ca_key_file="$egress_ca_dir/ca.key"
workspace_dir="$agent_dir/workspace"
local_instructions_file="$workspace_dir/AGENTS.local.md"
custom_plugins_dir="$agent_dir/custom-plugins"
claude_config_dir="$agent_dir/auth/claude"
codex_config_dir="$agent_dir/auth/codex"
host_codex_config_dir="${HOME}/.codex"
mediated="${MEDIATED:-0}"
egress_mode="direct"
compose_profiles=""
case "$mediated" in
  1|true|TRUE|True|yes|YES|Yes)
  egress_mode="mediated"
  compose_profiles="mediated"
  ;;
esac
egress_allow_insecure_broker="${NVT_EGRESS_ALLOW_INSECURE_BROKER:-0}"

mkdir -p "$workspace_dir" "$custom_plugins_dir" "$claude_config_dir" "$codex_config_dir" "$broker_dir"

if [ ! -f "$broker_dir/broker.yaml" ]; then
  cp "$templates_dir/broker.yaml" "$broker_dir/broker.yaml"
  echo "created $broker_dir/broker.yaml"
fi

if [ ! -f "$broker_agents_file" ]; then
  cp "$templates_dir/broker-agents.yaml" "$broker_agents_file"
  echo "created $broker_agents_file"
fi

if [ ! -f "$broker_dir/env" ]; then
  cp "$templates_dir/broker-env" "$broker_dir/env"
  echo "created $broker_dir/env"
fi

broker_token=""
egress_token=""
if [ -f "$env_file" ]; then
  broker_token="$(grep -E '^NVT_BROKER_TOKEN=' "$env_file" | tail -n 1 | cut -d= -f2- || true)"
fi
if [ -f "$egressd_env_file" ]; then
  egress_token="$(grep -E '^NVT_BROKER_TOKEN=' "$egressd_env_file" | tail -n 1 | cut -d= -f2- || true)"
fi
if [ -z "$broker_token" ]; then
  broker_token="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
fi
if [ "$egress_mode" = "mediated" ] && [ -z "$egress_token" ]; then
  egress_token="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
fi

if [ ! -f "$env_file" ]; then
  AGENT_NAME="$name" \
    AGENT_HOST="$name.agent.localhost" \
    AGENT_ENV_FILE="$env_file" \
    WORKSPACE_DIR="$workspace_dir" \
    NVT_WORKSPACE="$workspace_dir" \
    CUSTOM_PLUGINS_DIR="$custom_plugins_dir" \
    AGENT_CONFIG_FILE="$agent_config_file" \
    EGRESSD_CONFIG_FILE="$egressd_config_file" \
    EGRESSD_ENV_FILE="$egressd_env_file" \
    EGRESS_CA_CERT_FILE="$egress_ca_cert_file" \
    NVT_BROKER_TOKEN="$broker_token" \
    MEDIATED="$mediated" \
    NVT_EGRESS_MODE="$egress_mode" \
    NVT_EGRESS_ALLOW_INSECURE_BROKER="$egress_allow_insecure_broker" \
    COMPOSE_PROFILES="$compose_profiles" \
    CODEX_CONFIG_DIR="$codex_config_dir" \
    CLAUDE_CONFIG_DIR="$claude_config_dir" \
    AGENT_RUN_USER="$agent_run_user" \
    AGENT_HOME="$agent_home" \
    render_template "$templates_dir/env" "$env_file"
  echo "created $env_file"
else
  if grep -q '^CODEX_CONFIG_DIR=' "$env_file"; then
    python3 - "$env_file" "$codex_config_dir" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
codex_config_dir = sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines()
updated = [
    f"CODEX_CONFIG_DIR={codex_config_dir}" if line.startswith("CODEX_CONFIG_DIR=") else line
    for line in lines
]
path.write_text("\n".join(updated) + "\n", encoding="utf-8")
PY
  else
    {
      printf 'CODEX_CONFIG_DIR=%s\n' "$codex_config_dir"
    } >>"$env_file"
  fi
  if ! grep -q '^NVT_BROKER_URL=' "$env_file"; then
    {
      printf '\n'
      printf 'NVT_BROKER_URL=http://broker:7347\n'
    } >>"$env_file"
    echo "updated $env_file"
  fi
  if ! grep -q '^NVT_BROKER_TOKEN=' "$env_file"; then
    {
      printf 'NVT_BROKER_TOKEN=%s\n' "$broker_token"
    } >>"$env_file"
    echo "updated $env_file"
  fi
  if ! grep -q '^EGRESSD_CONFIG_FILE=' "$env_file"; then
    {
      printf 'EGRESSD_CONFIG_FILE=%s\n' "$egressd_config_file"
    } >>"$env_file"
  fi
  if ! grep -q '^EGRESSD_ENV_FILE=' "$env_file"; then
    {
      printf 'EGRESSD_ENV_FILE=%s\n' "$egressd_env_file"
    } >>"$env_file"
  fi
  if ! grep -q '^EGRESS_CA_CERT_FILE=' "$env_file"; then
    {
      printf 'EGRESS_CA_CERT_FILE=%s\n' "$egress_ca_cert_file"
    } >>"$env_file"
  fi
  python3 - "$env_file" "$mediated" "$egress_mode" "$egress_allow_insecure_broker" "$compose_profiles" "$agent_run_user" "$agent_home" "$egress_ca_cert_file" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
values = {
    "MEDIATED": sys.argv[2],
    "NVT_EGRESS_MODE": sys.argv[3],
    "NVT_EGRESS_ALLOW_INSECURE_BROKER": sys.argv[4],
    "COMPOSE_PROFILES": sys.argv[5],
    # Re-applying --user must actually switch an existing agent: the compose
    # user + HOME + auth/home mount targets are driven by these two vars.
    "AGENT_RUN_USER": sys.argv[6],
    "AGENT_HOME": sys.argv[7],
    "EGRESS_CA_CERT_FILE": sys.argv[8],
}
lines = path.read_text(encoding="utf-8").splitlines()
seen = set()
updated = []
for line in lines:
    key = line.split("=", 1)[0] if "=" in line else ""
    if key in {"NVT_EGRESS_BROKER_TOKEN", "EGRESS_CA_DIR", "EGRESS_CA_KEY_FILE"}:
        continue
    if key in values:
        updated.append(f"{key}={values[key]}")
        seen.add(key)
    else:
        updated.append(line)
for key, value in values.items():
    if key not in seen:
        updated.append(f"{key}={value}")
path.write_text("\n".join(updated) + "\n", encoding="utf-8")
PY
  echo "exists  $env_file"
fi

python3 "$script_dir/broker-agents.py" \
  --agents-file "$broker_agents_file" \
  register \
  --name "$name" \
  --token="$broker_token"

if [ "$egress_mode" = "mediated" ]; then
  python3 "$script_dir/broker-agents.py" \
    --agents-file "$broker_agents_file" \
    register \
    --name "$name-egress" \
    --token="$egress_token" \
    --role egress \
    --paired-agent "$name"
fi

python3 - "$broker_agents_file" "$name" "$egress_mode" "$egress_allow_insecure_broker" <<'PY'
import sys
from pathlib import Path

import yaml

agents_file = Path(sys.argv[1])
name = sys.argv[2]
mode = sys.argv[3]
allow_insecure = sys.argv[4] in {"1", "true", "TRUE", "True", "yes", "YES", "Yes"}
data = yaml.safe_load(agents_file.read_text(encoding="utf-8")) or {}
agent = next((item for item in data.get("agents", []) if isinstance(item, dict) and item.get("id") == name), None)
if agent is None:
    raise SystemExit(f"agent-init: agent {name} is not registered")
header_inject = []
for grant in agent.get("grants", []) or []:
    if not isinstance(grant, dict):
        continue
    provider = grant.get("provider") or "<unknown>"
    materialization = grant.get("materialization") or "file-bundle"
    if materialization not in ("file-bundle", "header-inject", "placeholder-file"):
        raise SystemExit(f"agent-init: broker grant {provider} materialization must be file-bundle, header-inject, or placeholder-file, got {materialization}")
    # header-inject and placeholder-file are zero-possession mediated modes.
    if mode == "direct" and materialization != "file-bundle":
        raise SystemExit(f"agent-init: egress direct is incompatible with broker grant {provider} materialization {materialization}")
    if mode == "mediated" and materialization == "file-bundle":
        raise SystemExit(f"agent-init: egress mediated is incompatible with broker grant {provider} materialization file-bundle")
    if mode == "mediated" and materialization == "header-inject":
        hosts = grant.get("egress-hosts") or grant.get("egressHosts") or []
        if not isinstance(hosts, list) or not hosts or not all(isinstance(host, str) and host and "://" not in host and "/" not in host and "@" not in host for host in hosts):
            raise SystemExit(f"agent-init: egress mediated broker grant {provider} requires egress-hosts")
        header_inject.append((provider, hosts))
if mode == "mediated":
    if not allow_insecure:
        raise SystemExit("agent-init: mediated mode with plaintext local broker requires NVT_EGRESS_ALLOW_INSECURE_BROKER=1")
    if len(header_inject) == 0:
        raise SystemExit("agent-init: mediated mode requires at least one header-inject grant with egress-hosts")
PY

mkdir -p "$egress_ca_dir"
chmod 700 "$egress_ca_dir"

if [ "$egress_mode" = "mediated" ]; then
  {
    printf 'NVT_BROKER_TOKEN=%s\n' "$egress_token"
    printf 'EGRESS_CA_KEY_FILE=%s\n' "$egress_ca_key_file"
  } >"$egressd_env_file"
  chmod 600 "$egressd_env_file"
else
  rm -f "$egressd_env_file"
fi

if [ "$egress_mode" = "direct" ] && [ -d "$host_codex_config_dir" ] && [ -z "$(find "$codex_config_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  cp -R "$host_codex_config_dir"/. "$codex_config_dir"/
  echo "seeded $codex_config_dir from $host_codex_config_dir"
fi

if [ "$egress_mode" = "mediated" ]; then
  python3 - "$broker_agents_file" "$name" "$egressd_config_file" "$egress_allow_insecure_broker" <<'PY'
import json
import sys
from pathlib import Path

import yaml

agents_file = Path(sys.argv[1])
name = sys.argv[2]
target = Path(sys.argv[3])
allow_insecure = sys.argv[4] in {"1", "true", "TRUE", "True", "yes", "YES", "Yes"}
data = yaml.safe_load(agents_file.read_text(encoding="utf-8")) or {}
agent = next((item for item in data.get("agents", []) if isinstance(item, dict) and item.get("id") == name), None)
inject_routes = []
seen_inject_routes = set()
for grant in agent.get("grants", []) or []:
    if not isinstance(grant, dict):
        continue
    materialization = grant.get("materialization") or "file-bundle"
    if materialization not in {"header-inject", "placeholder-file"}:
        continue
    hosts = grant.get("egress-hosts") or grant.get("egressHosts") or []
    for host in hosts:
        host = str(host).lower()
        key = (host.split(":", 1)[0], grant.get("provider"))
        if key in seen_inject_routes:
            continue
        seen_inject_routes.add(key)
        route = {
            "host": key[0],
            "capability": grant.get("provider"),
            "upstream": host,
        }
        quota = grant.get("quota")
        if isinstance(quota, dict) and isinstance(quota.get("requests"), int):
            route["max_requests"] = quota["requests"]
        inject_routes.append(route)
config = {
    "broker_url": "http://broker:7347",
    "allow_insecure_broker": allow_insecure,
    "routes": [],
}
if inject_routes:
    config["forward_proxy"] = {
        "listen": "0.0.0.0:8470",
        # Local compose remains a development backend: agents need normal
        # internet access for package downloads and tool calls. Inject routes
        # still mediate configured credential hosts; unmatched hosts are blind
        # tunnels with no broker credential. Kubernetes enforcement is stricter
        # and is handled by NetworkPolicy.
        "allow_unmatched_hosts": True,
        "inject_routes": inject_routes,
    }
    config["ca"] = {
        "cert_file": "/etc/nvt-egress-ca/ca.crt",
        "key_file": "/etc/nvt-egress-ca/ca.key",
    }
target.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  ca_init_args=()
  while IFS= read -r arg; do
    [ -n "$arg" ] && ca_init_args+=("$arg")
  done < <(python3 - "$egressd_config_file" <<'PY'
import json
import sys
from pathlib import Path

config = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not config.get("ca"):
    raise SystemExit(0)
for name in config.get("ca", {}).get("leaf_dns_names") or []:
    print(f"--leaf-dns-name={name}")
for route in (config.get("forward_proxy") or {}).get("inject_routes") or []:
    host = route.get("host")
    if host:
        print(f"--upstream-leaf-name={host.lower()}")
PY
)
  ca_configured="$(
    python3 - "$egressd_config_file" <<'PY'
import json
import sys
from pathlib import Path
print("1" if json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("ca") else "0")
PY
  )"
  if [ "$ca_configured" = "1" ]; then
    if [ -n "${NVT_EGRESS_CA_INIT_BIN:-}" ]; then
      "$NVT_EGRESS_CA_INIT_BIN" \
        --cert-file "$egress_ca_cert_file" \
        --key-file "$egress_ca_key_file" \
        ${ca_init_args+"${ca_init_args[@]}"}
    else
      docker run --rm \
        --user 0:0 \
        --entrypoint /usr/local/bin/egress-ca-init \
        -v "$egress_ca_dir:/egress-ca" \
        "${NVT_EGRESSD_IMAGE:-nvt-egressd:latest}" \
        --cert-file /egress-ca/ca.crt \
        --key-file /egress-ca/ca.key \
        ${ca_init_args+"${ca_init_args[@]}"}
    fi
    chmod 644 "$egress_ca_cert_file" 2>/dev/null || true
    chmod 600 "$egress_ca_key_file" 2>/dev/null || true
  fi
else
  rm -f "$egressd_config_file"
fi

if [ ! -f "$agent_config_file" ]; then
  AGENT_TYPE="$agent_type" AGENT_ARGS="$runtime_args" AGENT_USER="$runtime_user" render_template "$templates_dir/agent.yaml" "$agent_config_file"
  echo "created $agent_config_file"
else
  # Keep the declared runtime.user in sync when re-running with --user, without
  # touching the rest of a possibly user-edited agent.yaml. An agent created
  # before this field existed has no user line; recreate it to adopt the field.
  python3 - "$agent_config_file" "$runtime_user" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
user = sys.argv[2]
text = path.read_text(encoding="utf-8")
updated, count = re.subn(r"(?m)^(  user: ).*$", r"\g<1>" + user, text)
if count:
    path.write_text(updated, encoding="utf-8")
PY
  echo "exists  $agent_config_file"
fi

# Manage the generic preseed block in agent.yaml. bootstrap only knows how to
# write configured files; the tool presets live here so core stays
# implementation-swappable. If a user already owns an unmarked preseed block,
# leave it untouched instead of creating duplicate top-level YAML keys.
python3 - "$agent_config_file" "$agent_preseed" <<'PY'
import sys
from pathlib import Path

import yaml

config_file = Path(sys.argv[1])
preseed = sys.argv[2].strip()

BEGIN = "# BEGIN nvt-managed preseed (agent-init)"
END = "# END nvt-managed preseed (agent-init)"

text = config_file.read_text(encoding="utf-8")
if BEGIN in text:
    before, _, rest = text.partition(BEGIN)
    _, _, after = rest.partition(END)
    text = before.rstrip("\n") + "\n" + after.lstrip("\n")
else:
    parsed = yaml.safe_load(text) or {}
    if isinstance(parsed, dict) and "preseed" in parsed:
        raise SystemExit(0)

block = "\n".join([BEGIN, preseed, END])
if "tools:" in text:
    text = text.replace("tools:", block + "\n\ntools:", 1)
else:
    text = text.rstrip("\n") + "\n\n" + block + "\n"
parsed = yaml.safe_load(text)
if not isinstance(parsed, dict):
    raise SystemExit("agent-init: agent config is not a YAML object after preseed rendering")
config_file.write_text(text, encoding="utf-8")
print(f"rendered preseed config into {config_file}")
PY

# Local compose needs runtime.proxy.provider for mediated forward-proxy mode.
# The default generated runtime command is tool-specific, so agent-init owns
# this small preset and keeps bootstrap generic.
python3 - "$agent_config_file" "$broker_agents_file" "$name" "$egress_mode" "$agent_type" <<'PY'
import sys
from pathlib import Path

import yaml

config_file = Path(sys.argv[1])
agents_file = Path(sys.argv[2])
name = sys.argv[3]
mode = sys.argv[4]
agent_type = sys.argv[5]

if mode != "mediated":
    raise SystemExit(0)

default_provider = {"codex": "codex-main", "claude": "claude-main"}.get(agent_type)
if not default_provider:
    raise SystemExit(0)

text = config_file.read_text(encoding="utf-8")
parsed = yaml.safe_load(text) or {}
if not isinstance(parsed, dict):
    raise SystemExit("agent-init: agent config is not a YAML object before runtime proxy rendering")
runtime = parsed.get("runtime") or {}
if not isinstance(runtime, dict):
    raise SystemExit("agent-init: runtime must be a YAML object")
proxy = runtime.get("proxy")
if isinstance(proxy, dict) and proxy.get("provider"):
    raise SystemExit(0)

data = yaml.safe_load(agents_file.read_text(encoding="utf-8")) or {}
agent = next((item for item in data.get("agents", []) if isinstance(item, dict) and item.get("id") == name), None)
providers = {
    grant.get("provider")
    for grant in (agent or {}).get("grants", []) or []
    if isinstance(grant, dict)
}
if default_provider not in providers:
    raise SystemExit(f"agent-init: mediated {agent_type} agent requires broker grant {default_provider} or an explicit runtime.proxy.provider")

lines = text.splitlines()
runtime_index = next((index for index, line in enumerate(lines) if line == "runtime:"), None)
if runtime_index is None:
    raise SystemExit("agent-init: runtime block is required")
insert_at = len(lines)
for index in range(runtime_index + 1, len(lines)):
    if lines[index] and not lines[index].startswith((" ", "\t", "#")):
        insert_at = index
        break
lines[insert_at:insert_at] = ["  proxy:", f"    provider: {default_provider}"]
config_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"rendered runtime proxy provider {default_provider} into {config_file}")
PY

# Manage the egress block in agent.yaml: bootstrap reads egress.grants
# (base-url per route) from the agent config, so the compose path must render
# the same grant metadata the operator injects on k8s. The block lives
# between markers so re-runs replace it without touching user edits.
python3 - "$agent_config_file" "$broker_agents_file" "$name" "$egress_mode" <<'PY'
import sys
from pathlib import Path

import yaml

config_file = Path(sys.argv[1])
agents_file = Path(sys.argv[2])
name = sys.argv[3]
mode = sys.argv[4]

BEGIN = "# BEGIN nvt-managed egress (agent-init)"
END = "# END nvt-managed egress (agent-init)"

text = config_file.read_text(encoding="utf-8")
changed = BEGIN in text
if changed:
    before, _, rest = text.partition(BEGIN)
    _, _, after = rest.partition(END)
    text = before.rstrip("\n") + "\n" + after.lstrip("\n")

if mode == "mediated":
    data = yaml.safe_load(agents_file.read_text(encoding="utf-8")) or {}
    agent = next((item for item in data.get("agents", []) if isinstance(item, dict) and item.get("id") == name), None)
    lines = [
        BEGIN,
        "egress:",
        "  mode: mediated",
        "  placeholder: NVT-PLACEHOLDER-NOT-A-KEY",
        "  forward-proxy: true",
        "  forward-proxy-url: http://127.0.0.1:8470",
        "  grants:",
    ]
    for grant in (agent or {}).get("grants", []) or []:
        if not isinstance(grant, dict) or (grant.get("materialization") or "file-bundle") != "header-inject":
            continue
        lines.append(f"    - provider: {grant.get('provider')}")
        lines.append("      materialization: header-inject")
        hosts = grant.get("egress-hosts") or grant.get("egressHosts") or []
        if hosts:
            lines.append("      egress-hosts:")
            for host in hosts:
                lines.append(f"      - {host}")
        if grant.get("git"):
            lines.append("      git: true")
    # placeholder-file grants carry no egressd route (edge injection is Phase
    # 6.2); bootstrap only needs provider + mode to materialize the file.
    for grant in (agent or {}).get("grants", []) or []:
        if not isinstance(grant, dict) or (grant.get("materialization") or "file-bundle") != "placeholder-file":
            continue
        lines.append(f"    - provider: {grant.get('provider')}")
        lines.append("      materialization: placeholder-file")
        hosts = grant.get("egress-hosts") or grant.get("egressHosts") or []
        if hosts:
            lines.append("      egress-hosts:")
            for host in hosts:
                lines.append(f"      - {host}")
    lines.append(END)
    text = text.rstrip("\n") + "\n\n" + "\n".join(lines) + "\n"
    changed = True

parsed = yaml.safe_load(text)
if not isinstance(parsed, dict):
    raise SystemExit("agent-init: agent config is not a YAML object after egress rendering")
egress = parsed.get("egress") or {}
if mode == "mediated" and not egress.get("grants"):
    raise SystemExit("agent-init: mediated agent config rendered no egress grants")
if mode != "mediated" and egress.get("mode") == "mediated":
    raise SystemExit("agent-init: direct mode but agent config still declares egress mediated")
if changed:
    config_file.write_text(text, encoding="utf-8")
    print(f"rendered egress config into {config_file}")
PY

if [ ! -f "$local_instructions_file" ]; then
  cp "$templates_dir/AGENTS.local.md" "$local_instructions_file"
  echo "created $local_instructions_file"
else
  echo "exists  $local_instructions_file"
fi

echo "workspace $workspace_dir"
if [ "$autonomy" = "trusted-local" ]; then
  echo "autonomy trusted-local (type=$agent_type): auto-approval flags enabled"
else
  echo "autonomy interactive (type=$agent_type): agent CLI approval prompts preserved"
fi
