# nvt-agent

`nvt-agent` runs named coding agents in local Docker containers. Each agent gets
its own workspace, browser-accessible code-server, persistent root home volume,
and terminal agent session.

The current implementation is intentionally script and Makefile driven. A
manager/CLI can be added later on top of the same runtime pieces.

## Architecture

`nvt-agent` is split into small runtime pieces:

```text
host scripts / future manager   create, start, stop, inspect agents
runtime core                    bootstrap tools, start services, launch plugins
agentd                          container-local session and event API
plugins                         executable automation units
```

The long-term direction is to replace the Make/scripts host layer with a
manager. The preferred manager direction is Kubernetes-native: an operator
reconciles agent custom resources into Pods, PVCs, Services, Ingress/Gateway
routes, Secrets, and status conditions. Local Docker Compose should remain a
development backend, not the center of the architecture.

The container runtime pieces should not depend on Make or Docker Compose; they
should keep working when started by Docker Compose, another CLI, or a future
Kubernetes controller.

`agentd` is intentionally narrower than a manager. It runs inside each agent
container and owns only interaction with the running agent session:

- prompt queue
- single writer into the tmux session
- external prompt warning
- append-only event log
- `agentdctl` client commands
- reactive plugin support through event-log subscription

`agentd` is not a security boundary and does not own secrets, egress policy,
Docker, Compose, Kubernetes, bootstrap, or plugin supervision.

## Kubernetes-Native Direction

The intended mature shape is:

```text
Agent CRD        desired state for one agent
Operator         reconciliation, lifecycle, scheduling, status
Agent Pod        runtime container, optional sidecars/init containers
agentd           pod-local session and event API
Plugins          runtime processes, init containers, or sidecars
Workspace        PVC-backed mounted workspace
Secrets          Kubernetes Secrets or external secret providers
Routing          Ingress, Gateway API, or Traefik
Status           Kubernetes conditions, events, and logs
```

This keeps nvt-agent aligned with GitOps workflows: desired agents can live in
git, and Flux/Argo CD can apply them while the operator reconciles actual
runtime state. Kubernetes tools such as `kubectl`, `k9s`, logs, events, and RBAC
become the first operational UI instead of building a custom web UI first.

The operator should also be extensible. Core scheduling policy can start as
declarative fields and profiles, while custom scheduling/provisioning decisions
can later be delegated to external extension services. Runtime plugins and
operator extensions are separate concerns:

```text
runtime plugins      behavior inside or beside an agent Pod
operator extensions  scheduling, placement, provisioning, routing policy
```

The immediate constraint is to keep runtime and plugin contracts
container-native: config, env, files, workspace mounts, and `agentd` APIs should
not assume Docker Compose-specific behavior unless a feature is explicitly
local-only.

Isolation should be runtime-selectable. Local development can use normal
containers, while the Kubernetes operator should support hardened pod runtimes
through `RuntimeClass`, such as Kata Containers or other microVM-backed pod
runtimes. KubeVirt can be considered for full VM-style agents when needed. This
keeps nvt-agent container-native while leaving a path to stronger isolation.

## Quick Start

Build the runtime image from `runtime/Dockerfile`:

```sh
make runtime-build
```

Start the shared proxy:

```sh
make infra-up
```

Create an agent config:

```sh
make agent-init NAME=frontend
```

This creates:

```text
.agents/frontend/env
.agents/frontend/agent.yaml
.agents/frontend/workspace/
.agents/frontend/custom-plugins/
.agents/frontend/auth/claude/
```

Edit the generated agent config before starting it:

```sh
$EDITOR .agents/frontend/agent.yaml
```

Start the agent:

```sh
make agent-up NAME=frontend
```

Open it in the browser:

```text
http://frontend.agent.localhost:4090
```

Useful commands:

```sh
make agent-ps
make agent-logs NAME=frontend
make agent-shell NAME=frontend
make agent-doctor NAME=frontend
make agent-down NAME=frontend
make agent-rm NAME=frontend FORCE=1
```

Use `TYPE=claude` during init to generate a Claude command instead of Codex:

```sh
make agent-init NAME=research TYPE=claude
```

## Supported Agent CLIs

Agents currently support both Codex and Claude Code.

Codex is the default:

```sh
make agent-init NAME=frontend
```

which generates:

```yaml
runtime:
  command: codex
```

Claude Code can be selected at init time:

```sh
make agent-init NAME=research TYPE=claude
```

Codex auth is mounted from the host `~/.codex` read-only. Claude Code auth is
stored per agent under `.agents/<name>/auth/claude` and mounted into the
container at `/root/.claude`.

## Browser URLs And Proxy

Agents are routed through one shared Traefik proxy.

Default URL format:

```text
http://<name>.agent.localhost:4090
```

Examples:

```text
http://frontend.agent.localhost:4090
http://studio-api.agent.localhost:4090
```

The proxy listens on the host at `127.0.0.1:${NVT_PROXY_PORT:-4090}` and forwards
matching hostnames to code-server inside each agent container on port `4090`.

The route is created from Docker labels in `compose.agent.yaml`:

```yaml
traefik.http.routers.${AGENT_NAME}.rule=Host(`${AGENT_HOST}`)
traefik.http.services.${AGENT_NAME}.loadbalancer.server.port=4090
```

The default proxy port can be changed when starting infra:

```sh
NVT_PROXY_PORT=4910 make infra-up
```

Then agent URLs use that port:

```text
http://frontend.agent.localhost:4910
```

## Lifecycle Cleanup

Stop one agent:

```sh
make agent-down NAME=frontend
```

Stop all agents and infra, keeping agent files, volumes, and the proxy network:

```sh
make down-all
```

Remove one agent, including local `.agents/<name>` files and its Docker volume:

```sh
make agent-rm NAME=frontend
```

Remove all agents, including local files and Docker volumes:

```sh
make agent-rm-all
```

Remove only the shared proxy network:

```sh
make infra-network-rm
```

Clean stops all agents and infra, then removes the shared proxy network. It keeps
agent files and volumes:

```sh
make clean
```

Nuke removes all agents, agent files, Docker volumes, infra, and the shared
proxy network:

```sh
make nuke
```

Use `FORCE=1` to skip confirmation for destructive remove commands:

```sh
make nuke FORCE=1
```

## Agent Layout

`agent-init` creates per-agent files under `.agents/<name>/`:

```text
.agents/frontend/
  env
  agent.yaml
  workspace/
  custom-plugins/
  auth/
    claude/
```

`.agents/` is ignored by git.

Useful paths:

```text
.agents/<name>/agent.yaml            agent runtime, tools, and plugins config
.agents/<name>/env                   Compose env file for host paths and mounts
.agents/<name>/workspace/            persisted workspace for repos/files
.agents/<name>/custom-plugins/       host directory for custom plugin binaries/scripts
.agents/<name>/auth/claude/          per-agent Claude Code auth/config
```

The generated env file contains the host paths used by Compose:

```env
AGENT_NAME=frontend
AGENT_HOST=frontend.agent.localhost

WORKSPACE_DIR=/absolute/path/.agents/frontend/workspace
NVT_WORKSPACE=/absolute/path/.agents/frontend/workspace
CUSTOM_PLUGINS_DIR=/absolute/path/.agents/frontend/custom-plugins
AGENT_CONFIG_FILE=/absolute/path/.agents/frontend/agent.yaml
NVT_AGENT_CONFIG_FILE=/nvt-agent/agent.yaml

CODEX_CONFIG_DIR=/Users/you/.codex
CLAUDE_CONFIG_DIR=/absolute/path/.agents/frontend/auth/claude
```

The workspace is bind-mounted at the same absolute path inside the container.
This is deliberate: agents have Docker socket access, and host Docker bind mounts
need host-visible paths.

## Agent Config

Each agent is configured with `.agents/<name>/agent.yaml`.

Minimal generated config:

```yaml
runtime:
  command: codex

tools:
  apt: []
  mise: []
  additional-paths: []
  shell: []

plugins: []
```

Tool bootstrap runs before plugins and before the agent session starts.

Example:

```yaml
tools:
  apt:
    - jq
  mise:
    - go@latest
  additional-paths:
    - ~/.local/bin
  shell:
    - |
      echo "custom bootstrap"
```

## Code Server

`agent.yaml` can install code-server extensions during bootstrap:

```yaml
code-server:
  extensions:
    - redhat.vscode-yaml
```

Default settings can be provided at:

```text
<workspace>/.nvt-agent/code-server/settings.json
```

Bootstrap copies that file to code-server's user settings only if the target
does not already exist:

```text
/root/.local/share/code-server/User/settings.json
```

This gives new agents defaults without overwriting settings changed later in
the browser. To use a different default settings file, set:

```yaml
code-server:
  settings-file: .config/code-server/default-settings.json
```

## Plugins

Plugins are container-side processes configured in `agent.yaml`.

Builtin plugins are baked into the runtime image under `runtime/plugins/`.
Custom plugins are mounted per agent from:

```text
.agents/<name>/custom-plugins/
```

to:

```text
/custom-plugins
```

Builtin checkout example:

```yaml
plugins:
  - name: checkout-repos
    source: builtin
    when: before-agent
    restart: never
    config:
      repos:
        - url: https://github.com/example/public-repo.git
        - url: https://github.com/example/other-public-repo.git
          path: vendor/other-public-repo
          upstream: https://github.com/original-org/other-public-repo.git
```

Custom plugin example:

Put an executable on the host:

```text
.agents/frontend/custom-plugins/custom-plugin
```

Then reference it from `.agents/frontend/agent.yaml`:

```yaml
plugins:
  - name: custom-plugin
    source: custom
    command: /custom-plugins/custom-plugin
    when: after-agent
    restart: always
    config:
      poll-seconds: 30
```

Custom plugin commands can be scripts or binaries in any language available in
the container.

To keep custom plugins somewhere else on the host, edit:

```text
.agents/<name>/env
```

and change:

```env
CUSTOM_PLUGINS_DIR=/path/to/custom-plugins
```

See [runtime/plugins/README.md](runtime/plugins/README.md) for the plugin
contract and authoring details.

Plugins can talk to the running Codex or Claude Code session through `agentd`.
For simple prompts, use the compatibility wrapper:

```sh
echo "Review failing tests and fix them." | prompt-agent
```

For the full container-local API, use `agentdctl`:

```sh
agentdctl prompt --source plugin:my-plugin "Review failing tests"
agentdctl publish plugin.my-plugin.ready --source plugin:my-plugin --payload '{"ok":true}'
agentdctl signal done --message "Finished the current task"
agentdctl subscribe --filter plugin.my-plugin.
```

`agentdctl subscribe` tails `$NVT_STATE_DIR/agentd/events.jsonl`. By default it
uses `--since end`, so restarted plugins only receive future events. Use
`--since beginning` only when the reaction is idempotent.

Plugins can also export public tools that are added to `PATH` for the agent,
terminal users, and other plugins:

```yaml
exports:
  tools:
    - name: github-helper
      command: /usr/local/lib/nvt-agent/plugins/github-helper/github-helper
      description: GitHub PR/checks helper
```

The runtime renders wrappers in `$HOME/.local/bin`, injects the exporting
plugin's `NVT_PLUGIN_NAME`, `NVT_PLUGIN_CONFIG`, and `NVT_WORKSPACE`, and rejects
duplicate names or names that shadow existing commands.

Run diagnostics inside an agent:

```sh
make agent-doctor NAME=frontend
make agent-doctor NAME=frontend PLUGIN=my-plugin
```

Inside the container, `doctor` supports:

```sh
doctor
doctor --core
doctor --plugins
doctor --plugin my-plugin
doctor --json
```

Scaffold a builtin plugin:

```sh
make plugin-init NAME=my-plugin
```

Scaffold a custom plugin under an agent:

```sh
make plugin-init NAME=my-plugin DIR=.agents/frontend/custom-plugins
```

The scaffold includes `plugin.yaml`, `run.sh`, and a plugin README. The manifest
describes plugin commands; agent readiness policy stays in `agent.yaml`:

```yaml
command: /custom-plugins/my-plugin/run.sh
health:
  command: /custom-plugins/my-plugin/run.sh ready
doctor:
  command: /custom-plugins/my-plugin/run.sh doctor
```

## Runtime

The runtime image is built from `runtime/Dockerfile` on top of:

```text
ghcr.io/catthehacker/ubuntu:act-24.04
```

The image includes:

- code-server on port `4090`
- tmux
- Codex CLI
- Claude Code CLI
- mise
- Python YAML support for runtime scripts

Container startup order:

```text
1. bootstrap tools from agent.yaml
2. run before-agent plugins
3. start agentd
4. start code-server
5. start the terminal agent in tmux
6. run after-agent plugins in the background
```

Codex auth is mounted from the host `~/.codex` read-only. Claude auth is stored
per agent under `.agents/<name>/auth/claude` and mounted to `/root/.claude`.

The agent root home is a named Docker volume, so installed state under `/root`
can survive `agent-down`. Use `agent-rm` to remove the agent Compose volume.

## agentd Long-Term Direction

The `agentd` protocol is documented under [protocol/](protocol/). Its behavior
is covered by a black-box Go conformance suite in [tests/agentd/](tests/agentd/),
so the implementation can be rewritten later without changing plugins.

Current scope:

- JSONL over a Unix socket at `/run/nvt-agent/agentd.sock`
- `health`, `status`, `prompt`, and `event.publish`
- `agentdctl subscribe` implemented as client-side log tailing
- advisory `plugin.agent.signal.*` events

Deferred work:

- session readiness / turn detection
- verified `session.*` events
- durable subscribe cursors and log rotation
- bounded prompt queue and queue overflow policy
- stronger agentd supervision
- optional Go rewrite behind the same protocol
