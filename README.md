# nvt-agent

`nvt-agent` runs named coding agents in local Docker containers. Each agent gets
its own workspace, browser-accessible code-server, persistent root home volume,
and terminal agent session.

The current implementation is intentionally script and Makefile driven. A
manager/CLI can be added later on top of the same runtime pieces.

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
  additional_paths: []
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
  additional_paths:
    - ~/.local/bin
  shell:
    - |
      echo "custom bootstrap"
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
    when: before_agent
    restart: never
    config:
      repos:
        - url: https://github.com/example/public-repo.git
        - url: https://github.com/example/other-public-repo.git
          path: vendor/other-public-repo
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
    when: after_agent
    restart: always
    config:
      poll_seconds: 30
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
2. run before_agent plugins
3. start code-server
4. start the terminal agent in tmux
5. run after_agent plugins in the background
```

Codex auth is mounted from the host `~/.codex` read-only. Claude auth is stored
per agent under `.agents/<name>/auth/claude` and mounted to `/root/.claude`.

The agent root home is a named Docker volume, so installed state under `/root`
can survive `agent-down`. Use `agent-rm` to remove the agent Compose volume.
