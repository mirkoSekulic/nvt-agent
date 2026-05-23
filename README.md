# nvt-agent

`nvt-agent` is a planned platform for running terminal coding agents in isolated
Docker containers.

The first implementation target is intentionally small: create named local
agents, open each one in the browser, and interact with the agent process
through a persistent terminal session. Higher-level manager workflows can be
added later on top of the same runtime primitives.

## First Iteration

The first version should be Makefile and script driven.

Example usage:

```sh
make infra-up
make agent-up NAME=frontend
make agent-logs NAME=frontend
make agent-down NAME=frontend
make agent-rm NAME=frontend
```

Each agent is named by the user. Names are not tied to PRs, issues, branches, or
repositories.

Valid MVP names:

```text
frontend
studio-api
agent-1
xsd-fixer
```

For the MVP, names should be DNS-safe:

```text
lowercase letters, numbers, and hyphens
must start and end with a letter or number
```

## Runtime Model

Each named agent runs as its own Docker Compose project.

The same `compose.agent.yaml` template is reused for every agent:

```sh
docker compose \
  -p "agent-${AGENT_NAME}" \
  --env-file ".agents/${AGENT_NAME}/env" \
  -f compose.agent.yaml \
  up -d
```

This gives each agent isolated Compose resources:

```text
agent-frontend-agent-1
agent-frontend_agent-home
agent-studio-api-agent-1
agent-studio-api_agent-home
```

Per-agent state can start as files:

```text
.agents/
  frontend/
    env
    workspace/
  studio-api/
    env
    workspace/
```

Example `.agents/frontend/env`:

```env
AGENT_NAME=frontend
AGENT_DOMAIN=agent.localhost
AGENT_HOST=frontend.agent.localhost
WORKSPACE_DIR=/absolute/path/.agents/frontend/workspace
AGENT_COMMAND=codex
```

## Browser Access

Agents should be exposed through one shared reverse proxy instead of unique host
ports.

Default URL format:

```text
http://<name>.agent.localhost
```

Examples:

```text
http://frontend.agent.localhost
http://studio-api.agent.localhost
http://xsd-fixer.agent.localhost
```

The proxy routes by `Host` header:

```text
Host frontend.agent.localhost -> frontend agent container:4090
Host studio-api.agent.localhost -> studio-api agent container:4090
```

Use Traefik for the MVP. It can watch Docker containers and build routes from
labels, so scripts do not need to rewrite proxy config when agents start or
stop.

Shared network:

```sh
docker network create agents-proxy
```

Infra Compose:

```yaml
services:
  proxy:
    image: traefik:v3
    command:
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --providers.docker.network=agents-proxy
      - --entrypoints.web.address=:80
    ports:
      - "127.0.0.1:80:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - agents-proxy

networks:
  agents-proxy:
    external: true
```

Agent Compose:

```yaml
services:
  agent:
    image: nvt-agent-runtime:latest
    networks:
      - agents-proxy
    labels:
      - traefik.enable=true
      - traefik.docker.network=agents-proxy
      - traefik.http.routers.${AGENT_NAME}.rule=Host(`${AGENT_HOST}`)
      - traefik.http.services.${AGENT_NAME}.loadbalancer.server.port=4090
    volumes:
      - ${WORKSPACE_DIR}:/workspace
      - agent-home:/home/agent
    environment:
      AGENT_NAME: ${AGENT_NAME}
      AGENT_COMMAND: ${AGENT_COMMAND:-codex}

volumes:
  agent-home:

networks:
  agents-proxy:
    external: true
```

Browsers and `curl` commonly resolve `.localhost` names to loopback even when
system resolver tools such as `ping`, `dscacheutil`, or language runtimes do not
show a DNS result. Keep the base domain configurable:

```env
AGENT_DOMAIN=agent.localhost
```

If an environment does not resolve wildcard `.localhost` names, use a fallback
such as:

```env
AGENT_DOMAIN=127.0.0.1.nip.io
```

which produces:

```text
http://frontend.127.0.0.1.nip.io
```

## Agent Container

Each container should have:

- mounted workspace at `/workspace`
- persistent home volume at `/home/agent`
- `tmux`
- `code-server` for browser inspection
- one terminal agent CLI, such as Codex or Claude Code
- optional bootstrap script support

`code-server` should listen inside the container on port `4090`:

```sh
code-server --bind-addr 0.0.0.0:4090 --auth none /workspace
```

For local-only MVP usage, auth can be disabled because Traefik binds only to
`127.0.0.1`. If the proxy is exposed on LAN, VPN, or the internet, add real
authentication before using it.

The terminal agent should run in a persistent `tmux` session:

```sh
tmux new-session -d -s agent -c /workspace "$AGENT_COMMAND"
```

Prompt injection can be implemented by pasting into that session:

```sh
tmux load-buffer -b agent-prompt /tmp/prompt.txt
tmux paste-buffer -b agent-prompt -t agent -p -r
tmux send-keys -t agent Enter
```

This treats Claude Code, Codex, or another terminal agent as a black-box
process. `nvt-agent` does not implement a reasoning loop.

## Initial File Layout

Planned MVP repository structure:

```text
Makefile
compose.infra.yaml
compose.agent.yaml
runtime/
  Dockerfile
  entrypoint.sh
  start-code-server.sh
  start-agent-session.sh
scripts/
  agent-up.sh
  agent-down.sh
  agent-logs.sh
  agent-rm.sh
  agent-prompt.sh
.agents/
```

`.agents/` should be ignored by git.

## Commands

Start with Make targets backed by scripts:

```sh
make infra-up
make infra-down
make runtime-build
make agent-up NAME=frontend
make agent-logs NAME=frontend
make agent-shell NAME=frontend
make agent-prompt NAME=frontend < prompt.txt
make agent-down NAME=frontend
make agent-rm NAME=frontend
```

The scripts should preserve a stable command contract so a future CLI can keep
the same behavior:

```sh
nvt-agent create <agent>
nvt-agent up <agent>
nvt-agent prompt <agent> --stdin
nvt-agent exec <agent> -- <command>
nvt-agent logs <agent>
nvt-agent down <agent>
nvt-agent rm <agent>
```

## Later Manager

The manager is a later layer. It should consume the same runtime primitives a
human uses manually.

Future manager responsibilities:

- discover tasks from issues, queues, schedules, or plugins
- claim work
- create one branch/workspace/container per task
- send initial prompts
- monitor lifecycle
- create PRs/MRs through provider plugins
- stop, retain, or clean up agents

One likely workflow:

```text
one issue = one branch = one named agent = one PR/MR
```

But the core runtime should not assume GitHub, GitLab, or issue planning.

## Plugin Direction

Plugins should start as external processes or scripts.

Agent-level plugins can prompt an agent through stdin:

```sh
nvt-agent prompt "$NVT_AGENT_NAME" --stdin
```

Manager-level plugins can create and start agents:

```sh
nvt-agent create repo-issue-123
nvt-agent up repo-issue-123
nvt-agent prompt repo-issue-123 --stdin
```

Avoid dynamic plugin loading in the first versions. A stable command contract is
enough.

