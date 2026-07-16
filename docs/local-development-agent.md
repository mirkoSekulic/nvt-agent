# Local Development Agent

This guide creates one Docker Compose agent with a broker-backed GitHub App.
The App private key stays in the broker; the agent receives only a scoped
broker identity.

## Prerequisites

- Docker with Compose
- Make
- A GitHub App installed on the target repository
- The App ID, installation ID, and private key
- Codex or Claude credentials when using that runtime

`.broker/` and `.agents/` are ignored local state. Never commit provider
credentials from either directory.

## Configure The Broker

From the repository root:

```sh
export AGENT=nvt-dev
export REPO=mirkosekulic/nvt-agent
export PROVIDER=github-main-app

mkdir -p .broker
cp -n templates/broker-agents.yaml .broker/agents.yaml
```

Create `.broker/env` with mode `0600`:

```text
GITHUB_APP_ID=<app-id>
GITHUB_APP_INSTALLATION_ID=<installation-id>
GITHUB_APP_PRIVATE_KEY_BASE64=<base64-private-key>
```

Generate the final value portably with:

```sh
base64 < /absolute/path/to/private-key.pem | tr -d '\n'
```

Create `.broker/broker.yaml`:

```yaml
providers:
  - name: github-main-app
    plugin: github-app
    config:
      app-id-env: GITHUB_APP_ID
      installation-id-env: GITHUB_APP_INSTALLATION_ID
      private-key-base64-env: GITHUB_APP_PRIVATE_KEY_BASE64
      api-url: https://api.github.com
      injection-hosts: [github.com, api.github.com]
    allow:
      repositories: [mirkoSekulic/nvt-agent]
      permissions:
        contents: write
        pull_requests: write
        checks: read
      methods: [GET, POST, PATCH]
```

Provider `allow` is the maximum ceiling. Each agent grant narrows it further.

## Build And Start

```sh
make runtime-build broker-build egressd-build captured-build
make infra-up
make agent-init NAME=$AGENT
make agent-grant NAME=$AGENT PROVIDER=$PROVIDER REPO=$REPO
make agent-up NAME=$AGENT
```

`agent-init` creates `.agents/$AGENT/agent.yaml`, environment, workspace,
state, and a unique broker identity. The broker stores only its token hash.

Open code-server:

```text
http://nvt-dev.agent.localhost:4090
```

Useful commands:

```sh
make agent-logs NAME=$AGENT
make agent-shell NAME=$AGENT
make agent-doctor NAME=$AGENT
make agent-ps
```

## Configure Repositories And Tools

Edit `.agents/$AGENT/agent.yaml`. Generated defaults already contain the
runtime, tools, code-server, and plugin sections.

Broker-backed repository access uses the public provider alias exported by
`git-host-credentials`, then references that alias from checkout and watcher
plugins:

```yaml
plugins:
  - name: git-host-credentials
    source: builtin
    config:
      default-provider: github-main
      providers:
        - name: github-main
          type: broker
          broker-provider: github-main-app
          match:
            - github.com/mirkosekulic/nvt-agent

  - name: git-credentials
    source: builtin
    when: before-agent
    config:
      credentials:
        - match: https://github.com/mirkosekulic/nvt-agent
          provider: github-main
          identity:
            mode: provider

  - name: checkout-repos
    source: builtin
    when: before-agent
    restart: never
    config:
      repos:
        - url: https://github.com/mirkosekulic/nvt-agent.git
```

Keep `broker-provider` aligned with `.broker/broker.yaml`. Plugin `provider`
values refer to the local exported alias, not directly to the broker provider.

For custom tools, exposed ports, runtime arguments, and watcher configuration,
see [Runtime plugins](../runtime/plugins/README.md) and the generated comments
in `agent.yaml`.

## Verify

Inside `make agent-shell NAME=$AGENT`:

```sh
brokerctl health
docker info
docker compose version
cd "$NVT_WORKSPACE/nvt-agent"
git fetch
agentdctl status
doctor
```

Do not print broker tokens or provider credentials during verification.

Register a pull-request watcher dynamically:

```sh
github-watch register \
  --repo mirkoSekulic/nvt-agent \
  --number <pr-number> \
  --label nvt-dev

github-watch list
```

Registrations live in the persistent agent state directory and survive
container restart.

## HTTP Services

Declare named routes in `agent.yaml`:

```yaml
expose:
  http:
    - name: app
      targetPort: 3000
```

Then open:

```text
http://app.nvt-dev.agent.localhost:4090
```

For temporary forwarding:

```sh
make forward NAME=$AGENT PORT=5173
make forward NAME=$AGENT PORT=5173 LOCAL=9000
```

Ports 4090 and 2375 are reserved.

## Troubleshooting

- **Broker image missing:** run `make broker-build && make infra-up`.
- **Unauthorized:** verify the grant in `.broker/agents.yaml` and provider
  ceiling in `.broker/broker.yaml`.
- **GitHub mint failure:** verify App installation, permissions, IDs, and the
  base64 private key in `.broker/env`.
- **Docker unavailable:** recreate the agent and verify
  `DOCKER_HOST=tcp://127.0.0.1:2375`.
- **Runtime credentials stale:** update the broker-owned credential source;
  mediated agents should not receive copied provider credentials.

## Cleanup

If the configured tmux agent session disappears, the main agent container exits
non-zero. Docker Compose does not automatically stop the agent's support
containers; use `agent-down` to remove the complete local stack.

```sh
make agent-down NAME=$AGENT
make agent-rm NAME=$AGENT FORCE=1
make infra-down
```

To clone an initialized agent definition with a fresh broker identity:

```sh
make agent-copy FROM=$AGENT TO=nvt-dev-copy
```
