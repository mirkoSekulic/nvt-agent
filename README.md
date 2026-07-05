# nvt-agent

`nvt-agent` runs named coding agents in local Docker containers. Each agent gets
its own workspace, browser-accessible code-server, persistent root home volume,
and terminal agent session.

The current implementation is intentionally script and Makefile driven. A
manager/CLI can be added later on top of the same runtime pieces.

This README also serves as a lightweight PR flow check target.

## Architecture

`nvt-agent` is split into small runtime pieces:

```text
host scripts / future manager   create, start, stop, inspect agents
runtime core                    bootstrap tools, start services, launch plugins
agentd                          container-local session and event API
brokerd                         trusted authority API for secrets/capabilities
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

Current local runtime connections:

```text
Host
----
make/scripts
  |
  | docker compose
  v
Shared infra network: agents-proxy
+--------------------+             +----------------------+
| Traefik proxy      |             | brokerd              |
| :4090 host -> :80  |             | :7347 internal only  |
+---------+----------+             +----------+-----------+
          |                                   ^
          | Host(`name.agent.localhost`)      |
          v                                   | brokerctl HTTP
+---------------------------------------------+-------------+
| Agent docker sidecar / shared net namespace               |
|                                                           |
|  +-------------------+        +-------------------------+ |
|  | agent container   |        | docker:dind sidecar     | |
|  |                   |        | DOCKER_HOST :2375       | |
|  | code-server :4090 |<-------+ same net namespace      | |
|  | tmux agent session|                                  | |
|  | agentd            |                                  | |
|  | /run/...sock      |                                  | |
|  | events.jsonl      |                                  | |
|  +----+---------+----+                                  | |
|       ^         ^                                       | |
|       |         | agentdctl / prompt-agent              | |
|       |         |                                       | |
|       |     +---+----------------+                      | |
|       |     | runtime plugins    |                      | |
|       |     | before/after/tools |                      | |
|       |     +---------+----------+                      | |
|       |               | broker-backed credentials        | |
|       |               v                                  | |
|       |          brokerctl ------------------------------+-+
|       |
|       + agentd writes prompts/events to tmux + event log
+-----------------------------------------------------------+

External APIs
-------------
brokerd -> GitHub/API using broker-held secrets, grants, and audit log
```

Kubernetes / operator path:

```text
Helm chart
  |
  | installs CRDs, nvt-operator, nvt-broker, default AgentSchedule
  v
+---------------------------- Kubernetes namespace ----------------------------+
|                                                                              |
| Schedule producer                                                             |
| any trusted source that submits work                                          |
|   |                                                                          |
|   | HTTP admission                                                            |
|   v                                                                          |
| nvt-operator Service :8082                                                    |
|   |                                                                          |
|   v                                                                          |
| AgentSchedule admission                                                       |
| maxParallelism + duplicate active work checks                                 |
|   |                                                                          |
|   v                                                                          |
| AgentRun controller                                                           |
| creates ConfigMap, token Secrets, broker policy, AgentRun Pod                 |
|   |                                                                          |
|   v                                                                          |
| +---------------------------- AgentRun Pod --------------------------------+ |
| | optional runtime-auth-copy init -> writable runtime auth home             | |
| |                                                                          | |
| | +-------------------------------+     +-------------------------------+  | |
| | | agent runtime container       |     | docker:dind sidecar           |  | |
| | | agentd + tmux + codex/claude  |     | shared Pod netns / :2375      |  | |
| | | runtime plugins               |     | workspace Docker daemon       |  | |
| | +-------+---------------+-------+     +-------------------------------+  | |
| |         |               |                                                  | |
| |         | brokerctl     | event-webhook callback                           | |
| +---------+---------------+--------------------------------------------------+ |
|           |               |                                                    |
|           v               v                                                    |
|      nvt-broker      nvt-operator callback endpoint                            |
|           |               |                                                    |
|           |               v                                                    |
|           |       Completed / Failed status + Pod TTL cleanup                  |
|           v                                                                    |
|      GitHub/API using broker-held secrets, grants, and audit log               |
+------------------------------------------------------------------------------+
```

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

`brokerd` is the trusted-side counterpart to `agentd`. It runs outside the
agent container and owns brokered credentials, broker-executed API requests, and
audit logs. The agent image contains only `brokerctl`, a thin client. Local
broker mode is the first step toward the production operator model where root
secrets stay outside Kata-backed agent Pods.

## Secret Direction

Local Docker agents currently run in a development trust mode. Plugins may read
environment variables or mounted files when configured to do so. That is useful
for local iteration, but it is not the production security model for autonomous
agents: a prompt-injected agent can ask the shell to print files, environment
variables, or plugin configs that are visible inside the container.

The production direction is an operator-managed capability broker. Agents and
plugins should request named capabilities, not raw secrets. The future
Kubernetes operator should mount real secrets only into a broker sidecar or
service, validate which agents/plugins may use each capability, and keep the
agent container itself secret-free.

Example direction:

```text
agent/plugin       requests capability github-fork-push
broker             holds GitHub App private key or API secret
broker policy      checks agent, plugin, repo, host, method, and purpose
GitHub/API         receives only approved broker-mediated requests or tokens
```

`git-host-credentials` currently supports in-container Git host credentials as
a local/dev fallback, including GitHub App private keys. That keeps the runtime
usable before the manager exists, but the intended operator mode is to move
GitHub App private keys and other plugin secrets into broker-managed Kubernetes
Secrets or external secret providers.

Broker mode starts that split locally: GitHub App private keys live in the
broker service, while agents use `brokerctl` or broker-backed
`git-host-credential` providers.

Local shared-broker mode uses per-agent bearer tokens and grants stored under
`.broker/agents.yaml`. The token identifies an agent to the broker; grants
narrow each provider's repository ceiling. This is a local development identity
model, not production workload identity.

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

Build the runtime and broker images:

```sh
make runtime-build
make broker-build
```

Start shared local infra. This starts the Traefik proxy and the shared broker
service, and creates `.broker/` files from templates if they do not exist:

```sh
make infra-up
```

Create an agent config:

```sh
make agent-init NAME=frontend
```

`agent-init` defaults to `AUTONOMY=trusted-local`, so generated agents include
explicit approval-bypass flags for the selected terminal agent CLI. Use
`AUTONOMY=interactive` if you want the CLI to ask for approvals normally:

```sh
make agent-init NAME=frontend AUTONOMY=interactive
```

`trusted-local` trusts the local agent environment: the workspace mount, the
agent container, broker-granted capabilities, and the per-agent Docker daemon.
It does not grant direct access to the rest of the host filesystem, but it is
still powerful because the agent can run commands, start containers, and mutate
checked-out repos.

Copy an initialized agent definition to a new local agent, with a fresh broker
token and copied broker grants:

```sh
make agent-copy FROM=frontend TO=frontend-2
```

Use `make agent-cp FROM=frontend TO=frontend-2` as the short alias. To create
the new agent without copying broker grants, pass `COPY_GRANTS=0`. To also copy
the source workspace contents and per-agent auth files, pass `COPY_WORKSPACE=1`.
Use `COPY_AUTH=0` with `COPY_WORKSPACE=1` to leave auth behind.

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

If the agent needs brokered access to private GitHub resources, configure the
local broker and grant the agent a repo before starting it. See
[Local Broker](#local-broker). For a complete broker-backed setup for
developing this repo with a local agent, see
[Local Development Agent From Scratch](docs/local-development-agent.md).

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
make agent-copy FROM=frontend TO=frontend-2
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
  args:
    - --sandbox
    - danger-full-access
    - --ask-for-approval
    - never
```

Claude Code can be selected at init time:

```sh
make agent-init NAME=research TYPE=claude
```

which generates:

```yaml
runtime:
  command: claude
  args:
    - --dangerously-skip-permissions
```

The runtime itself is generic: it runs `runtime.command` with `runtime.args`.
For another terminal agent, set those fields directly in `agent.yaml`.

Codex auth/config is seeded from host `~/.codex` into
`.agents/<name>/auth/codex` and mounted into the container at `/root/.codex`.
Claude Code auth is stored per agent under `.agents/<name>/auth/claude` and
mounted into the container at `/root/.claude`.

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
matching hostnames to code-server inside each agent's shared local network
namespace on port `4090`.

The route is created from Docker labels in `compose.agent.yaml`:

```yaml
traefik.http.routers.${AGENT_NAME}.rule=Host(`${AGENT_HOST}`)
traefik.http.services.${AGENT_NAME}.loadbalancer.server.port=4090
```

Agents can also expose local HTTP services running inside the agent's shared
local network namespace.
Configure named routes in `.agents/<name>/agent.yaml`:

```yaml
expose:
  http:
    - name: app
      targetPort: 3000
    - name: api
      targetPort: 8080
```

After `make agent-up NAME=<name>`, those services are reachable through the
same proxy port:

```text
http://app.<name>.agent.localhost:4090
http://api.<name>.agent.localhost:4090
```

Route names must be unique DNS labels. `targetPort` is a port in the agent's
shared local namespace. It can be served by a direct agent process, or by an
inner Docker/Compose service that publishes that port. Ports `4090`
(code-server) and `2375` (Docker API) are reserved. The host-side renderer
supports the block YAML shape shown above; keep `expose.http` in that form
rather than flow-style inline YAML.

For one-off local access without editing `agent.yaml`, run a temporary forward:

```sh
make forward NAME=frontend PORT=3000
make forward NAME=frontend PORT=3000 LOCAL=9000
```

This starts a foreground `alpine/socat` helper on the `agents-proxy` network.
The first run may pull the image. Stop the forward with Ctrl-C.

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
    AGENTS.local.md
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
.agents/<name>/workspace/AGENTS.local.md
                                      local agent guidance appended to generated AGENTS.md
.agents/<name>/custom-plugins/       host directory for custom plugin binaries/scripts
.agents/<name>/auth/codex/           per-agent Codex auth/config seeded from host
.agents/<name>/auth/claude/          per-agent Claude Code auth/config
```

The runtime generates `.agents/<name>/workspace/AGENTS.md` at container startup.
Edit `AGENTS.local.md` for workspace-specific guidance; `agent-init` creates it
once and later runs do not overwrite it.

The generated env file contains the host paths used by Compose:

```env
AGENT_NAME=frontend
AGENT_HOST=frontend.agent.localhost

WORKSPACE_DIR=/absolute/path/.agents/frontend/workspace
NVT_WORKSPACE=/absolute/path/.agents/frontend/workspace
CUSTOM_PLUGINS_DIR=/absolute/path/.agents/frontend/custom-plugins
AGENT_CONFIG_FILE=/absolute/path/.agents/frontend/agent.yaml
NVT_AGENT_CONFIG_FILE=/nvt-agent/agent.yaml

NVT_BROKER_URL=http://broker:7347
NVT_BROKER_TOKEN=<per-agent random token>

CODEX_CONFIG_DIR=/absolute/path/.agents/frontend/auth/codex
CLAUDE_CONFIG_DIR=/absolute/path/.agents/frontend/auth/claude
```

The workspace is bind-mounted at the same absolute path inside the container.
This is also mounted into the per-agent Docker sidecar at the same path, so
Docker Compose bind mounts from the workspace resolve correctly.

## Local Broker

The local broker keeps root secrets outside agent containers while still letting
agents use approved GitHub App capabilities. `make infra-up` starts the broker
from the local `nvt-broker:latest` image, so run `make broker-build` before
starting infra.

Broker files live under `.broker/`, which is ignored by git:

```text
.broker/broker.yaml      provider definitions and repository ceilings
.broker/agents.yaml      per-agent token hashes and grants
.broker/env              broker-only secret environment variables
.broker/audit.jsonl      broker audit log
```

Configure a provider in `.broker/broker.yaml`:

```yaml
providers:
  - name: github-fork-app
    plugin: github-app
    config:
      app-id-env: GITHUB_APP_ID
      installation-id-env: GITHUB_APP_INSTALLATION_ID
      private-key-base64-env: GITHUB_APP_PRIVATE_KEY_BASE64
      api-url: https://api.github.com
    allow:
      repositories:
        - my-user/*
      permissions:
        contents: read
        pull_requests: read
        checks: read
      methods:
        - GET
```

Put the real secret values in `.broker/env`:

```env
GITHUB_APP_ID=123456
GITHUB_APP_INSTALLATION_ID=987654
GITHUB_APP_PRIVATE_KEY_BASE64=...
```

Static PAT and header providers can also live in the broker:

```yaml
providers:
  - name: github-pat
    plugin: token
    config:
      token-env: GITHUB_PAT
    allow:
      repositories:
        - my-user/frontend

  - name: company-headers
    plugin: headers
    config:
      target-mode: literal
      headers:
        - header-env: COMPANY_GIT_API_KEY_HEADER
    allow:
      repositories:
        - altinn.studio/repos/digdir/oed
```

These are compatibility providers. They keep raw secret env vars out of the
agent container and put grants/audit in the broker, but Git token/header flows
still return credentials to the agent. GitHub App remains the stronger Git path
because broker-minted installation tokens are short-lived and repo-scoped.

Codex ChatGPT-plan OAuth can use the broker as the single refresh-token writer.
Configure the broker with the canonical read-write `auth.json`; agents receive
a file bundle whose `auth.json` contains a valid access token and a stub refresh
token:

```yaml
providers:
  - name: codex-main
    plugin: codex-oauth
    config:
      auth-file: /broker-secrets/codex/auth.json
      token-url: https://auth.openai.com/oauth/token
      client-id: app_EMoamEEZ73f0CkXaXp7hrann
      refresh-margin-seconds: 600
      bundle-ttl-seconds: 1200
      stub-refresh-token: nvt-broker-stub
      extra-files:
        - name: config.toml
          path: /broker-secrets/codex/config.toml
```

Grant the provider by name; repositories do not apply to file bundles:

```yaml
agents:
  - id: frontend
    token-sha256: sha256:<hash>
    grants:
      - provider: codex-main
```

Materialize the bundle before the agent starts:

```yaml
plugins:
  - name: broker-auth-files
    source: builtin
    when: before-agent
    restart: never
    config:
      bundles:
        - provider: codex-main
          target: /root/.codex
          dir-mode: "0700"
          file-mode: "0600"
```

For long-lived agents, keep the bundle fresh with the generic refresher:

```yaml
plugins:
  - name: broker-auth-files
    source: builtin
    when: before-agent
    config:
      bundles:
        - provider: codex-main
          target: /root/.codex
  - name: broker-auth-files-refresher
    source: builtin
    when: after-agent
    restart: always
    config:
      bundles:
        - provider: codex-main
          target: /root/.codex
      refresh-slack-seconds: 900
```

Long-lived auth has three levers. Broker provider
`refresh-margin-seconds` controls when the canonical broker token is refreshed,
and `bundle-ttl-seconds` caps the broker-vended bundle's `expires_at` metadata
as short-lived bundle metadata. OpenAI owns the actual access-token lifetime:
`bundle-ttl-seconds` does not reduce the lifetime of an already-issued OpenAI
access token. The `broker-auth-files-refresher` plugin uses that metadata for
frequent broker re-materialization so indefinite runs keep fresh files on disk.
With the defaults, `1200 - 900 = 300s`, so the refresher wakes roughly every
five minutes per agent. If `bundle-ttl-seconds <= refresh-slack-seconds`, the
runtime clamps to `min-sleep-seconds`, which can create a 60-second loop with
the defaults. For Codex, frequent re-materialization is sufficient because the
running CLI reloads `auth.json` from disk after a real 401 before trying OAuth
refresh, while preserving the broker-vended `account_id` satisfies Codex's
reload guard. The canonical contract is in `protocol/broker.md`.

This is still the Codex plan-auth fallback file-bundle path. The root refresh
token stays broker-owned, but agent-side bundles still contain the real OpenAI
access token plus inert stub fields. This remains the insecure/compatibility
file-bundle fallback until credential-less Codex ships.

The operator `runtimeAuth` Secret path documented in
`operator/docs/kind-codex-auth.md` remains the local/dev fallback for Codex
auth seeding; this broker path does not change the operator.

In Kubernetes, `codex-oauth` should run with persistent broker state because
the broker-owned `/state/codex/auth.json` contains the current refresh-token
lineage. Install order:

1. Create the seed Secret with `make operator-codex-auth-secret`.
2. Install or upgrade `charts/nvt` with `broker.persistence.enabled=true` and
   `broker.persistence.seedSecretName=codex-auth`.
3. Configure the provider `auth-file` as `/state/codex/auth.json`.

The seed is copied only when the target state directory is absent or empty; do
not re-apply an old seed Secret over live broker state after token rotation.

`agent-init` registers each agent with an empty grant set by default. Grant a
specific repo before the agent uses brokered credentials:

```sh
make agent-init NAME=frontend
make agent-grant NAME=frontend PROVIDER=github-fork-app REPO=my-user/frontend
```

Use `agent-copy` to create an equivalent parallel agent. It copies
`.agents/<FROM>/agent.yaml`, copies `workspace/AGENTS.local.md` when present,
creates fresh env/auth/workspace/plugin directories, writes a new broker token,
and copies the broker grants by default. Workspace contents are copied only
when requested; auth is included with workspace copies unless disabled:

```sh
make agent-copy FROM=frontend TO=frontend-2
make agent-copy FROM=frontend TO=frontend-3 COPY_GRANTS=0
make agent-copy FROM=frontend TO=frontend-4 COPY_WORKSPACE=1
make agent-copy FROM=frontend TO=frontend-5 COPY_WORKSPACE=1 COPY_AUTH=0
```

The broker enforces the intersection of the provider ceiling and the agent
grant. For example, if the provider allows `my-user/*` but `frontend` is granted
only `my-user/frontend`, that agent cannot use the provider for
`my-user/backend`.

Inside the agent container, broker clients use:

```env
NVT_BROKER_URL=http://broker:7347
NVT_BROKER_TOKEN=<per-agent token>
```

This local token is a development identity mechanism. Production Kubernetes
mode should replace it with workload identity such as ServiceAccount or SPIFFE,
with root secrets mounted only into broker-managed components.

For an end-to-end local setup guide, see
[Local Development Agent From Scratch](docs/local-development-agent.md).

## Agent Config

Each agent is configured with `.agents/<name>/agent.yaml`.

Minimal generated config:

```yaml
runtime:
  command: codex

tools:
  packages: []
  mise: []
  additional-paths: []
  shell: []

plugins: []
```

Tool bootstrap runs before plugins and before the agent session starts.

Example:

```yaml
tools:
  packages:
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

Default settings can be provided inline:

```yaml
code-server:
  extensions:
    - redhat.vscode-yaml
  settings:
    overwrite: false
    values:
      workbench.colorTheme: "Default Dark Modern"
      workbench.startupEditor: "none"
      editor.minimap.enabled: false
      security.workspace.trust.enabled: false
```

Bootstrap writes `settings.values` as JSON to code-server's user settings:

```text
/root/.local/share/code-server/User/settings.json
```

With `overwrite: false`, existing browser-edited settings are preserved. With
`overwrite: true`, the inline settings replace the existing file.

The older file-based form still works for existing agents, but is deprecated:

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

To save recent terminal-agent output from tmux, use:

```sh
agent-capture --lines 200 --out logs.txt
```

With no flags, `agent-capture` writes the last 100 lines from session
`${AGENT_SESSION:-agent}` to `agent-capture.txt` in the current directory. Use
`--print` to write the capture to stdout instead.

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
- Docker CLI and Compose plugin
- Codex CLI
- Claude Code CLI
- mise
- Python YAML support for runtime scripts

Container startup order:

```text
1. bootstrap tools from agent.yaml
2. export enabled plugin tools into PATH
3. write generated agent instructions
4. run before-agent plugins
5. start agentd
6. start code-server
7. start the terminal agent in tmux
8. run after-agent plugins in the background
```

Codex auth/config is seeded from host `~/.codex` into
`.agents/<name>/auth/codex` and mounted to `/root/.codex` read-write so Codex
can store runtime state. Claude auth is stored per agent under
`.agents/<name>/auth/claude` and mounted to `/root/.claude`.

Each agent also gets its own Docker daemon sidecar. The agent talks to it with
`DOCKER_HOST=tcp://127.0.0.1:2375`; the host Docker socket is intentionally not
mounted. The agent and sidecar share one local network namespace, matching the
Kubernetes Pod model more closely: direct agent processes and ports published by
inner Docker Compose projects bind in the same namespace. This lets multiple
agents run the same Docker Compose project without sharing Docker images,
containers, networks, or volumes.

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
