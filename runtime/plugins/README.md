# Runtime Plugins

Builtin runtime plugins live here and are copied into the image at:

```text
/usr/local/lib/nvt-agent/plugins
```

Each builtin plugin has its own directory:

```text
runtime/plugins/<name>/
  plugin.yaml
  run.py
```

`plugin.yaml` defines builtin plugin defaults:

```yaml
command: /usr/local/lib/nvt-agent/plugins/<name>/run.py
health:
  command: /usr/local/lib/nvt-agent/plugins/<name>/run.py ready
doctor:
  command: /usr/local/lib/nvt-agent/plugins/<name>/run.py doctor
exports:
  tools: []
```

The runner reads `plugins:` from `agent.yaml`, writes each plugin's `config:`
section to a runtime file, writes minimal plugin lifecycle state, and runs the
plugin command with:

```text
NVT_PLUGIN_NAME=<name>
NVT_PLUGIN_CONFIG=/root/.nvt-agent/plugins/<name>/config.yaml
```

`NVT_PLUGIN_CONFIG` is the main contract. Plugins should read that file and exit
non-zero on failure.

Runtime state is written under `NVT_STATE_DIR`, which defaults to
`/root/.nvt-agent`:

```text
$NVT_STATE_DIR/plugins/<name>/
  config.yaml
  state.json
```

Plugins should not write `state.json` directly. The process plugin runner owns
that file and updates fields such as `status`, `ready`, `pid`,
`last_exit_code`, and `last_error`. Plugin stdout/stderr stays in the container
logs.

## Exported Tools

Plugins can explicitly export public tools. Exported tools are made available on
`PATH` through generated wrappers in `$HOME/.local/bin`.

```yaml
exports:
  tools:
    - name: github-helper
      command: /usr/local/lib/nvt-agent/plugins/github-helper/github-helper
      description: GitHub PR/checks helper
```

The generated wrapper sets the exporting plugin context before executing the
tool:

```text
NVT_PLUGIN_NAME
NVT_PLUGIN_CONFIG
NVT_WORKSPACE
```

Plugins whose lifecycle process or exported tools make authenticated HTTPS
requests can select a broker provider without implementing mediation logic:

```yaml
plugins:
  - name: example-http-plugin
    source: builtin
    egress:
      provider: company-oauth
```

In mediated forward-proxy or transparent transport, the generic launcher and
tool wrapper supply the provider-scoped `HTTPS_PROXY` environment. Plain HTTP
is deliberately not sent to egressd's CONNECT-only injection listener. The plugin
makes an ordinary request; it does not inspect the run's egress mode, construct
an egress URL, call `brokerctl`, or carry a placeholder header. The exact
provider capability may be backed by multiple repository-aggregating grants,
but every entry must use the same injection-eligible materialization. Direct
mode leaves networking unchanged, and omitting `egress` leaves all modes
unchanged. Loopback callbacks remain in `NO_PROXY`.

Provider names must remain unique after uppercase environment normalization
(punctuation runs become `_`). Bootstrap rejects colliding names before plugin
launch rather than making one valid provider unreachable.

Exported tools are public inside the agent container: the agent, terminal users,
and other plugins can call them. Do not export tools that require raw long-lived
secrets in their plugin config. Secret-bearing operations should go through
`brokerctl` or broker-backed providers where possible.

Tool wrappers are regenerated at container startup from the enabled plugins.
Stale generated wrappers are removed. Tool names must not collide with other
plugin exports or existing commands on `PATH`.

## Builtin Example

```yaml
plugins:
  - name: git-host-credentials
    source: builtin
    config:
      default-provider: fork-app
      providers:
        - name: fork-app
          type: github-app
          app-id-env: GITHUB_APP_ID
          installation-id-env: GITHUB_APP_INSTALLATION_ID
          private-key-base64-env: GITHUB_APP_PRIVATE_KEY_BASE64
          match:
            - github.com/example/*

  - name: git-credentials
    source: builtin
    when: before-agent
    config:
      credentials:
        - match: https://github.com/example/
          provider: fork-app
          identity:
            mode: provider

  - name: checkout-repos
    source: builtin
    when: before-agent
    restart: never
    config:
      repos:
        - url: https://github.com/example/public-repo.git
        - url: https://github.com/agent-user/forked-repo.git
          path: forked-repo
          upstream: https://github.com/original-org/forked-repo.git
```

`git-credentials` is optional. Use it before `checkout-repos` when private repos
need credentials. It configures Git once; later `git clone`, `git fetch`, and
`git push` use Git's normal credential helper flow. Token providers use
`git-credential-nvt`; header providers configure Git `http.<url>.extraHeader`
entries directly.

Commit identity is separate from Git auth username. `git-credentials` can set
repo-local `user.name` and `user.email` either explicitly or from a provider:

```yaml
identity:
  mode: provider
```

Provider identity is currently intended for broker-backed GitHub App providers.
For token/header providers, use:

```yaml
identity:
  mode: explicit
  name: "Automation Bot"
  email: "automation@example.com"
```

`checkout-repos` invokes `git-credentials configure-repo <repo>` after clone as
a best-effort identity setup step.

Broker-backed static PAT/header providers remove raw secret env vars from the
agent, but Git compatibility flows still expose returned tokens or headers to
the agent. Treat them as compatibility providers. GitHub App broker providers
are stronger for Git because they return short-lived repo-scoped installation
tokens.

`git-host-credentials` is a tool-only plugin. It resolves named credential
providers for Git hosting services and exports two tools:

```sh
git-host-credential token --provider fork-app
git-host-credential identity --provider fork-app --target github.com/example/project
git-host-credential headers --provider company-headers
git-host-credential credential-kind --provider company-headers
git-host-credential doctor --provider fork-app
gh-auth pr view 123 --repo example/project
```

`credential-kind: mediated` is available for broker providers whose Git traffic
is routed through egressd. In that mode `git-host-credential` refuses token and
header export; the real credential is injected outside the agent container.

`gh-auth` runs `gh` with a per-command token through `GH_TOKEN`. It
does not call `gh auth login` and does not persist credentials in the GitHub CLI
config. If `--provider` is omitted, it resolves a provider from `--repo`, the
current git remote, or `default-provider`.
For mediated providers, `GH_TOKEN` is only the inert NVT placeholder and
`gh-auth` uses the same generic provider-scoped environment resolver as plugin
wrappers. This compatibility command remains because interactive `gh` calls
select a provider per invocation; the watcher itself no longer uses it as an
HTTP transport.

Security note: `git-host-credentials` currently supports local/dev operation
where raw provider secrets, including GitHub App private keys, are provided to
the agent container through env or mounted files. Those secrets should be scoped
to the smallest possible set of repos and permissions. This is not the
production boundary for autonomous agents. The intended operator mode is for a
broker service to hold raw secrets, enforce capability policy, and let
`git-host-credentials` act as a broker client rather than a key holder.

`checkout-repos` supports fork workflows with optional `upstream`. If provided
on a newly cloned repo, it adds the original repository as the `upstream`
remote:

```yaml
repos:
  - url: https://github.com/agent-user/project.git
    path: project
    upstream: https://github.com/org/project.git
```

Existing repositories are skipped and left untouched, including remotes.

`github-watcher` watches GitHub PR comments, reviews, and aggregate check
transitions. Static PRs are configured in `agent.yaml`; dynamic PRs can be added
with the exported `github-watch register` command and are persisted under the
plugin state directory so they survive container restart. See
`runtime/plugins/github-watcher/README.md` for the full schema.

`event-webhook` subscribes to `agentd` events and forwards matching event
envelopes to a configured HTTP endpoint. It is generic and does not interpret
event payloads. See `runtime/plugins/event-webhook/README.md` for configuration
and delivery options.

`smoke-complete` is a tiny after-agent smoke/test plugin. It waits for
`event-webhook` readiness by default, sleeps for `delaySeconds`, and publishes a
deterministic `agentd` event, defaulting to `plugin.smoke.completed` with
payload `{ok: true}`. It is intended for local and operator lifecycle smoke
tests without GitHub or external services. See
`runtime/plugins/smoke-complete/README.md` for the full config.

`lifecycle-termination` is injected by the Kubernetes operator for enforced
literal zero-secret AgentRuns. It reports a matched lifecycle event through
the agent container's Kubernetes termination message and carries no reusable
callback credential. See
`runtime/plugins/lifecycle-termination/README.md`.

## Scaffolding

Generate a plugin folder from templates:

```sh
make plugin-init NAME=my-plugin
```

By default this creates a builtin plugin under:

```text
runtime/plugins/my-plugin/
```

To create a custom plugin for one agent:

```sh
make plugin-init NAME=my-plugin DIR=.agents/frontend/custom-plugins
```

The generated `plugin.yaml` includes common plugin metadata:

```yaml
command: /custom-plugins/my-plugin/run.sh
health:
  command: /custom-plugins/my-plugin/run.sh ready
doctor:
  command: /custom-plugins/my-plugin/run.sh doctor
exports:
  tools: []
```

`doctor.command` is diagnostic. It should check whether the plugin has the tools,
configuration, and credentials it needs. It is separate from readiness.
Whether a plugin blocks agent readiness is configured per agent in `agent.yaml`
with `health.readiness: true`.

Credential `match` values are URL prefixes. They can target a server, an
org/user, or one repo:

```yaml
credentials:
  - match: https://github.com/
    provider: general-github-token
    identity:
      mode: explicit
      name: General Automation
      email: automation@example.com
  - match: https://github.com/acme/
    provider: fork-app
    identity:
      mode: provider
  - match: https://github.com/acme/frontend.git
    provider: frontend-token
    identity:
      mode: explicit
      name: Frontend Automation
      email: frontend-automation@example.com
```

The most specific matching rule wins.

Credential rules point at providers from `git-host-credentials`:

```yaml
plugins:
  - name: git-host-credentials
    source: builtin
    config:
      providers:
        - name: acme-token
          type: token-env
          token-env: ACME_PAT
          match:
            - github.com/acme/*
        - name: fork-app
          type: github-app
          app-id-env: GITHUB_APP_ID
          installation-id-env: GITHUB_APP_INSTALLATION_ID
          private-key-base64-env: GITHUB_APP_PRIVATE_KEY_BASE64
          match:
            - github.com/acme/*
        - name: company-headers
          type: headers
          headers:
            - header-env: COMPANY_GIT_API_KEY_HEADER

credentials:
  - match: https://github.com/acme/
    provider: acme-token
    identity:
      mode: explicit
      name: Acme Automation
      email: automation@example.com

  - match: https://github.com/acme/
    provider: fork-app
    identity:
      mode: provider
```

For provider `headers`, each `header-env` contains one full HTTP header line:

```env
COMPANY_GIT_API_KEY_HEADER=X-API-Key: xyz789
```

## Custom Example

Custom plugins are provided per agent from:

```text
.agents/<name>/custom-plugins/
```

That directory is mounted inside the container at:

```text
/custom-plugins
```

`agent-init` writes the host path to the agent env file:

```env
CUSTOM_PLUGINS_DIR=/path/to/.agents/<name>/custom-plugins
```

`compose.agent.yaml` mounts that host path into the container:

```yaml
${CUSTOM_PLUGINS_DIR}:/custom-plugins
```

Edit `CUSTOM_PLUGINS_DIR` in `.agents/<name>/env` if custom plugins should live
somewhere else on the host.

For example, this host file:

```text
.agents/frontend/custom-plugins/custom-plugin
```

is available inside the `frontend` agent container as:

```text
/custom-plugins/custom-plugin
```

Example `agent.yaml`:

```yaml
plugins:
  - name: custom-plugin
    source: custom
    command: /custom-plugins/custom-plugin
    when: after-agent
    restart: always
    health:
      readiness: true
    config:
      poll-seconds: 30
```

The command can be any executable script or binary, written in any language
available in the container, such as Bash, Python, Node.js, Go, or Rust. It should
read `NVT_PLUGIN_CONFIG` for its configuration.

Plugins inherit the agent container environment. If a plugin needs to read or
write files in the agent workspace, it can use `NVT_WORKSPACE` as the workspace
path.

### Public Git sources

An implementation can instead be selected explicitly from a public HTTPS Git
repository at an immutable full commit object ID:

```yaml
plugins:
  - name: example-runtime
    source:
      git:
        url: https://github.com/example/nvt-plugins.git
        revision: 0123456789abcdef0123456789abcdef01234567
        subdir: plugins/example-runtime
    when: after-agent
```

The selected directory must contain the same `plugin.yaml` manifest used by
packaged plugins. Lifecycle and exported-tool commands in a Git-sourced
manifest are executable paths relative to that directory. Each implementation
is declared separately; repositories are never scanned or auto-enabled, so two
entries can select different subdirectories of one repository.

A Git-sourced `health.command` follows the same containment rule: it is a safe
relative executable path beneath the selected directory and runs directly,
without shell expression parsing. Existing builtin, custom, and local health
commands keep their current behavior.

Only public HTTPS sources are supported. Interactive authentication, credential
helpers, redirects, submodules, Git LFS, hooks, builds, installs, and floating
revisions are disabled. `NVT_GIT_SOURCE_ALLOWED_HOSTS` is a comma-separated
exact-host allowlist and defaults conservatively to `github.com`. The runtime
caches a verified checkout by canonical URL plus revision, publishes it
atomically, revalidates cache hits, and independently checks each selected
subdirectory against traversal and symlink escape. It never updates a declared
revision automatically.

Fetched runtime plugins remain untrusted code inside the agent container. This
does not grant them broker trust or create a sandbox boundary.

## Prompting The Agent

An AgentRun's initial prompt is part of the generic runtime launch contract and
is passed as the final command argument. The plugin prompt path below is only
for later work sent to an already-running session.

Plugins should use `prompt-agent` to send work to the running Codex or Claude
Code session:

```sh
echo "Review the workspace and summarize failing tests." | prompt-agent
```

`prompt-agent` is a compatibility wrapper around `agentdctl prompt`.
`agentd` queues the prompt, adds an external-input warning, and injects it into
the main tmux agent session as the single session writer. Plugins should not
call `tmux` directly.

Reactive plugins can subscribe to the event log:

```sh
agentdctl subscribe --filter plugin.test-runner.failed | while read -r event; do
  printf '%s\n' "$event" | prompt-agent
done
```

`agentdctl subscribe` defaults to `--since end`, so restarted plugins only see
future events. Use `--since beginning` only for idempotent reactions, because it
replays historical events.

## Lifecycle

`when` controls startup order:

- `before-agent`: run before code-server and the main agent session start
- `after-agent`: run after the main agent session starts

`restart` controls process restart behavior:

- `never`: run once
- `on-failure`: restart only after non-zero exits
- `always`: restart after every exit

`retries` controls immediate retry attempts for a failed run.
`restart-delay-seconds` controls the delay before retries or restarts.

## Health

The image includes a readiness-style `health` command:

```sh
health
health --json
```

Docker uses it through the image `HEALTHCHECK`. In Docker Compose this marks the
container `healthy` or `unhealthy`; it does not restart the container by itself.
Kubernetes AgentRun Pods use the same command as the agent-container readiness
probe, so the gateway does not route a session until code-server, agentd, the
tmux agent session, and readiness-blocking plugins are ready. It is not a
liveness probe and does not restart a slow bootstrap.

After startup has established the configured tmux agent session, PID 1 also
supervises that session. If it disappears unexpectedly, the main agent
container exits non-zero instead of remaining alive but unhealthy. Kubernetes
AgentRun Pods use `restartPolicy: Never`, so the existing operator status and
TTL path records the run as failed; the runtime does not create a replacement
session. An intentional lifecycle-reporting `TERM` exits cleanly instead.

In local Compose, this stops only the main agent container. Its Docker,
egress, capture, and other support containers may continue running until
`make agent-down NAME=<name>`.

By default, plugins do not affect readiness. Add `health.readiness: true` when a
plugin should block agent readiness:

```yaml
plugins:
  - name: custom-plugin
    source: custom
    command: /custom-plugins/custom-plugin
    when: after-agent
    restart: always
    health:
      readiness: true
```

Without `health.command`, readiness is based on lifecycle state:

- `restart: never`: ready after exit `0`
- `restart: on-failure`: ready while running or after exit `0`
- `restart: always`: ready while running

For deeper readiness checks, provide a command:

```yaml
health:
  readiness: true
  command: /custom-plugins/custom-plugin --ready
```

When `health.command` is present, the command decides readiness. Exit `0` means
ready, and any non-zero exit means not ready. For process plugins, the plugin
state file must still exist so the runtime knows the plugin was launched.

## Doctor

`doctor` is diagnostic. It is separate from readiness.

```sh
doctor
doctor --core
doctor --plugins
doctor --plugin custom-plugin
doctor --json
```

The core doctor command checks runtime basics and generically discovers plugin
doctor commands from `agent.yaml` and builtin `plugin.yaml` files. Plugin-specific
checks belong inside each plugin's `doctor.command`.
