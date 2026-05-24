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

## Builtin Example

```yaml
plugins:
  - name: git-credentials
    source: builtin
    when: before-agent
    config:
      credentials:
        - match: https://github.com/example/
          type: token-env
          token-env: GIT_TOKEN
          username: x-access-token

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
`git push` use Git's normal credential helper flow.

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
    type: token-env
    token-env: GENERAL_GITHUB_TOKEN
    username: x-access-token
  - match: https://github.com/acme/
    type: github-app
    app-id-env: GITHUB_APP_ID
    installation-id-env: GITHUB_APP_INSTALLATION_ID
    private-key-b64-env: GITHUB_APP_PRIVATE_KEY_B64
  - match: https://github.com/acme/frontend.git
    type: token-env
    token-env: FRONTEND_TOKEN
    username: x-access-token
```

The most specific matching rule wins.

Supported credential types:

```yaml
credentials:
  - match: https://github.com/acme/
    type: token-env
    token-env: ACME_PAT
    username: x-access-token

  - match: https://github.com/acme/
    type: github-app
    app-id-env: GITHUB_APP_ID
    installation-id-env: GITHUB_APP_INSTALLATION_ID
    private-key-b64-env: GITHUB_APP_PRIVATE_KEY_B64

  - match: https://git.company.com/team/
    type: headers
    headers:
      - header-env: COMPANY_GIT_AUTH_HEADER
      - header-env: COMPANY_GIT_API_KEY_HEADER
```

For `headers`, each `header-env` contains one full HTTP header line:

```env
COMPANY_GIT_AUTH_HEADER=Authorization: Bearer abc123
COMPANY_GIT_API_KEY_HEADER=X-Api-Key: xyz789
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

## Prompting The Agent

Plugins should use `prompt-agent` to send work to the running Codex or Claude
Code session:

```sh
echo "Review the workspace and summarize failing tests." | prompt-agent
```

`prompt-agent` is a compatibility wrapper around `agentdctl prompt`.
`agentd` queues the prompt, adds an external-input warning, and injects it into
the main tmux agent session as the single session writer. Plugins should not
call `tmux` directly.

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
The same command can later be used by a Kubernetes `readinessProbe`.

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
