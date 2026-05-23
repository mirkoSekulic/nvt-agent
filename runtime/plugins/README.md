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

`plugin.yaml` defines the default command:

```yaml
command: /usr/local/lib/nvt-agent/plugins/<name>/run.py
```

The runner reads `plugins:` from `agent.yaml`, writes each plugin's `config:`
section to a runtime file, and runs the plugin command with:

```text
NVT_PLUGIN_CONFIG=/root/.nvt-agent/plugins/<name>/config.yaml
NVT_PLUGIN_NAME=<name>
```

`NVT_PLUGIN_CONFIG` is the main contract. Plugins should read that file and exit
non-zero on failure.

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
```

`git-credentials` is optional. Use it before `checkout-repos` when private repos
need credentials. It configures Git once; later `git clone`, `git fetch`, and
`git push` use Git's normal credential helper flow.

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

`prompt-agent` reads stdin, adds a warning that the prompt came from a plugin,
and injects it into the main tmux agent session. Plugins should not call `tmux`
directly.

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
