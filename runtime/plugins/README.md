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
  - name: checkout-repos
    source: builtin
    when: before_agent
    restart: never
    config:
      repos:
        - url: https://github.com/example/public-repo.git
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
    when: after_agent
    restart: always
    config:
      poll_seconds: 30
```

The command can be any executable script or binary, written in any language
available in the container, such as Bash, Python, Node.js, Go, or Rust. It should
read `NVT_PLUGIN_CONFIG` for its configuration.

Plugins inherit the agent container environment. If a plugin needs to read or
write files in the agent workspace, it can use `NVT_WORKSPACE` as the workspace
path.

## Lifecycle

`when` controls startup order:

- `before_agent`: run before code-server and the main agent session start
- `after_agent`: run after the main agent session starts

`restart` controls process restart behavior:

- `never`: run once
- `on-failure`: restart only after non-zero exits
- `always`: restart after every exit

`retries` controls immediate retry attempts for a failed run.
`restart_delay_seconds` controls the delay before retries or restarts.
