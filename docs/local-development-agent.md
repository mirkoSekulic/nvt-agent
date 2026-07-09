# Local Development Agent From Scratch

This guide sets up one local agent for developing this repository with a shared
local broker and a GitHub App provider. The agent gets a broker identity token;
the GitHub App private key stays in `.broker/env` and is mounted only into the
broker service.

The examples use:

```sh
AGENT=nvt-dev
REPO=mirkosekulic/nvt-agent
PROVIDER=github-main-app
```

Replace those values for another agent, repository, or broker provider.

## Prerequisites

- Docker Desktop or another Docker engine with Compose support.
- A GitHub App installed on the repository you want the agent to work on.
- The GitHub App ID, installation ID, and private key `.pem` file.
- Local Codex auth under `~/.codex` if the agent uses Codex.
- This repository checked out locally.

Keep the GitHub App private key outside the repository. Do not commit `.broker/`
or `.agents/`; both are local runtime state.

## 1. Prepare Local Variables

From the repository root:

```sh
export AGENT=nvt-dev
export REPO=mirkosekulic/nvt-agent
export PROVIDER=github-main-app
export GITHUB_APP_ID=<numeric-app-id>
export GITHUB_APP_INSTALLATION_ID=<numeric-installation-id>
export GITHUB_APP_KEY_PEM=/absolute/path/to/private-key.pem
```

On macOS, encode the private key for the broker env file:

```sh
export GITHUB_APP_PRIVATE_KEY_BASE64="$(base64 -i "$GITHUB_APP_KEY_PEM" | tr -d '\n')"
```

On GNU/Linux, use:

```sh
export GITHUB_APP_PRIVATE_KEY_BASE64="$(base64 -w0 "$GITHUB_APP_KEY_PEM")"
```

## 2. Configure The Broker

Create local broker files:

```sh
mkdir -p .broker
cp -n templates/broker-agents.yaml .broker/agents.yaml
```

Write broker-only secret env vars:

```sh
cat > .broker/env <<EOF
GITHUB_APP_ID=$GITHUB_APP_ID
GITHUB_APP_INSTALLATION_ID=$GITHUB_APP_INSTALLATION_ID
GITHUB_APP_PRIVATE_KEY_BASE64=$GITHUB_APP_PRIVATE_KEY_BASE64
EOF
chmod 600 .broker/env
```

Write a GitHub App provider. The provider ceiling is the maximum scope the
broker can grant from this provider:

```sh
cat > .broker/broker.yaml <<EOF
providers:
  - name: $PROVIDER
    plugin: github-app
    config:
      app-id-env: GITHUB_APP_ID
      installation-id-env: GITHUB_APP_INSTALLATION_ID
      private-key-base64-env: GITHUB_APP_PRIVATE_KEY_BASE64
      api-url: https://api.github.com
    allow:
      repositories:
        - $REPO
      permissions:
        contents: write
        pull_requests: write
        checks: read
      methods:
        - GET
EOF
```

`permissions` are GitHub App installation-token permissions requested from
GitHub. `methods` controls broker HTTP executor methods; v1 uses `GET` for
brokered API reads. Git push uses token mode through Git credentials.

## 3. Build And Start Shared Infra

Build both images:

```sh
make runtime-build
make broker-build
```

Start the local proxy and broker:

```sh
make infra-up
```

The broker is not published to the host. Agents reach it at
`http://broker:7347` on the internal Compose network.

## 4. Create And Grant The Agent

Create the agent directory and env:

```sh
make agent-init NAME=$AGENT
```

This creates `.agents/$AGENT/env`, `.agents/$AGENT/agent.yaml`, workspace,
auth, and custom plugin directories. It also creates a per-agent broker token
and registers only the token hash in `.broker/agents.yaml` with no grants.
For mediated local compose agents, it also creates or reuses
`.agents/$AGENT/egress-ca/ca.crt` and `.agents/$AGENT/egress-ca/ca.key`.
Only the public certificate is mounted into the agent container at
`/nvt-egress-ca/ca.crt`; the private key path stays out of the agent env, and
the key is mounted only into egressd. Local compose runs that trusted egressd
sidecar as root so `ca.key` can stay `0600`. Deleting
`.agents/$AGENT/egress-ca/` rotates the local egress CA on the next mediated
creation.

To create a parallel local agent from an existing initialized one, copy the
agent definition and broker grants while generating a fresh broker token:

```sh
make agent-copy FROM=$AGENT TO=nvt-dev-copy
```

`make agent-cp` is the same command. Pass `COPY_GRANTS=0` to create the new
agent without copying broker grants. Pass `COPY_WORKSPACE=1` to copy workspace
contents and per-agent auth files. Add `COPY_AUTH=0` if you want the workspace
copy without auth.

Grant the agent access to the repository:

```sh
make agent-grant NAME=$AGENT PROVIDER=$PROVIDER REPO=$REPO
```

The broker enforces:

```text
effective scope = provider ceiling in .broker/broker.yaml
                ∩ agent grant in .broker/agents.yaml
```

The default empty grant set is deny-by-default. `agents.yaml` is live-reloaded
by the broker, so this does not require a broker restart.

## 5. Configure The Agent

Edit `.agents/$AGENT/agent.yaml`:

```sh
$EDITOR ".agents/$AGENT/agent.yaml"
```

New agents default to `AUTONOMY=trusted-local`, which writes explicit
auto-approval flags into `runtime.args`. That trusts the local agent environment:
the workspace mount, agent container, broker-granted capabilities, and
per-agent Docker daemon. Use `AUTONOMY=interactive` during `agent-init` if you
want the terminal agent CLI to ask for approvals normally.

A broker-backed configuration for developing this repo:

```yaml
runtime:
  command: codex
  args:
    - --sandbox
    - danger-full-access
    - --ask-for-approval
    - never

tools:
  packages:
    - jq
  mise: []
  additional-paths: []
  shell: []

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

expose:
  http:
    - name: app
      targetPort: 3000

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

  - name: github-watcher
    source: builtin
    when: after-agent
    restart: always
    config:
      default-provider: github-main
      poll-seconds: 60
      broker:
        enabled: true
        provider: github-main-app
      prs: []
```

Keep the `broker-provider` value aligned with `.broker/broker.yaml`. Keep the
`provider` values aligned with the local `git-host-credentials` provider name.

Git auth username defaults to `x-access-token` internally. `identity.mode:
provider` asks the broker-backed GitHub App provider for the App bot commit
identity and writes repo-local `user.name` / `user.email` after checkout.

## 6. Start The Agent

```sh
make agent-up NAME=$AGENT
make agent-logs NAME=$AGENT
```

Open code-server:

```text
http://nvt-dev.agent.localhost:4090
```

If you start an HTTP dev server inside the agent on port `3000`, open the
named route:

```text
http://app.nvt-dev.agent.localhost:4090
```

`expose.http` is local-development routing for HTTP services listening on ports
in the agent's shared local network namespace. That includes direct agent
processes and inner Docker Compose services that publish a port. Keep it in
block YAML form as shown. Ports `4090` and `2375` are reserved.

For temporary access to another port without editing `agent.yaml`:

```sh
make forward NAME=$AGENT PORT=5173
make forward NAME=$AGENT PORT=5173 LOCAL=9000
```

Open a shell:

```sh
make agent-shell NAME=$AGENT
```

## 7. Verify From Inside The Agent

Inside `make agent-shell`:

```sh
brokerctl health
docker info
docker compose version
git-host-credential token --provider github-main --target github.com/mirkosekulic/nvt-agent | wc -c
cd "$NVT_WORKSPACE/nvt-agent"
git fetch
agentdctl status
doctor
```

The token command should print a non-zero byte count. Do not print tokens in
logs or paste them into chat.

Optional push smoke test:

```sh
git switch -c nvt-agent-smoke
date > .nvt-smoke
git add .nvt-smoke
git commit -m "Smoke test brokered agent push"
git push -u origin nvt-agent-smoke
```

Delete the smoke branch and test file after verifying the path.

## 8. Optional: Watch A Pull Request

The watcher can be configured statically in `agent.yaml`, or dynamically from
inside the running agent:

```sh
github-watch register \
  --repo mirkosekulic/nvt-agent \
  --number <pr-number> \
  --label nvt-dev

github-watch list
```

Dynamic registrations are stored under the agent state directory and survive
container restart.
By default they accept PR comments and reviews from `OWNER`, `MEMBER`,
`COLLABORATOR`, and `CONTRIBUTOR`; include `CONTRIBUTOR` in static watcher
config for fork, upstream, or organization PR workflows where GitHub reports
maintainers that way.

## Troubleshooting

`nvt-broker:latest` cannot be found:

```sh
make broker-build
make infra-up
```

`brokerctl` says `NVT_BROKER_TOKEN` is not set:

- Recreate or inspect `.agents/$AGENT/env`.
- Start the shell with `make agent-shell NAME=$AGENT` so the agent env is loaded.

Broker returns `unauthorized`:

- Run `make agent-grant NAME=$AGENT PROVIDER=$PROVIDER REPO=$REPO`.
- Check `.broker/agents.yaml` has the agent entry and grant.
- Check the broker container is using the current `.broker` directory.

GitHub token minting fails:

- Confirm the GitHub App is installed on the repository.
- Confirm the app has the required repository permissions.
- Confirm `.broker/env` contains the app ID, installation ID, and base64 private
  key.

`git fetch` cannot find `git-credential-nvt`:

- Rebuild and restart the runtime image.
- Use `make agent-shell NAME=$AGENT` for an env-loaded shell.

`docker info` cannot reach Docker:

- Confirm the agent was recreated after the DinD change.
- Run `make agent-down NAME=$AGENT && make agent-up NAME=$AGENT`.
- Confirm `DOCKER_HOST=tcp://127.0.0.1:2375` is set inside the agent.

Docker API exposure check:

- Inside the agent, confirm dockerd listens only on localhost. If `ss` is
  installed, run `ss -ltn | grep 2375` and expect `127.0.0.1:2375`, not
  `0.0.0.0:2375`.
- If `ss` is unavailable, inspect `/proc/net/tcp`:

  ```sh
  python3 - <<'PY'
  from pathlib import Path
  for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
      parts = line.split()
      addr, port = parts[1].split(":")
      if port.upper() == "0947":
          ip = ".".join(str(int(addr[i:i+2], 16)) for i in (6, 4, 2, 0))
          print(f"{ip}:2375 state={parts[3]}")
  PY
  ```

  Expected output:

  ```text
  127.0.0.1:2375 state=0A
  ```

## Cleanup

Stop the agent:

```sh
make agent-down NAME=$AGENT
```

Remove the agent and its local state:

```sh
make agent-rm NAME=$AGENT FORCE=1
```

Stop shared infra:

```sh
make infra-down
```
