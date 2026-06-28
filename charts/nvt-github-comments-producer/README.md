# nvt-github-comments-producer chart

This chart deploys only the GitHub comments producer. It does not install the
nvt operator, broker, CRDs, runtime image resources, or any GitHub-specific
configuration into the core `charts/nvt` chart.

The producer polls configured GitHub repositories for:

```text
<configured-prefix> pr create
```

and creates `AgentRun` resources in the configured namespace.

## Install

Create a Secret that contains the GitHub App private key. The chart references
an existing Secret and never renders private key material into Kubernetes
manifests:

```sh
kubectl create secret generic nvt-github-app \
  --from-file=private-key.pem=./private-key.pem \
  -n nvt
```

Install the chart with values for the GitHub App, target repositories, and
AgentRun runtime settings:

```sh
helm install nvt-github-comments-producer ./charts/nvt-github-comments-producer \
  -n nvt \
  -f values.github-comments.yaml
```

## Example values

```yaml
commandPrefixes:
  - /nvtagent

allowedAuthors:
  - mirkoSekulic

repositories:
  - owner: mirkoSekulic
    name: nvt-agent

githubApp:
  appID: 12345
  installationID: 67890
  existingSecret: nvt-github-app
  privateKeyKey: private-key.pem

agentRun:
  namespace: nvt
  runtimeImage: nvt-agent-runtime:latest
  runtimeType: codex
  runtimeAutonomy: trusted-local
  workspaceMode: Ephemeral
  runtimeAuthSecret: codex-auth
  brokerGrants:
    - provider: github-main-app
      repositories:
        - mirkoSekulic/nvt-agent

agentConfig:
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
              - github.com/mirkoSekulic/nvt-agent
    - name: git-credentials
      source: builtin
      when: before-agent
      config:
        credentials:
          - match: https://github.com/mirkoSekulic/nvt-agent
            provider: github-main
            username: x-access-token
            identity:
              mode: provider
    - name: checkout-repos
      source: builtin
      when: before-agent
      restart: never
      config:
        repos:
          - url: https://github.com/mirkoSekulic/nvt-agent.git
            path: nvt-agent
```

`allowedAuthors` defaults to `["*"]`, which allows commands from any GitHub
login. For POC deployments, restrict it to the maintainer login, for example
`mirkoSekulic`.

## Persistence

SQLite cursor state is stored at `/var/lib/nvt-github-comments/state.db` by
default. `persistence.enabled` is `true` by default and creates a PVC unless
`persistence.existingClaim` is set.

Keep `replicaCount: 1` in SQLite/PVC mode. Multiple replicas can race on local
state and create redundant polling work.

For local development only, set:

```yaml
persistence:
  enabled: false
```

This uses `emptyDir`, so cursor state is lost when the pod is replaced.

## RBAC

By default the chart creates a ServiceAccount in the release namespace. The
Role and RoleBinding are created in the effective `agentRun.namespace`, which
defaults to the release namespace. This lets the producer run in one namespace
and create `AgentRun` resources in another. The Role allows only `get`, `list`,
and `create` on `agentruns.nvt.dev`.

To use an existing ServiceAccount:

```yaml
serviceAccount:
  create: false
  name: nvt-github-comments-producer
```

Set `rbac.create: false` only when equivalent permissions are provided
separately.
