# Local kind GitHub Producer

This runbook starts the operator, broker, GitHub comments producer, and real
AgentRun Pods in a local kind cluster.

The producer watches for issue comments whose first non-empty line is:

```text
/nvtagent pr create
```

Additional lines become task instructions.

## Prerequisites

- Docker, kind, kubectl, Helm, and Make
- A GitHub App installed on the target repository
- A broker env file containing provider credentials
- Runtime auth when using the direct Codex compatibility path

Keep private keys, auth files, and local values outside Git. Common
`values.*.local.yaml` names are ignored.

## Values

Create `values.nvt-local.yaml` for the core chart:

```yaml
broker:
  envSecretName: nvt-broker-env
  config:
    providers:
      - name: github-main-app
        plugin: github-app
        config:
          app-id-env: GITHUB_APP_ID
          installation-id-env: GITHUB_APP_INSTALLATION_ID
          private-key-base64-env: GITHUB_APP_PRIVATE_KEY_BASE64
          api-url: https://api.github.com
        allow:
          repositories: [OWNER/REPO]
          permissions:
            contents: write
            pull_requests: write
            issues: write
          methods: [GET, POST, PATCH]
    agents: []

agentSchedule:
  enabled: true
  name: default
  maxParallelism: 1
```

Create `values.github-comments.yaml` for the producer block in the main chart:

```yaml
producer:
  allowedAuthors: [YOUR_GITHUB_LOGIN]
  repositories:
    - owner: OWNER
      name: REPO
  githubApp:
    appID: 123456
    installationID: 12345678
    existingSecret: nvt-github-app
  submission:
    mode: scheduleAdmission
    admissionBaseURL: http://nvt-operator:8082
    scheduleName: default
  idempotency:
    scope: comment
  agentRun:
    namespace: nvt
    runtimeImage: nvt-agent-runtime:latest
    runtimeType: codex
    runtimeAutonomy: trusted-local
    runtimeAuthSecret: codex-auth
    brokerGrants:
      - provider: github-main-app
        repositories: [OWNER/REPO]
```

Add runtime plugins under `producer.agentConfig` as needed. The complete
supported values live in [`charts/nvt/values.yaml`](../charts/nvt/values.yaml).

Use `idempotency.scope: comment` for repeated local tests. Production-like
issue scope permits one active PR-creation intent per issue.

## Create The Cluster And Secrets

```sh
make operator-kind-cluster CREATE_CLUSTER=1 CLUSTER=nvt-smoke
kubectl --context kind-nvt-smoke create namespace nvt \
  --dry-run=client -o yaml | kubectl --context kind-nvt-smoke apply -f -

make operator-codex-auth-secret \
  CODEX_AUTH_SOURCE="$HOME/.codex" \
  CODEX_AUTH_SECRET=codex-auth \
  NAMESPACE=nvt CLUSTER=nvt-smoke

make broker-env-secret \
  BROKER_ENV_FILE=.broker/env \
  BROKER_ENV_SECRET=nvt-broker-env \
  NAMESPACE=nvt CLUSTER=nvt-smoke

make github-comments-producer-secret \
  GITHUB_APP_PRIVATE_KEY_FILE=/path/to/private-key.pem \
  PRODUCER_GITHUB_APP_SECRET=nvt-github-app \
  NAMESPACE=nvt CLUSTER=nvt-smoke
```

The producer App Secret and broker provider Secret are intentionally separate.
They may represent different GitHub Apps.

## Install

```sh
make operator-kind-setup \
  CREATE_CLUSTER=0 \
  CLUSTER=nvt-smoke \
  NAMESPACE=nvt \
  OPERATOR_KIND_HELM_ARGS='-f values.nvt-local.yaml'

make producer-kind-setup \
  CLUSTER=nvt-smoke \
  NAMESPACE=nvt \
  PRODUCER_VALUES=values.github-comments.yaml
```

## Trigger And Observe

Post an issue comment:

```text
/nvtagent pr create

Implement the issue and open a pull request.
```

Observe the producer and runs:

```sh
kubectl --context kind-nvt-smoke logs \
  deployment/nvt-github-comments-producer -n nvt -f

kubectl --context kind-nvt-smoke get agentruns,pods -n nvt -w
```

Attach to the current tmux-backed session when diagnosing a running Pod:

```sh
kubectl --context kind-nvt-smoke exec -n nvt -it POD_NAME -c agent \
  -- tmux attach -t agent
```

Send a queued prompt without attaching:

```sh
kubectl --context kind-nvt-smoke exec -i -n nvt POD_NAME -c agent \
  -- agentdctl prompt <<'EOF'
Continue the issue task and create the requested pull request.
EOF
```

Use `gh-auth`, not an unconfigured plain `gh`, for broker-backed GitHub API
operations inside the agent.

When the watcher reports a merged or closed PR, the AgentRun reaches a terminal
phase. Pod and CR cleanup follow the configured TTLs.

## Cleanup

```sh
kind delete cluster --name nvt-smoke
```
