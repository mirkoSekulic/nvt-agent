# Local kind GitHub producer POC

This guide describes the local setup used to run the GitHub comments producer,
the operator, the broker, and real Codex AgentRun Pods in a kind cluster.

The goal is to let another agent or maintainer reproduce the flow without
knowing the local history of the test.

## What this runs

- `charts/nvt`: operator, broker, CRDs, and the default AgentSchedule.
- `charts/nvt-github-comments-producer`: a separate producer Deployment that
  polls GitHub issue comments.
- Runtime AgentRun Pods using `nvt-agent-runtime:latest`.
- Codex auth mounted from a Kubernetes Secret.
- GitHub App credentials split between the producer and broker.

The test trigger is a GitHub issue comment whose first non-empty line is:

```text
/nvtagent pr create
```

Additional prompt text goes below that line.

## Prerequisites

Install and authenticate these tools on the host:

- Docker
- kind
- kubectl
- helm
- gh

The GitHub App installation must have access to the target repository. For this
POC the app needs enough permissions for repository checkout, branch push, pull
request creation, issue comments, and pull request status polling.

Do not commit local values files, private keys, `.broker/env`, or Codex auth
files. The repo ignores the common local values filenames:

- `values.nvt-local.yaml`
- `values.github-comments.yaml`
- `values.*.local.yaml`

## Local files

Create `values.nvt-local.yaml` for the operator and broker:

```yaml
broker:
  enabled: true
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
          repositories:
            - OWNER/REPO
          permissions:
            contents: write
            pull_requests: write
            issues: write
            checks: read
          methods:
            - GET
            - POST
    agents: []

agentSchedule:
  enabled: true
  name: default
  maxParallelism: 1
  suspend: false
```

Create `values.github-comments.yaml` for the producer:

```yaml
commandPrefixes:
  - /nvtagent

allowedAuthors:
  - YOUR_GITHUB_LOGIN

pollInterval: 30s
operatorCallbackBaseURL: http://nvt-operator:8082

submission:
  mode: scheduleAdmission
  admissionBaseURL: http://nvt-operator:8082
  scheduleName: default

idempotency:
  scope: comment

repositories:
  - owner: OWNER
    name: REPO

githubApp:
  appID: 123456
  installationID: 12345678
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
        - OWNER/REPO
  ttl:
    activeDeadlineSeconds: 14400
    completedTTLSeconds: 30
    failedTTLSeconds: 3600
    runRetentionSeconds: 2592000

agentConfig:
  tools:
    packages:
      - jq
      - make
      - unzip
    mise:
      - go@1.24
  runtime:
    command: codex
    args:
      - --cd
      - /workspace/REPO
      - --no-alt-screen
      - --dangerously-bypass-approvals-and-sandbox
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
              - github.com/OWNER/REPO
    - name: git-credentials
      source: builtin
      when: before-agent
      config:
        credentials:
          - match: https://github.com/OWNER/REPO
            provider: github-main
            username: x-access-token
            identity:
              mode: provider
    - name: checkout-repos
      source: builtin
      when: before-agent
      restart: never
      retries: 12
      restart-delay-seconds: 10
      config:
        repos:
          - url: https://github.com/OWNER/REPO.git
            path: REPO
    - name: github-watcher
      source: builtin
      when: after-agent
      restart: always
      config:
        default-provider: github-main
        broker:
          enabled: true
          provider: github-main-app
```

`checkout-repos.retries` is important in kind. The operator writes each
AgentRun's broker token into the shared `nvt-broker-agents` ConfigMap, and the
broker live-reloads that projected file. Kubernetes projected ConfigMap updates
are not instant, so the first Git credential request can race the projection.
Retries let the checkout wait until the broker sees the generated agent token.

The broker does not need to be restarted for each new AgentRun when retries are
configured.

## Create secrets

Create the kind cluster and namespace first:

```sh
make operator-kind-cluster CREATE_CLUSTER=1 CLUSTER=nvt-smoke
kubectl --context kind-nvt-smoke create namespace nvt --dry-run=client -o yaml \
  | kubectl --context kind-nvt-smoke apply -f -
```

Create the Codex auth Secret from the host Codex config:

```sh
make operator-codex-auth-secret \
  CODEX_AUTH_SOURCE="$HOME/.codex" \
  CODEX_AUTH_SECRET=codex-auth \
  NAMESPACE=nvt \
  CLUSTER=nvt-smoke
```

Create the broker env Secret from a local env file:

```sh
make broker-env-secret \
  BROKER_ENV_FILE=.broker/env \
  BROKER_ENV_SECRET=nvt-broker-env \
  NAMESPACE=nvt \
  CLUSTER=nvt-smoke
```

Create the producer GitHub App private key Secret:

```sh
make github-comments-producer-secret \
  GITHUB_APP_PRIVATE_KEY_FILE=/path/to/github-app.private-key.pem \
  PRODUCER_GITHUB_APP_SECRET=nvt-github-app \
  PRODUCER_GITHUB_APP_KEY=private-key.pem \
  NAMESPACE=nvt \
  CLUSTER=nvt-smoke
```

## Install the stack

Install the operator and broker:

```sh
make operator-kind-setup \
  CREATE_CLUSTER=0 \
  CLUSTER=nvt-smoke \
  NAMESPACE=nvt \
  OPERATOR_KIND_HELM_ARGS='-f values.nvt-local.yaml'
```

Install the producer:

```sh
make producer-kind-setup \
  CLUSTER=nvt-smoke \
  NAMESPACE=nvt \
  PRODUCER_VALUES=values.github-comments.yaml
```

If only `values.github-comments.yaml` changes later, upgrade the producer and
restart it so the process reloads the new ConfigMap:

```sh
make producer-kind-install \
  CLUSTER=nvt-smoke \
  NAMESPACE=nvt \
  PRODUCER_VALUES=values.github-comments.yaml

kubectl --context kind-nvt-smoke rollout restart deployment/nvt-github-comments-producer -n nvt
kubectl --context kind-nvt-smoke rollout status deployment/nvt-github-comments-producer -n nvt
```

## Trigger a run

Add this comment to an existing issue in the configured repository:

```text
/nvtagent pr create

Create a small PR that changes one line in README.md. Keep the change minimal.
```

With `idempotency.scope: comment`, every matching command comment gets its own
idempotency key and AgentRun name. This is useful for local testing. For a more
production-like mode, use `idempotency.scope: issue` to allow one active PR
creation run per issue intent.

Watch the producer:

```sh
kubectl --context kind-nvt-smoke logs deployment/nvt-github-comments-producer -n nvt -f
```

Watch AgentRuns:

```sh
kubectl --context kind-nvt-smoke get agentruns,pods -n nvt -w
```

Inspect a running agent:

```sh
kubectl --context kind-nvt-smoke exec -n nvt -it POD_NAME -c agent -- tmux attach -t agent
```

## Known local POC behavior

Codex may stop at the workspace trust prompt. If that happens, attach to the
agent tmux session and choose the trust option. After clearing the prompt, a
queued prompt can be resent with:

```sh
kubectl --context kind-nvt-smoke exec -i -n nvt POD_NAME -c agent -- agentdctl prompt <<'EOF'
Continue the GitHub issue task and create the requested PR.
EOF
```

The plain `gh` CLI is not logged in inside the agent container. Use the exported
broker-backed wrapper for GitHub CLI operations:

```sh
gh-auth pr create ...
gh-auth issue comment ...
```

The GitHub App must include `issues: write` if agents should comment on issues.
With only `issues: read`, PR creation can work while issue comments fail with a
GitHub integration permission error.

PR lifecycle completion depends on `github-watch register`. Once the watched PR
is closed or merged, the watcher emits `plugin.github.pr.closed` or
`plugin.github.pr.merged`; the operator marks the AgentRun `Completed`.

With `completedTTLSeconds: 30`, the completed AgentRun Pod should be deleted
about 30 seconds after the AgentRun reaches `Completed`. The AgentRun CR itself
remains until `runRetentionSeconds`.

## Cleanup

Delete the local kind cluster:

```sh
kind delete cluster --name nvt-smoke
```
