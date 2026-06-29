# GitHub comments producer

This producer polls GitHub issue comments with GitHub App installation authentication and creates `AgentRun` resources for the first supported command:

```text
<configured-prefix> pr create
```

The default prefix is `/nvtagent`, but it is configuration only. GitHub-specific trigger logic lives in this producer, not in the operator or runtime image.

## Build

Build from the repository root so the producer can use the local operator API module:

```sh
docker build -f producers/github-comments/Dockerfile -t nvt-github-comments-producer:latest .
```

## Configuration

Example config:

```yaml
commandPrefixes:
  - /nvtagent
allowedAuthors:
  - "*"
pollInterval: 30s
operatorCallbackBaseURL: http://nvt-operator:8082
idempotency:
  scope: issue
state:
  sqlitePath: /var/lib/nvt-github-comments/state.db
repositories:
  - owner: mirkoSekulic
    name: nvt-agent

githubApp:
  appID: 12345
  installationID: 67890
  privateKeyPath: /var/run/secrets/github-app/private-key.pem
  # Or use one of:
  # privateKey: |
  #   -----BEGIN RSA PRIVATE KEY-----
  # privateKeyBase64: LS0t...
  # privateKeyEnv: GITHUB_APP_PRIVATE_KEY
  # privateKeyBase64Env: GITHUB_APP_PRIVATE_KEY_B64

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
  ttl:
    activeDeadlineSeconds: 14400
    completedTTLSeconds: 300
    failedTTLSeconds: 3600
    runRetentionSeconds: 2592000

agentConfig:
  runtime:
    command: codex
    args:
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

The producer creates AgentRuns with annotation:

```text
nvt.dev/idempotency-key = github:<owner>/<repo>:issue:<number>:intent:create_pr
```

Any existing AgentRun in the target namespace with the same annotation blocks a new run, regardless of status phase. A Kubernetes `AlreadyExists` response is also treated as already accepted.

`idempotency.scope` defaults to `issue`, which preserves the production-safe
behavior of allowing one `pr create` AgentRun per repository issue. For local
testing, set `idempotency.scope: comment` to include the command comment ID in
the idempotency key and AgentRun name so multiple command comments on the same
issue can create separate runs.

Producer-created AgentRuns complete on either `plugin.github.pr.merged` or
`plugin.github.pr.closed`. Closed/unmerged PRs are treated as valid terminal
outcomes for this workflow, not AgentRun failures.

`agentRun.ttl.completedTTLSeconds` and `agentRun.ttl.failedTTLSeconds` are
forwarded to `AgentRun.spec.ttl` so terminal Pods can be cleaned up by the
operator. Chart defaults keep successful Pods for 5 minutes, failed Pods for 1
hour, and terminal AgentRun CRs for 30 days.

The producer injects an `event-webhook` after-agent plugin unless
`agentConfig.plugins` already contains a plugin named `event-webhook`. The
injected webhook forwards `plugin.github.pr.` events to:

```text
<operatorCallbackBaseURL>/v1/agentruns/<namespace>/<agentrun-name>/events
```

If you provide your own `event-webhook` plugin, the producer does not add a
duplicate; that user-provided config is responsible for forwarding PR lifecycle
events to the operator callback endpoint.

Command comments are accepted only from `allowedAuthors`. The default is `["*"]`, which allows any GitHub login. POC deployments can restrict this to maintainer logins, for example:

```yaml
allowedAuthors:
  - mirkoSekulic
```

Polling state is stored in SQLite at `state.sqlitePath`. The producer stores one cursor per configured repository and resumes from that cursor after a pod restart. If no cursor exists, the first poll starts at producer startup time unless `initialSince` is configured for explicit backfill.

The agent prompt asks Codex to register created PRs with:

```sh
github-watch register --repo OWNER/REPO --number PR_NUMBER --provider github-main
```

The `github-watcher` plugin must be enabled in `agentConfig` so that command is
available and PR merge/close events are published.

## Local Run

Use a kubeconfig that can create and list `AgentRun` resources:

```sh
go run ./cmd/github-comments --config ./config.yaml --kubeconfig ~/.kube/config
```

If `--kubeconfig` is omitted, the producer tries in-cluster config first and then the default local kubeconfig.

## Kubernetes

Mount the config as a ConfigMap and the GitHub App private key as a Secret, then run the producer image outside the nvt-agent runtime image:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nvt-github-comments-producer
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nvt-github-comments-producer
  template:
    metadata:
      labels:
        app: nvt-github-comments-producer
    spec:
      serviceAccountName: nvt-github-comments-producer
      containers:
        - name: producer
          image: nvt-github-comments-producer:latest
          args:
            - --config=/etc/nvt-github-comments/config.yaml
          volumeMounts:
            - name: config
              mountPath: /etc/nvt-github-comments
              readOnly: true
            - name: github-app
              mountPath: /var/run/secrets/github-app
              readOnly: true
            - name: state
              mountPath: /var/lib/nvt-github-comments
      volumes:
        - name: config
          configMap:
            name: nvt-github-comments-producer
        - name: github-app
          secret:
            secretName: nvt-github-app
        - name: state
          persistentVolumeClaim:
            claimName: nvt-github-comments-producer-state
```

The ServiceAccount needs RBAC to list and create `agentruns.nvt.dev` in the configured target namespace. Runtime auth secrets and broker/provider grants should be configured to match the runtime image and credential broker installed in that namespace.
