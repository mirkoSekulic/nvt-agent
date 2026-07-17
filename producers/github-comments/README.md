# GitHub comments producer

This producer polls GitHub issue comments with GitHub App installation authentication and submits `AgentRun` work to the nvt operator schedule admission endpoint for the first supported command:

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
submission:
  mode: scheduleAdmission
  admissionMode: legacy
  admissionBaseURL: http://nvt-operator:8082
  scheduleName: default
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
  # Persistent mode additionally requires workspaceSize; the class is optional.
  # workspaceMode: Persistent
  # workspaceSize: 20Gi
  # workspaceStorageClassName: managed-csi
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
      egress:
        provider: github-main-app
      config:
        poll-seconds: 60
```

The producer uses this idempotency key as the schedule admission `work.id`:

```text
nvt.dev/idempotency-key = github:<owner>/<repo>:issue:<number>:intent:create_pr
```

In `scheduleAdmission` mode, the operator is the final authority for duplicate
work, suspension, and `maxParallelism`. A duplicate work response is treated as
an accepted no-op. `max-parallelism-reached` and `schedule-suspended` responses
are retried on a later poll by leaving the repository cursor unchanged.

`submission.admissionMode` is an explicit migration boundary:

- `legacy` is the backward-compatible default. The producer sends the complete
  `agentRun` configured by `agentRun` and `agentConfig`, and the target schedule
  must be a legacy schedule.
- `profiled` sends only work metadata, the generated prompt, and GitHub
  principal facts. It never sends a profile, runtime, image, proxy/provider,
  broker grant, egress policy, tool, or plugin setting. The operator-owned
  `AgentSchedule` resolves all of those fields.

Profiled mode identifies the command author with issuer `https://github.com`,
the immutable numeric GitHub user ID as the decimal subject, and the login as
display-only metadata. A missing or invalid numeric ID fails before admission.
`allowedAuthors` remains an optional login convenience filter; it is not profile
authorization. The operator authorizes exact issuer/subject rules.

```yaml
submission:
  mode: scheduleAdmission
  admissionMode: profiled
  admissionBaseURL: http://nvt-operator:8082
  admissionTokenFile: /var/run/secrets/nvt-operator/token
  scheduleNamespace: nvt
  scheduleName: default
```

The projected ServiceAccount token must have audience `nvt-operator`. It is
read for every request so Kubernetes rotation works without a restart.
Authentication, principal, or admission failures never fall back to legacy.

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

In legacy mode, the producer injects an `event-webhook` after-agent plugin unless
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
github-watch register --repo OWNER/REPO --number PR_NUMBER
```

The `github-watcher` plugin must be enabled in `agentConfig` so that command is
available and PR merge/close events are published. The mediated configuration
above selects the provider once through the plugin's outer `egress.provider`,
so registrations must not add `--provider`. That flag remains available for
direct/local watcher configurations that intentionally select an in-agent
credential provider.

## Local Run

By default the producer submits to the operator admission API:

```sh
go run ./cmd/github-comments --config ./config.yaml
```

For local/dev compatibility, `submission.mode: direct` can create `AgentRun`
resources through the Kubernetes API directly. Direct mode bypasses
`AgentSchedule`; use it only when that is intentional. If direct mode is used
outside the cluster, pass a kubeconfig:

```sh
go run ./cmd/github-comments --config ./config.yaml --kubeconfig ~/.kube/config
```

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

In `scheduleAdmission` mode, the ServiceAccount does not need AgentRun
create/list RBAC for submission. The operator creates the AgentRun. Direct mode
requires RBAC to list and create `agentruns.nvt.dev` in the configured target
namespace. Runtime auth secrets and broker/provider grants should be configured
to match the runtime image and credential broker installed in that namespace.
The Helm chart disables the default ServiceAccount token in schedule admission
mode and mounts only the audience-scoped projection when `admissionMode` is
`profiled`.
