# nvt-github-comments-producer chart

This chart deploys only the GitHub comments producer. It does not install the
nvt operator, broker, CRDs, runtime image resources, or any GitHub-specific
configuration into the core `charts/nvt` chart.

The producer polls configured GitHub repositories for:

```text
<configured-prefix> pr create
```

and submits work to the nvt operator `AgentSchedule` admission endpoint. The
operator creates `AgentRun` resources after applying schedule controls such as
`maxParallelism`, `suspend`, and duplicate active-work checks.

## Install

Create a Secret that contains the GitHub App private key. The chart references
an existing Secret and never renders private key material into Kubernetes
manifests:

```sh
make github-comments-producer-secret \
  GITHUB_APP_PRIVATE_KEY_FILE=/path/to/private-key.pem \
  NAMESPACE=nvt \
  CLUSTER=nvt-smoke
```

This producer Secret is consumed by `charts/nvt-github-comments-producer`. It
is intentionally separate from the core nvt broker env Secret, which is created
with `make broker-env-secret BROKER_ENV_FILE=.broker/env` and consumed by the
core `charts/nvt` broker deployment through `broker.envSecretName`. The two
Secrets may use different GitHub Apps later. Do not commit real private keys or
`.broker/env`.

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

operatorCallbackBaseURL: http://nvt-operator:8082

submission:
  mode: scheduleAdmission
  admissionMode: legacy
  admissionBaseURL: http://nvt-operator:8082
  scheduleName: default

idempotency:
  scope: issue

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

`allowedAuthors` defaults to `["*"]`, which allows commands from any GitHub
login. For POC deployments, restrict it to the maintainer login, for example
`mirkoSekulic`.

`idempotency.scope` defaults to `issue`, which allows one `pr create` AgentRun
per repository issue. For local testing, set it to `comment` so each matching
command comment ID gets its own idempotency key and AgentRun name.

The static broker config owns GitHub App providers, capabilities, and secrets.
Producer-created AgentRuns request only broker grants through
`agentRun.brokerGrants`, while runtime plugins use broker-backed credentials.
Do not put GitHub provider secrets in chart values or committed examples.

The example above is the backward-compatible legacy mode: the producer sends a
complete AgentRun, so `agentRun` and `agentConfig` remain producer-owned. For an
operator-owned profiled schedule, use:

```yaml
# Producer Helm values (release name nvt-github-comments-producer, namespace nvt)
submission:
  mode: scheduleAdmission
  admissionMode: profiled
  admissionBaseURL: http://nvt-operator:8082
  admissionTokenFile: /var/run/secrets/nvt-operator/token
  tokenExpirationSeconds: 3600
  scheduleNamespace: nvt
  scheduleName: default
```

and create the schedule policy separately:

```yaml
apiVersion: nvt.dev/v1alpha1
kind: AgentSchedule
metadata:
  name: default
  namespace: nvt
spec:
  allowedProducers:
    - system:serviceaccount:nvt:nvt-github-comments-producer
  template:
    image: nvt-agent-runtime:latest
    workspace: {mode: Ephemeral}
    agent:
      config:
        plugins: []
  profiles:
    - name: default
      runtime: {type: codex, autonomy: trusted-local}
      agentRuntimeConfig:
        command: codex
        proxy: {provider: codex-main}
      egress: mediated
      broker:
        grants:
          - provider: codex-main
            repositories: [example/*]
            materialization: header-inject
            egressHosts: [chatgpt.com]
  profileSelection:
    defaultProfile: default
    onNoMatch: useDefault
```

The producer sends the immutable numeric GitHub user ID as the authorization
subject and never sends a profile/provider choice. The default profile is
enough for normal deployments. Exact `issuer` + `subject` rules are optional
for multi-profile routing; GitHub login/display name never authorizes a profile.
The chart projects only an audience-`nvt-operator` token in profiled mode,
disables the default automount for schedule admission, and rereads the token on
each request. Legacy schedules must keep `admissionMode: legacy`; there is no
automatic fallback between modes.

The producer injects an `event-webhook` after-agent plugin for each generated
AgentRun unless `agentConfig.plugins` already contains `event-webhook`. The
callback URL is built from `operatorCallbackBaseURL` and the generated
AgentRun namespace/name. If you provide your own `event-webhook` plugin, it is
responsible for forwarding `plugin.github.pr.` lifecycle events to the operator
callback endpoint.

Generated AgentRuns complete on both `plugin.github.pr.merged` and
`plugin.github.pr.closed`. A closed/unmerged PR is a valid terminal result for
this workflow, not an AgentRun failure.

`agentRun.ttl.completedTTLSeconds` and `agentRun.ttl.failedTTLSeconds` control
owned AgentRun Pod cleanup after terminal phases. Defaults keep successful Pods
for 5 minutes and failed Pods for 1 hour. `agentRun.ttl.runRetentionSeconds`
defaults to 30 days for the terminal AgentRun CR. Set a TTL field to `null` to
leave that cleanup behavior unset, or `0` where the AgentRun API defines zero
as a meaningful value.

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
default `submission.mode` is `scheduleAdmission`, so the producer submits work
to the operator HTTP Service and the chart does not grant AgentRun create/list
RBAC. This is the production mode because `AgentSchedule` remains authoritative
for concurrency, suspension, and duplicate work policy.

`submission.mode: direct` is available only for local/dev compatibility and
bypasses `AgentSchedule`. In direct mode the chart creates a Role and
RoleBinding in the effective `agentRun.namespace`, which defaults to the
release namespace. The Role allows only `get`, `list`, and `create` on
`agentruns.nvt.dev`.

To use an existing ServiceAccount:

```yaml
serviceAccount:
  create: false
  name: nvt-github-comments-producer
```

Set `rbac.create: false` only when equivalent permissions are provided
separately for direct mode.
