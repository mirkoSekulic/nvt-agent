# GitHub comments producer

This producer polls GitHub issue comments with GitHub App installation authentication and submits `AgentRun` work to the nvt operator schedule admission endpoint for supported commands:

```text
<configured-prefix> <pr create|review|pr continue|run> [-- inline prompt]
[multiline prompt]
<configured-prefix> --help
```

The default prefix is `/nvtagent`, but it is configuration only. GitHub-specific trigger logic lives in this producer, not in the operator or runtime image.

`/nvtagent --help` posts a formal command reference to the originating issue or
pull request. Its usage section is:

```text
/nvtagent --help
/nvtagent pr create [-- <instructions>]
/nvtagent review [-- <instructions>]
/nvtagent pr continue [-- <optional instructions>]
/nvtagent run -- <instructions>
```

Help delivery is restart-safe and idempotent. The producer persists a pending
response with an unguessable stable marker before posting, reconciles that
marker from later thread comments after an ambiguous POST or restart, records
delivery, and removes delivered state only after the repository cursor advances.
The marker is an invisible HTML comment and does not change the displayed help.

`pr create` keeps multiline instructions and also supports inline syntax via
`/nvtagent pr create -- <instructions>`.

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
schedulingReactions:
  enabled: true
  accepted: "+1"
  rejected: "-1"
submission:
  mode: scheduleAdmission
  backend: kubernetes
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
        # Keep aligned with this producer's commandPrefixes so control-plane
        # comments are not also delivered to an existing watched session.
        ignored-comment-prefixes:
          - /nvtagent
```

The producer uses this idempotency key as the schedule admission `work.id`:

```text
nvt.dev/idempotency-key = github:<owner>/<repo>:issue:<number>:intent:create_pr
```

In `scheduleAdmission` mode, the operator is the final authority for duplicate
work, suspension, and `maxParallelism`. A duplicate work response is treated as
an accepted no-op. `max-parallelism-reached` and `schedule-suspended` responses
are retried on a later poll by leaving the repository cursor unchanged.

By default, the producer adds an accepted reaction (`+1`) to the triggering
issue comment after the operator confirms `scheduled: true`, or reports the
idempotent `duplicate-work` result. It adds the configured rejected reaction
(`-1` by default) only for a bounded, recognized non-retryable operator denial
that proves no AgentRun was created. Deferred capacity/suspension responses,
transport failures, timeouts, malformed responses, 5xx responses, invalid
commands, and unauthorized authors receive no reaction. Set
`schedulingReactions.enabled: false` to opt out. `accepted` and `rejected` may
be any GitHub-supported reaction: `+1`, `-1`, `laugh`, `confused`, `heart`,
`hooray`, `rocket`, or `eyes`.

Reaction posting uses GitHub's create-reaction-on-issue-comment endpoint and
requires the GitHub App to have **Issues: write** permission. HTTP 200 (the
reaction already exists) and 201 (created) are both successes. Reaction calls
are bounded and strictly best-effort: permission, API, timeout, network, or
response errors produce only a sanitized warning after scheduling and cursor
behavior have already been decided. Direct submission does not produce an
operator scheduling outcome and therefore does not add these reactions.

`submission.admissionMode` is an explicit migration boundary:

- `legacy` is the backward-compatible default. The producer sends the complete
  `agentRun` configured by `agentRun` and `agentConfig`, and the target schedule
  must be a legacy schedule.
- `profiled` sends only work metadata, the generated prompt, and GitHub
  principal facts, plus an optional static `submission.workflow` name. It never
  sends instruction text, an execution profile, runtime, image, proxy/provider,
  broker grant, egress policy, tool, or plugin setting. The operator-owned
  `AgentSchedule` resolves all of those fields.

`submission.backend` defaults to `kubernetes`, preserving the exact existing
URL and payload behavior. Setting it to `local` is valid only with profiled
schedule admission and changes only the trusted admission URL to
`/v1/schedules/<schedule>/admissions`. The local controller authenticates the
same private token file and maps the producer/principal to exact
administrator-owned profile/workflow policy. The producer still cannot send a
profile, provider, broker grant, credential generation, runtime, capability,
retention, or egress choice. Scheduling reactions and cursor behavior continue
to use only the authoritative admission result.

Profiled mode identifies the command author with issuer `https://github.com`,
the immutable numeric GitHub user ID as the decimal subject, and the login as
display-only metadata. A missing or invalid numeric ID fails before admission.
`allowedAuthors` remains an optional login convenience filter; it is not profile
authorization. The operator authorizes exact issuer/subject rules.

```yaml
submission:
  mode: scheduleAdmission
  backend: kubernetes
  admissionMode: profiled
  admissionBaseURL: http://nvt-operator:8082
  admissionTokenFile: /var/run/secrets/nvt-operator/token
  scheduleNamespace: nvt
  scheduleName: default
  workflow: review-pr # optional; must be allowed for this ServiceAccount
```

The equivalent local-controller selection keeps the same payload and outcome
contract:

```yaml
submission:
  mode: scheduleAdmission
  backend: local
  admissionMode: profiled
  admissionBaseURL: http://local-controller:7480
  admissionTokenFile: /run/secrets/nvt-local-controller/producer-token
  scheduleNamespace: unused # retained for config compatibility; not sent locally
  scheduleName: github
  workflow: review-pr
```

When `workflow` is empty or omitted, the producer preserves the previous
payload exactly and the schedule may apply that producer policy's default. The
workflow name is a non-secret routing choice only; all instruction text and
workflow authorization remain administrator-owned in AgentSchedule.

For Kubernetes, the projected ServiceAccount token must have audience
`nvt-operator`. It is read for every request so Kubernetes rotation works
without a producer restart. The local backend instead uses the private opaque
token file bound in the controller's scheduling policy; coordinate a
controller restart when rotating that startup-loaded value.
Authentication, principal, or admission failures never fall back to legacy.

`idempotency.scope` defaults to `issue`, which preserves the production-safe
behavior of allowing one `pr create` AgentRun per repository issue. For local
testing, set `idempotency.scope: comment` to include the command comment ID in
the idempotency key and AgentRun name so multiple command comments on the same
issue can create separate runs.

Producer-created AgentRuns complete on either `plugin.github.pr.merged` or
`plugin.github.pr.closed`. Closed/unmerged PRs are treated as valid terminal
outcomes for this workflow, not AgentRun failures.

`pr continue` is the long-lived PR-maintenance form. Its workflow stays alive on
the PR thread and is expected to continue responding to new activity.
Because it does not emit bounded work-completion events, it should use only
`plugin.github.pr.merged` / `plugin.github.pr.closed` terminal completion and no
work-control work-complete/fail lifecycle hooks.
Each command comment has a distinct admission work ID. The producer also sends
a stable, non-secret work group for that repository pull request. Both the
operator and local controller reject a second active member of the group as an
accepted duplicate before applying schedule capacity. Once the prior member is
terminal, a later command comment can start a replacement maintenance session.

Workflow selection only chooses administrator-authored workflow instructions;
it does not enable plugins or lifecycle events. Cooperative `review` and `run`
deployments must explicitly enable the builtin `work-control` plugin and add
`plugin.work.completed` / `plugin.work.failed` to the shared `AgentSchedule`
template. For PR-backed work, configure completion as the union of the work
event and `plugin.github.pr.merged` / `plugin.github.pr.closed`. An omitted
signal remains bounded by the configured active deadline.

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

## Epic commands (state contract only)

Epic support is opt-in and currently implements only commands, policy, and
SQLite state. It does **not** load graphs, admit child AgentRuns, discover PRs,
or advance after merges. An enabled epic remains gated at `awaiting-graph`.
The scheduling and PR stages must explicitly extend this contract before any
child work can run.

Configure profiled schedule admission as above, then add administrator-owned
settings:

```yaml
epics:
  enabled: true
  workflow: implement-pr
  maxParallel: 1
  allowedUserIDs: [12345678] # immutable numeric GitHub user IDs
```

Omitting `epics` or setting only `enabled: false` leaves epic commands inert.
Enabled epics require a workflow name, an explicit nonempty user-ID allowlist,
profiled schedule admission, and SQLite storage. `maxParallel` defaults to 1;
other values are unsupported in this initial contract. Unknown epic fields,
invalid IDs, duplicates, and settings supplied with `enabled: false` are errors.
No profile or credential selector is accepted in the epic configuration. The
configured workflow names an administrator-owned admission workflow; it does
not grant profile access or bypass the admission authority.

Commands use the configured prefix and are valid only on ordinary issues:

```text
/nvtagent epic start
/nvtagent epic status
/nvtagent epic pause
/nvtagent epic resume
/nvtagent epic cancel
/nvtagent epic retry
```

Commands accept no arguments, inline instructions, multiline instructions, or
workflow/profile overrides. Issue bodies and thread comments cannot select
policy or supply a graph. The existing `allowedAuthors` filter still applies,
and the numeric user ID must be in `epics.allowedUserIDs`. Only the original
initiator can subsequently control or inspect that epic. Removing that ID
revokes access, including replayed commands; a login rename cannot transfer
ownership. Workflow, initiating principal, and parallelism are frozen at start.

| Command | State contract |
| --- | --- |
| `start` | Creates `pending`, generation 1; repeated starts preserve the existing nonterminal epic. |
| `status` | Returns the durable snapshot for this command in one restart-safe reply. |
| `pause` | Moves `pending` to `paused`; already paused is a no-op. |
| `resume` | Moves `paused` to `pending` without changing generation. |
| `cancel` | Moves to terminal `canceled`; repeated cancellation is a no-op. |
| `retry` | Moves `paused` to `pending` with a new generation, reserving distinct future child identities. |

Other transitions are rejected. A canceled epic cannot restart. State-changing
commands record their result in producer logs; `status` provides the current
snapshot on request. Edited parent/child status projections are deferred to the
scheduling stage. A failed status reply retries independently of the already
committed command and does not authorize work or change its outcome.

The producer atomically commits each state change and its command receipt before
advancing the existing repository cursor. Receipts include negative outcomes
and are retained: replaying or editing a processed comment cannot create a new
transition. A new command requires a new comment. Restart loads validated,
versioned epic records directly from SQLite, without reading source comments.
Persist the database on a durable volume; do not delete receipts to retry work.
Unknown lifecycle/reconciliation values, extra fields (including unsupported
or malformed graph data), and contradictory persisted identities fail closed.
This stage accepts no graph data; loading and validating native GitHub graphs
belongs to the next stage.

Future child-attempt keys have the deterministic form
`github:<owner>/<repo>:epic:<parent>:generation:<generation>:child:<child>:attempt:<attempt>`.
Repository names are normalized to lowercase; all numeric components must be
positive, and the child must differ from the parent. The admission key appends
`:intent:create_pr`. These keys do not depend on a command comment, poll cursor,
mutable issue text, workflow change, or process lifetime. Defining the keys does
not enable admission in this stage.

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

Commands use the first non-empty line of a comment. Prompt text is preferably
placed on following lines; a same-line prompt must follow a standalone `--`:

```text
/nvtagent pr create
Implement the issue and open a PR.

/nvtagent review -- focus on authorization boundaries

/nvtagent run
Investigate the failing deployment and report the result here.

/nvtagent pr continue
Address actionable PR review comments and keep working until merge or close.
```

`pr create` is valid only on ordinary issues, `review` only on pull requests,
`pr continue` is valid only on pull requests, and `run` on either. `run` and
`pr continue` accept multiline instructions; inline instructions must follow `--`.
Bare trailing text, unknown options, and malformed separators are rejected.
Command prefixes remain configuration-driven.

Profiled admission routes commands only through administrator-authored workflow
names:

```yaml
submission:
  commandWorkflows:
    pr-create: implement-pr
    review: review-pr
    run: generic-run
    pr-continue: continue-pr
```

Existing `submission.workflow` remains the fallback for `pr create` only.
`review`, `run`, and `pr continue` fail closed when their exact mapping is absent.

A complete profiled configuration routes commands and independently installs
the provider-neutral completion tool and lifecycle contract:

```yaml
agentSchedule:
  template:
    agent:
      config:
        plugins:
          - name: work-control
            source: builtin
    lifecycle:
      completeOn:
        - plugin.work.completed
        - plugin.github.pr.merged
        - plugin.github.pr.closed
      failOn:
        - plugin.work.failed
  workflowProfiles:
    - name: implement-pr
      workspaceInstructions: Implement the issue and open a pull request.
    - name: review-pr
      workspaceInstructions: Review the pull request and report findings.
    - name: generic-run
      workspaceInstructions: Perform the requested task and report the result.
    - name: continue-pr
      workspaceInstructions: Inspect PR maintenance state and address actionable items.
      lifecycle:
        completeOn:
          - plugin.github.pr.merged
          - plugin.github.pr.closed
        failOn: []
  producerPolicies:
    - identity: system:serviceaccount:nvt:nvt-github-comments-producer
      workflows: [implement-pr, review-pr, generic-run, continue-pr]
      defaultWorkflow: implement-pr

producer:
  submission:
    mode: scheduleAdmission
    admissionMode: profiled
    commandWorkflows:
      pr-create: implement-pr
      review: review-pr
      run: generic-run
      pr-continue: continue-pr
```

The operator injects the per-run lifecycle event webhook for a profiled
schedule template. `work-control` itself only exports `nvt-work` and publishes
the fixed work events; it remains provider-neutral and holds no credentials.
