# AgentSchedule v1alpha1

`AgentSchedule` is an admission pool for disposable `AgentRun` resources. It
supports an operator-owned profiled mode and a compatibility-only legacy mode.
The operator core remains producer-agnostic.

## Profiled schedules

A profiled schedule owns a typed common template, named execution profiles,
static or explicitly enabled dynamic principal selection, optional workflow profiles, and the exact
Kubernetes producer identities that may submit work. See
[`operator/examples/agentschedule-profiled.yaml`](../examples/agentschedule-profiled.yaml)
for a complete resource.

The common `template` owns the runtime image, RuntimeClass, agent-container
resources, optional agent-Pod tolerations, workspace (including optional
dedicated `dockerSize` for persistent runs), shared agent config (packages, tools, and plugins),
lifecycle defaults, and TTL. RuntimeClass scheduling may select a runtime/node
environment. Tolerations permit the generated agent Pod to schedule onto
matching tainted nodes, but do not select a node or remove a taint. The template
does not contain a prompt or top-level `agent.config.runtime` key.

Each `profiles[]` entry owns runtime type/auth, the complete top-level agent
runtime configuration (including exact `runtime.proxy.provider`), egress mode
and enforcement, broker providers/grants, and optional `workspaceInstructions`.
The operator inserts
`profile.agentRuntimeConfig` as `AgentRun.spec.agent.config.runtime`. This is an
explicit replacement boundary, not an arbitrary merge patch.

### Execution selection

Execution selection is administrator-owned. Omitting `execution` from a
profile preserves the existing built-in Kubernetes Pod path byte-for-byte. An
explicit built-in selection is equivalent:

```yaml
profiles:
  - name: codex-default
    execution:
      kind: pod
      driver: kubernetes
    # runtime, agentRuntimeConfig, egress, and broker fields omitted
```

External drivers use a logical name and one exact operator-owned class. Class
configuration is opaque JSON, bounded to 256 KiB, and snapshotted into the
resolved AgentRun so later schedule changes cannot alter an accepted run:

```yaml
executionClasses:
  - name: vm-standard
    kind: vm
    driver: example-vm
    configuration:
      cpu: 4
      network:
        isolation: required
profiles:
  - name: codex-vm
    execution:
      kind: vm
      driver: example-vm
      classRef: vm-standard
    # remaining profile-owned fields omitted
```

The profile kind and driver must match the named class exactly. Missing,
unknown, or mismatched selections fail before an agent Pod is created and
never fall back to Kubernetes or another driver. This release registers only
the built-in `pod`/`kubernetes` adapter; external selections report the stable
`ExecutionDriverUnavailable` condition until a future dedicated driver-host
integration is installed. Class configuration must not contain credentials;
future driver credentials remain a separate operator-owned projection.

Producer admission can select only its authorized workflow and immutable work
principal as documented below. It cannot name an execution profile, class,
driver source, executable, environment, credentials, or arbitrary driver
configuration.

`workspaceInstructions` is administrator-owned, reusable workflow guidance.
The selected value is snapshotted into the resolved AgentRun and appended to
the generated workspace `AGENTS.md`; it never replaces nvt's platform guidance.
The value is bounded to 64 KiB. It is configuration, not a security boundary,
and must not contain credentials or sensitive values because the untrusted
agent can read it. Producers cannot submit or override this field.

```yaml
profiles:
  - name: codex-default
    workspaceInstructions: |
      Follow the repository contribution guide.
      Run the project checks before opening a pull request.
```

Profiles may also opt the untrusted Kubernetes/OCI agent container into valid
Linux capabilities without exposing a raw security context:

```yaml
profiles:
  - name: debug-codex
    runtime:
      type: codex
      autonomy: trusted-local
      container:
        capabilities:
          add: [SYS_PTRACE]
    # remaining profile-owned runtime, egress, and broker fields omitted
```

The capability request is snapshotted with the selected execution profile.
Producer work, workflow selection, prompts, and agent input cannot add or
override it. See the AgentRun documentation for the container-only portability
and security limits.

Profiles may optionally pin the runtime model and reasoning effort. These
administrator-owned values are snapshotted into each AgentRun; producer input
cannot supply or override them:

```yaml
profiles:
  - name: codex-high
    runtime: {type: codex, autonomy: trusted-local, model: gpt-5.6-sol, effort: high}
  - name: claude-high
    runtime: {type: claude, autonomy: trusted-local, model: opus, effort: high}
```

Forward-proxy and transparent execution profiles may set the generic
`egressMaxConcurrentTunnels` bound from 1 through 4096. It is snapshotted into
the AgentRun with the other profile-owned egress settings. Omission uses
egressd's default of 256 active tunnels with bounded burst queueing.

Profiles may also require bounded IPv4 Docker bridge networks without naming a
tool or repository:

```yaml
profiles:
  - name: nested-cluster
    runtime:
      type: codex
      autonomy: trusted-local
      docker:
        kernelLogDevice: true
        requiredNetworks:
          - name: kind
            subnet: 172.31.250.0/24
    # remaining profile-owned fields omitted
```

The selected network list is deep-copied into the AgentRun and cannot be
supplied by producer admission. It is reconciled at the Docker CLI boundary,
including after pruning. Only canonical IPv4 `/24` networks inside the managed
pool are supported; IPv6 and dual-stack requests fail closed.

`kernelLogDevice` is independently optional and defaults false. It is
snapshotted from the administrator-owned profile and reaches only DinD. Enable
it only for approved microVM-backed profiles: on an ordinary container runtime
the nested privileged workload may otherwise gain access to the Kubernetes
node kernel log. Producers cannot submit or override this control.

For new deployments that need producer-selectable workflows, keep execution
credentials in `profiles` and define guidance independently:

```yaml
workflowProfiles:
  - name: implement-pr
    workspaceInstructions: |
      Implement the change and create a pull request.
    lifecycle:
      completeOn: [plugin.github.pr.merged, plugin.github.pr.closed]
      failOn: [plugin.work.failed]
  - name: review-pr
    workspaceInstructions: |
      Review the pull request and report findings first.
    lifecycle:
      completeOn: [plugin.work.completed]
      failOn: [plugin.work.failed]
producerPolicies:
  - identity: system:serviceaccount:nvt:nvt-github-comments-producer
    workflows: [implement-pr, review-pr]
    defaultWorkflow: implement-pr
```

TokenReview establishes `identity`; it is never read from admission JSON. A
requested workflow is exact-matched against that policy. When omitted, the
policy's optional default is used. Workflow selection is independent of
principal-based execution-profile selection and cannot change runtime, auth,
provider, broker, or egress configuration.

When a workflow profile defines `lifecycle`, that block completely replaces
the lifecycle from the schedule template for the immutable AgentRun snapshot;
event lists are not merged. When it is omitted, the template lifecycle is
preserved exactly. Lifecycle is administrator-authored workflow policy and is
never accepted from producer admission input. This makes it safe for workflows
sharing one execution profile to use different terminal events while active TTL
continues to provide the final bound.

`profileSelection.rules` match exact `issuer` plus immutable `subject` values.
`displayName` is stored for audit/display only and never participates in
selection. Duplicate selectors/profile names, missing references, invalid
`onNoMatch`, and unusable selection paths fail closed. There are no
producer-selectable profile names, candidates, or fallbacks.

### Dynamic principal-owned credentials

`principalCredentialSelection` is an additive, disabled-by-default alternative
to `profileSelection`. It resolves a ready broker-owned account for the exact
canonical issuer plus immutable subject supplied by an authenticated producer,
then maps the broker-returned public credential template through an
administrator-owned profile table:

```yaml
principalCredentialSelection:
  enabled: true
  onNoMatch: deny
  templateProfiles:
    - template: approved-work
      profile: mediated-work
producerPolicies:
  - identity: system:serviceaccount:nvt:producer
    workflows: [implement]
    defaultWorkflow: implement
    allowedPrincipalIssuers:
      - https://identity.example/tenant
profiles:
  - name: mediated-work
    runtime: {type: generic-agent, autonomy: trusted-local}
    agentRuntimeConfig:
      command: agent
      proxy: {provider: $principal-account}
    egress: mediated
    egressEnforcement: true
    egressTransport: forward-proxy
    broker:
      grants:
        - provider: $principal-account
          materialization: header-inject
          repositories: [example/*]
          egressHosts: [provider.example]
```

The authenticated producer identity comes from TokenReview as before. Each
dynamic producer policy additionally lists 1–32 exact canonical HTTPS
principal issuers. This constrains which identity domains that producer may
assert but is not current user eligibility. The portal's shared OAuth policy
mints a bounded renewable eligibility lease after each successful login; the
broker persists only its non-secret expiry and requires it during operator
readiness/resolution. A later verified policy denial revokes the lease, and
expiry or revocation denies new AgentRuns as `principal-not-eligible` without
interrupting already frozen runs. Display name, login, and email are never
ownership. A missing/malformed principal or disallowed issuer is rejected
before the broker is contacted.

The operator alone sends a short-lived exact-principal assertion to the broker
over verified TLS. It requires consistent authenticated readiness and
resolution responses, maps only the returned public template, and replaces the
reserved exact scalar `$principal-account` in the mapped profile's broker
grants and runtime config with the opaque resolved provider instance. Substring
values are unchanged. The mapped profile must use mediated egress, have a
broker grant containing that placeholder, and must not use file-bundle
materialization for it. Static auxiliary grants remain unchanged.

Producer JSON still accepts only workflow, work/principal facts, and prompt.
Template, provider instance, generation, profile, grants, capabilities,
runtime, and egress fields are rejected rather than ignored. There is no
static/shared fallback. Stable failures are `principal-not-eligible`,
`principal-not-enrolled`, `credential-not-ready`, and
`credential-resolution-unavailable`; broker IDs and diagnostics are not
returned.

Resolution happens only before creating a new AgentRun. The exact principal,
public template, opaque provider instance ID, credential generation, selected
profile, and schedule provenance are frozen in the immutable run. Duplicate
work retries are answered from existing Kubernetes state without re-resolving;
reconnect, revoke, schedule changes, operator restart, or broker outage cannot
rewrite an accepted run. Revoked/unready accounts cannot admit new runs.

Template switching remains fail-closed unless the separate operator-only
coordination contract is enabled. Broker revocation retains its durable
template lock; an opaque target-free portal request lets the trusted operator
reserve the exact account, prove there are no non-terminal exact-principal
AgentRuns, and commit the unlock. Dynamic admission uses that same broker
reservation around resolution and creation, closing the race. Browser and
producer input never supplies a transition, target, provider, or profile. The
proof uses a bounded uncached API read; pagination or ambiguous dynamic
provenance fails closed.

Profiled requests contain only an optional workflow name, work metadata, and
prompt input:

```json
{
  "workflow": "review-pr",
  "work": {
    "id": "github:example/repo:issue:123",
    "title": "Fix the failing test",
    "url": "https://github.com/example/repo/issues/123",
    "repository": "example/repo",
    "principal": {
      "issuer": "https://github.com",
      "subject": "12345678",
      "displayName": "octocat"
    }
  },
  "input": {"prompt": "Investigate and open a PR"}
}
```

The principal may be absent when `onNoMatch: useDefault` names a valid default.
Unknown and missing principals follow `onNoMatch` exactly. Any top-level field
other than `workflow`, `work`, or `input`, including `agentRun`, profile, broker, grant,
provider, proxy, egress, or workspace instruction configuration, is rejected
rather than ignored. The only additional top-level field is the optional,
non-secret `workflow` name. `input` accepts only `prompt`.

### Producer authentication

Profiled admission requires a projected Kubernetes ServiceAccount bearer token
with audience `nvt-operator`. The operator validates it with TokenReview and
exact-matches the authenticated username against schedule-owned authorization.
Workflow-enabled schedules use typed `spec.producerPolicies`:

```yaml
producerPolicies:
  - identity: system:serviceaccount:nvt:nvt-github-comments-producer
    workflows: [implement-pr, review-pr]
    defaultWorkflow: implement-pr
```

Requested-by annotations, principal display names, and request content are not
authentication. Missing, malformed, failed, wrong-audience, and unauthorized
credentials fail closed.

The GitHub comments producer uses this contract with
`submission.mode: scheduleAdmission` and `submission.admissionMode: profiled`.
It reports issuer `https://github.com`, the immutable numeric GitHub user ID as
`subject`, and the login as display-only metadata. Its projected token is read
for every request and uses audience `nvt-operator`; the schedule must list the
producer ServiceAccount username in `producerPolicies` when workflows are
enabled. `submission.workflow` may set one static allowlisted workflow name;
when absent, the producer emits no workflow field. Most deployments need only
`defaultProfile`. Add exact issuer/subject rules only when different principals
must resolve to different execution profiles.

### Producer policy migration

The original `allowedProducers: []string` field remains supported unchanged for
schedules without workflow configuration. To enable workflows, replace that
list with `producerPolicies` and add `workflowProfiles`. The two authorization
forms cannot be mixed. This additive typed migration avoids a string-or-object
union and keeps stored schedules valid until administrators opt in.

### Immutable resolution

The operator resolves once, builds the complete `AgentRun`, generates its final
name, injects lifecycle callback configuration, and creates it. The stored run
contains the resolved configuration and `spec.profileProvenance`: authenticated
producer, schedule identity/generation, selected execution profile, selected
workflow when present, and principal. Dynamic admission also records the
public credential template, opaque provider instance ID, and credential
generation in `profileProvenance.principalCredential`. Profile and workflow instruction text are
stored separately in the AgentRun snapshot. The runtime appends generated
platform guidance, execution-profile guidance, workflow guidance, then local
workspace guidance, in that order.
Subsequent schedule edits do not change existing runs. Structured provenance is
authoritative; labels and annotations are display data only.

When the common template configures lifecycle events, `event-webhook` is
reserved for the operator-generated callback. Declaring that plugin in the
common config is rejected so the callback cannot be replaced or ambiguously
merged.

## Legacy migration mode

A schedule with none of `template`, `profiles`, `profileSelection`,
`principalCredentialSelection`,
`workflowProfiles`, `producerPolicies`, or `allowedProducers` keeps the existing
full-`AgentRun` request contract. It
remains unauthenticated for compatibility in this PR and must stay
cluster-internal:

```json
{
  "work": {"id": "work-123", "title": "Legacy work"},
  "agentRun": {
    "metadata": {"generateName": "legacy-"},
    "spec": {
      "runtime": {"type": "codex", "autonomy": "trusted-local"},
      "image": "nvt-agent-runtime:latest",
      "workspace": {"mode": "Ephemeral"},
      "agent": {"config": {}}
    }
  }
}
```

Do not expose either mode publicly. Profiled authentication proves the
Kubernetes producer workload identity, not an end-user identity.

## Generic admission controls

Both modes enforce suspend, global max parallelism, and retained work-ID
deduplication. The global parallelism default is `1`. Profiled schedules may
also set `principalParallelism.defaultMaxParallelism` to limit active runs
independently for every exact immutable `issuer` + `subject` pair. Up to 256
administrator-owned `overrides` may replace that default for exact principals:

```yaml
maxParallelism: 20
principalParallelism:
  defaultMaxParallelism: 2
  overrides:
    - issuer: https://identity.example/tenant
      subject: immutable-user-42
      maxParallelism: 5
```

The global value remains the absolute ceiling. Omitting `principalParallelism`
preserves global-only behavior. Requests must carry a canonical principal when
the object is configured. Display names, selected profiles, credential
providers, and producer identities do not affect the capacity key. Duplicate
override keys are invalid, and terminal runs release both limits.

Admissions are serialized per schedule within the active operator process.
The chart therefore requires one operator replica and an unconditional
`Recreate` Deployment strategy. Upgrades may briefly pause admission, but an
old and new binary cannot overlap and make independent capacity decisions.
The operator forces namespace and ownership and records work/gateway metadata;
`work.repository` is stored in `nvt.dev/work-repository` when present.

Responses use `201` for creation, `202` for suspended/duplicate work, `429` for
capacity, `401` for failed profiled authentication, `403` for unauthorized
producer/profile denial, `400` for malformed or invalid requests/config, and
`404` for a missing schedule.

When dynamic principal selection is absent there is no external resolver and
the existing static and legacy behavior is unchanged. No mode permits a
producer-selectable profile choice, repository templating, or gateway
creator-only authorization.

When optional dynamic template switching is enabled, every dynamic admission
first obtains an exact-principal reservation from the broker and releases it
only after AgentRun creation has succeeded or failed. The trusted switch
handler uses the same reservation while listing AgentRuns for the
broker-returned canonical issuer and immutable subject. It commits the
target-free unlock only when every matching run is terminal (`Completed`,
`Failed`, or `DeadlineExceeded`) or absent. An active run returns
`active-agentruns`; list, broker, storage, timeout, malformed-response, or
authentication uncertainty fails closed. Producers cannot invoke this handler
or supply a switch request/template/provider/profile. The portal supplies only
an opaque broker request id, and neither hop contains credential material.
