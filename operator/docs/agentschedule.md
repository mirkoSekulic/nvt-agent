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

The same profiles may define an optional administrator-owned
`egressDomainPolicy`:

```yaml
profiles:
  - name: restricted
    egress: mediated
    egressEnforcement: true
    egressTransport: transparent
    egressDomainPolicy:
      defaultAction: deny
      allow: [github.com, registry.npmjs.org]
      deny: [pastebin.com]
```

The complete policy is deep-copied into the selected AgentRun. Producers can
only select an authorized profile and cannot widen the policy. Required broker
injection hosts that the policy denies make the profile/run invalid.

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

When a workflow profile defines `lifecycle`, it completely replaces the
template lifecycle in the immutable AgentRun snapshot; event lists are not
merged. Omission preserves the template lifecycle exactly. Lifecycle is
administrator-owned workflow policy and is never accepted from producer input.

`profileSelection.rules` match exact `issuer` plus immutable `subject` values.
`displayName` is stored for audit/display only and never participates in
selection. Duplicate selectors/profile names, missing references, invalid
`onNoMatch`, and unusable selection paths fail closed. There are no
producer-selectable profile names, candidates, or fallbacks.

### Dynamic principal-owned credentials

`principalCredentialSelection` is a disabled-by-default alternative to static
`profileSelection`. For the exact canonical issuer and immutable subject from
an authenticated producer, the operator resolves a ready broker-owned account
and maps its public credential template to an administrator-owned profile:

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
    allowedPrincipalIssuers: [https://identity.example/tenant]
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

The producer policy permits only exact canonical principal issuers. Current
eligibility is a bounded broker lease, not a display name or login. The
operator authenticates to the broker over verified TLS, requires readiness and
resolution to agree, and substitutes only the exact `$principal-account`
placeholder. Dynamic profiles must use mediated egress and cannot use
file-bundle materialization for the principal-owned grant. Resolution failures
never fall back to a static provider.

The resolved principal, public template, opaque provider instance, credential
generation, profile, and schedule provenance are frozen in the AgentRun.
Duplicate work retries do not re-resolve. Producers cannot choose templates,
providers, generations, profiles, grants, runtime settings, or egress policy.

Profiled requests contain only an optional workflow name, work metadata, and
prompt input:

```json
{
  "workflow": "review-pr",
  "work": {
    "id": "github:example/repo:issue:123",
    "group": "github:example/repo:issue:123:intent:pr-continue",
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

`work.group` is optional bounded, non-secret concurrency metadata. Admission is
an accepted duplicate while another member of the group is active; terminal
members release the group. Exact work-ID deduplication still applies across
retained terminal runs. The local-controller backend uses the same contract.

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
workflow when present, and principal. Profile and workflow instruction text are
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

Both modes enforce suspend, global max parallelism, retained work-ID
deduplication, and optional active work-group exclusion. Exact work and active
group checks happen before capacity. The global default is `1`. Profiled
schedules may additionally set a positive per-principal default and exact
immutable-principal overrides:

```yaml
maxParallelism: 20
principalParallelism:
  defaultMaxParallelism: 2
  overrides:
    - issuer: https://identity.example/tenant
      subject: immutable-user-42
      maxParallelism: 5
```

The global limit remains the ceiling. Display names, profiles, providers, and
producer identities do not affect the principal capacity key; terminal runs
release both limits. Admissions are serialized per schedule within the active
operator process. The operator forces namespace and
ownership and records work/gateway metadata; `work.repository` is stored in
`nvt.dev/work-repository` when present.

Responses use `201` for creation, `202` for suspended/duplicate work, `429` for
capacity, `401` for failed profiled authentication, `403` for unauthorized
producer/profile denial, `400` for malformed or invalid requests/config, and
`404` for a missing schedule.

When dynamic principal selection is absent, no broker resolver is contacted
and static/legacy behavior is unchanged. No mode permits producer-selectable
profiles, repository templating, or gateway creator-only authorization.

Optional dynamic template switching uses the same exact-principal broker
reservation as admission. The operator commits an opaque, target-free unlock
only after a bounded uncached Kubernetes read proves that every matching run is
terminal or absent. Active work returns a stable denial; pagination or
ambiguous provenance fails closed.
