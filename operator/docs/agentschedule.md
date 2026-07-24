# AgentSchedule v1alpha1

`AgentSchedule` is an admission pool for disposable `AgentRun` resources. It
supports an operator-owned profiled mode and a compatibility-only legacy mode.
The operator core remains producer-agnostic.

## Profiled schedules

A profiled schedule owns a typed common template, named execution profiles,
static principal selection, optional workflow profiles, and the exact
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

For new deployments that need producer-selectable workflows, keep execution
credentials in `profiles` and define guidance independently:

```yaml
workflowProfiles:
  - name: implement-pr
    workspaceInstructions: |
      Implement the change and create a pull request.
  - name: review-pr
    workspaceInstructions: |
      Review the pull request and report findings first.
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

`profileSelection.rules` match exact `issuer` plus immutable `subject` values.
`displayName` is stored for audit/display only and never participates in
selection. Duplicate selectors/profile names, missing references, invalid
`onNoMatch`, and unusable selection paths fail closed. There are no
producer-selectable profile names, candidates, or fallbacks.

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

Both modes enforce suspend, max parallelism, and retained work-ID
deduplication. The parallelism default is `1`. Admissions are serialized per
schedule within the active operator process. The operator forces namespace and
ownership and records work/gateway metadata; `work.repository` is stored in
`nvt.dev/work-repository` when present.

Responses use `201` for creation, `202` for suspended/duplicate work, `429` for
capacity, `401` for failed profiled authentication, `403` for unauthorized
producer/profile denial, `400` for malformed or invalid requests/config, and
`404` for a missing schedule.

There is no external resolver, producer-selectable profile choice, repository
templating, or gateway creator-only authorization in this version.
