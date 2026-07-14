# AgentSchedule v1alpha1

`AgentSchedule` is an admission pool for disposable `AgentRun` resources. It
supports an operator-owned profiled mode and a compatibility-only legacy mode.
The operator core remains producer-agnostic.

## Profiled schedules

A profiled schedule owns a typed common template, named execution profiles,
static principal selection, and the exact Kubernetes producer identities that
may submit work. See
[`operator/examples/agentschedule-profiled.yaml`](../examples/agentschedule-profiled.yaml)
for a complete resource.

The common `template` owns the runtime image, RuntimeClass, workspace, shared
agent config (packages, tools, and plugins), lifecycle defaults, and TTL. It
does not contain a prompt or top-level `agent.config.runtime` key.

Each `profiles[]` entry owns runtime type/auth, the complete top-level agent
runtime configuration (including exact `runtime.proxy.provider`), egress mode
and enforcement, and broker providers/grants. The operator inserts
`profile.agentRuntimeConfig` as `AgentRun.spec.agent.config.runtime`. This is an
explicit replacement boundary, not an arbitrary merge patch.

`profileSelection.rules` match exact `issuer` plus immutable `subject` values.
`displayName` is stored for audit/display only and never participates in
selection. Duplicate selectors/profile names, missing references, invalid
`onNoMatch`, and unusable selection paths fail closed. There are no
producer-selectable profile names, candidates, or fallbacks.

Profiled requests contain only work metadata and prompt input:

```json
{
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
other than `work` or `input`, including `agentRun`, profile, broker, grant,
provider, proxy, or egress configuration, is rejected rather than ignored.

### Producer authentication

Profiled admission requires a projected Kubernetes ServiceAccount bearer token
with audience `nvt-operator`. The operator validates it with TokenReview and
exact-matches the authenticated username against `spec.allowedProducers`:

```yaml
allowedProducers:
  - system:serviceaccount:nvt:nvt-github-comments-producer
```

Requested-by annotations, principal display names, and request content are not
authentication. Missing, malformed, failed, wrong-audience, and unauthorized
credentials fail closed.

The GitHub comments producer uses this contract with
`submission.mode: scheduleAdmission` and `submission.admissionMode: profiled`.
It reports issuer `https://github.com`, the immutable numeric GitHub user ID as
`subject`, and the login as display-only metadata. Its projected token is read
for every request and uses audience `nvt-operator`; the schedule must list the
producer ServiceAccount username in `allowedProducers`. Most deployments need
only `defaultProfile`. Add exact issuer/subject rules only when different
principals must resolve to different execution profiles.

### Immutable resolution

The operator resolves once, builds the complete `AgentRun`, generates its final
name, injects lifecycle callback configuration, and creates it. The stored run
contains the resolved configuration and `spec.profileProvenance`: authenticated
producer, schedule identity/generation, selected profile, and principal.
Subsequent schedule edits do not change existing runs. Structured provenance is
authoritative; labels and annotations are display data only.

When the common template configures lifecycle events, `event-webhook` is
reserved for the operator-generated callback. Declaring that plugin in the
common config is rejected so the callback cannot be replaced or ambiguously
merged.

## Legacy migration mode

A schedule with none of `template`, `profiles`, `profileSelection`, or
`allowedProducers` keeps the existing full-`AgentRun` request contract. It
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
