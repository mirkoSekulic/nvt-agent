# AgentSchedule v1alpha1

`AgentSchedule` is the first POC scheduling foundation for the Kubernetes
operator. It is a generic admission pool for disposable `AgentRun` resources,
not a plugin-specific schedule, template, or event source.

Scheduler plugins decide what work should run and submit a complete `AgentRun`
spec to the operator. The operator only enforces generic controls:

- the schedule exists
- the schedule is not suspended
- active runs are below `spec.maxParallelism`
- no active run already has the same work id

The operator core does not contain GitHub, issue, Slack, or other source-specific
logic.

## Spec

```yaml
apiVersion: nvt.dev/v1alpha1
kind: AgentSchedule
metadata:
  name: default
spec:
  suspend: false
  maxParallelism: 5
```

`spec.suspend` stops new admissions without deleting or modifying existing
`AgentRun` resources.

`spec.maxParallelism` is optional. When omitted or set to `0`, the effective
default is `1`, which is the conservative default for disposable automation.

## Status

```yaml
status:
  observedGeneration: 1
  activeRuns: 0
  lastAcceptedAt: "2026-05-31T12:00:00Z"
  lastRejectedAt: "2026-05-31T12:05:00Z"
  lastRejectionReason: "max-parallelism-reached"
```

`status.observedGeneration` mirrors the reconciled
`metadata.generation`. It is not a run counter.

`status.activeRuns` counts accepted child `AgentRun` resources in the same
namespace that are not terminal. Empty phase, `Pending`, and `Running` count as
active. `Completed`, `Failed`, and `DeadlineExceeded` do not.

## Admission Endpoint

For this POC, trusted cluster-internal scheduler producers can submit a run to:

```text
POST /v1/schedules/{namespace}/{name}/runs
```

Do not expose this endpoint publicly. v1 has no authentication and assumes
trusted same-cluster callers.

Payload:

```json
{
  "work": {
    "id": "github:Altinn/altinn-studio:issue:123",
    "title": "Warm runner cache",
    "url": "https://github.com/Altinn/altinn-studio/issues/123"
  },
  "agentRun": {
    "metadata": {
      "generateName": "github-issue-"
    },
    "spec": {
      "runtime": {
        "type": "codex",
        "autonomy": "trusted-local"
      },
      "image": "nvt-agent-runtime:latest",
      "workspace": {
        "mode": "Ephemeral"
      },
      "agent": {
        "config": {}
      }
    }
  }
}
```

Admission is create-only. The operator forces the `AgentRun` namespace to the
schedule namespace, sets `AgentSchedule` ownership, and sets reserved metadata:

```yaml
labels:
  nvt.dev/schedule: <schedule-name>
annotations:
  nvt.dev/work-id: <work.id>
  nvt.dev/work-url: <work.url>
```

`nvt.dev/work-url` is set only when the submitted work URL is non-empty. If the
submitted `AgentRun` has neither `metadata.name` nor `metadata.generateName`,
the operator defaults `generateName` to `<schedule-name>-`.

Responses:

- `201 {"scheduled":true,"agentRun":{"namespace":"nvt","name":"..."}}`
- `202 {"scheduled":false,"reason":"schedule-suspended"}`
- `202 {"scheduled":false,"reason":"duplicate-work"}`
- `429 {"scheduled":false,"reason":"max-parallelism-reached"}`
- `400` for malformed JSON or missing `work.id`
- `404` when the schedule does not exist

## Scope

This slice is intentionally same-namespace and cluster-internal. It does not add
authentication, template mode, per-key limits, multi-namespace scheduling, or
concrete scheduler plugins. Those are future work.
