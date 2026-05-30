# AgentRun v1alpha1

`AgentRun` represents one disposable nvt agent execution.

It is generic by design. An `AgentRun` can be created manually, by GitOps, by a
future scheduler, or by another future extension. The resource itself does not
encode who scheduled it.

## Design Boundaries

- `AgentRun` is the generic execution unit.
- Future scheduler extensions may create `AgentRun` resources, but `AgentRun`
  does not know who scheduled it.
- Runtime plugins remain configured through the embedded agent config at
  `spec.agent.config`.
- Operator extensions and schedulers are separate from runtime plugins.
- v1 broker providers are static. `spec.broker.grants` declares per-agent
  dynamic grants against those static providers.
- v1 supports `workspace.mode: Ephemeral` only. There is no PVC-backed
  workspace retention in this contract.
- This API contract does not include scheduler CRDs, controller code, or
  GitHub-specific scheduler/operator logic.

## Example

See `operator/examples/agentrun-basic.yaml`.

The example uses `runtimeClassName: kata-vm-isolation` to show the intended
isolation class for disposable agent pods.

## Spec

### `spec.runtime`

Selects the agent runtime and autonomy mode.

```yaml
runtime:
  type: codex
  autonomy: trusted-local
```

`type` is `codex` or `claude`.

`autonomy` is `trusted-local` or `interactive`.

### `spec.image`

Runtime image for the controller-created agent pod.

```yaml
image: nvt-agent-runtime:latest
```

### `spec.runtimeClassName`

Optional Kubernetes runtime class for the agent pod.

```yaml
runtimeClassName: kata-vm-isolation
```

### `spec.workspace`

v1 supports ephemeral workspaces only:

```yaml
workspace:
  mode: Ephemeral
```

The intended controller mapping is `emptyDir`. The workspace survives container
restart inside the same pod, but is lost if the pod is deleted or rescheduled.

### `spec.broker.grants`

Declares per-run dynamic grants against static broker providers:

```yaml
broker:
  grants:
    - provider: github-main-app
      repositories:
        - mirkoSekulic/nvt-agent
```

`provider` names a statically configured broker provider. `repositories` are
repository identifiers accepted by that provider. Patterns such as `owner/*`
are provider-specific and follow the existing broker behavior.

### `spec.agent.config`

Embedded nvt agent configuration rendered by the controller into an owned
ConfigMap:

```text
<agentrun-name>-agent-config
```

The ConfigMap stores the rendered YAML under:

```text
/nvt-agent/agent.yaml
```

The CRD preserves unknown fields in this object because it mirrors the current
`agent.yaml` shape and plugin config can be arbitrary.

Runtime plugins, tools, code-server settings, exposed ports, and repository
checkout behavior all live here.

### `spec.lifecycle`

Lifecycle event rules define how future webhook callbacks can mark the
`AgentRun` complete or failed:

```yaml
lifecycle:
  completeOn:
    - plugin.github.pr.merged
    - plugin.github.pr.closed
    - plugin.agent.signal.done
  failOn: []
```

The operator should compare callback event names with `completeOn` and `failOn`.
For plugin-published events, use the event's `plugin_event` name. For ordinary
agent/runtime events, use the event's `event` name.

### `spec.ttl`

Cleanup timing hints:

```yaml
ttl:
  activeDeadlineSeconds: 14400
  completedTTLSeconds: 300
  failedTTLSeconds: 3600
```

`activeDeadlineSeconds` bounds active runtime duration. `completedTTLSeconds`
and `failedTTLSeconds` control eventual cleanup after terminal phases. v1 has no
PVC/workspace retention, so cleanup removes the ephemeral workspace with the
pod.

## Status

The controller currently writes basic Pod-phase status:

```yaml
status:
  phase: Pending
  podName: nvt-dev-agent
  startedAt: "2026-05-29T16:00:00Z"
  finishedAt: "2026-05-29T16:30:00Z"
  reason: Completed by lifecycle event plugin.agent.signal.done
```

`podName` is set once the owned agent Pod exists. `startedAt` is set once when
the Pod first reaches `Running`. `finishedAt` and `reason` are reserved for
future lifecycle callback handling.

`phase` is one of:

- `Pending`
- `Running`
- `Completed`
- `Failed`
- `DeadlineExceeded`

## Intended v1 Controller Behavior

The current controller initializes empty `status.phase` values to `Pending` and
renders `spec.agent.config` to an owned ConfigMap with the key `agent.yaml`.
It then creates one owned Pod named `<agentrun-name>-agent` with the configured
agent image and a Docker-in-Docker native sidecar-style init container. That
Pod mounts the rendered ConfigMap at `/nvt-agent/agent.yaml`, provides an
ephemeral `emptyDir` workspace, sets `DOCKER_HOST=tcp://127.0.0.1:2375` for the
agent container, and binds the DinD daemon to localhost inside the Pod network
namespace. The agent container starts after the DinD startup probe can run
`docker info`.

This controller slice only creates the ConfigMap and Pod and syncs basic
Pod-phase status. Broker token registration, operator callback token creation,
lifecycle completion/failure handling, and TTL cleanup remain future work.
Static broker providers remain outside `AgentRun`; the run only requests
dynamic grants against them.

Runtime plugins remain normal runtime plugins. Operator extensions and
schedulers remain separate from runtime plugins.

The event-webhook runtime plugin can post callbacks to the operator. The
operator can then match received event names against `spec.lifecycle.completeOn`
and `spec.lifecycle.failOn` to update `status.phase`, set timestamps, and apply
TTL cleanup behavior.
