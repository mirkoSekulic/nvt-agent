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

The controller writes these grants into the shared `nvt-broker-agents`
ConfigMap in the same namespace as the `AgentRun`. The broker identity is
`<namespace>/<name>`, and the policy stores only the SHA-256 hash of the
per-run `NVT_BROKER_TOKEN`.

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

The operator compares callback event names with `completeOn` and `failOn`. For
plugin-published events, it uses the event's `plugin_event` name when present.
For ordinary agent/runtime events, it uses the event's `event` name.

Current controller behavior creates a stable per-run callback token Secret and
wires it into the agent Pod as `NVT_OPERATOR_CALLBACK_TOKEN`.

The event-webhook plugin posts to the cluster-internal operator endpoint:

```text
POST /v1/agentruns/{namespace}/{name}/events
Authorization: Bearer <NVT_OPERATOR_CALLBACK_TOKEN>
```

The bearer token is read from the same-namespace Secret
`<agentrun-name>-callback-token` key `NVT_OPERATOR_CALLBACK_TOKEN`. Missing or
wrong tokens return `401`, and token values are not logged or returned.

### `spec.ttl`

Cleanup timing hints:

```yaml
ttl:
  activeDeadlineSeconds: 14400
  completedTTLSeconds: 300
  failedTTLSeconds: 3600
```

`activeDeadlineSeconds` bounds active runtime duration but is not enforced yet.
`completedTTLSeconds` and `failedTTLSeconds` control owned Pod cleanup after
`Completed` and `Failed` phases. Lifecycle failure callbacks and Kubernetes Pod
`Failed` status both stamp `status.finishedAt`, so both failure paths can use
`failedTTLSeconds`. If the relevant terminal TTL or `status.finishedAt` is
unset, the Pod is left in place. The `AgentRun` CR is not deleted by this
controller slice, so status/history remain visible.

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
the Pod first reaches `Running`. `finishedAt` and `reason` are set by lifecycle
callbacks when a configured event marks the run complete or failed.

`phase` is one of:

- `Pending`
- `Running`
- `Completed`
- `Failed`
- `DeadlineExceeded`

## Intended v1 Controller Behavior

The current controller initializes empty `status.phase` values to `Pending` and
renders `spec.agent.config` to an owned ConfigMap with the key `agent.yaml`.
It creates two stable owned opaque Secrets per run:

```text
<agentrun-name>-broker-token    NVT_BROKER_TOKEN
<agentrun-name>-callback-token  NVT_OPERATOR_CALLBACK_TOKEN
```

These tokens are generated once and reused across reconciles. Existing same-name
Secrets that are not owned by the `AgentRun` are rejected.

The controller then creates one owned Pod named `<agentrun-name>-agent` with the
configured agent image and a Docker-in-Docker native sidecar-style init
container. That Pod mounts the rendered ConfigMap at `/nvt-agent/agent.yaml`,
provides an ephemeral `emptyDir` workspace, sets
`DOCKER_HOST=tcp://127.0.0.1:2375` and `NVT_BROKER_URL=http://nvt-broker:7347`
for the agent container, wires both token Secrets through `secretKeyRef`, and
binds the DinD daemon to localhost inside the Pod network namespace. The agent
container starts after the DinD startup probe can run `docker info`.

Between token Secret reconciliation and Pod creation, the controller updates the
shared `nvt-broker-agents` ConfigMap so `agents.yaml` contains the run's broker
identity, `sha256:<hash>` of the raw broker token, and requested grants. It
preserves unrelated agent entries and does not set `AgentRun` ownership on this
shared infrastructure ConfigMap.

The controller adds a finalizer to remove the run's broker policy entry on
deletion. Deletion cleanup preserves unrelated entries and fails open if the
broker agents ConfigMap has already been removed, so local/kind POC cleanup does
not leave an `AgentRun` stuck terminating.

The manager exposes the AgentRun callback endpoint on `--callback-bind-address`
(default `:8082`) for cluster-internal POC traffic:

```text
POST /v1/agentruns/{namespace}/{name}/events
```

The accepted event-webhook payload shape is:

```json
{
  "agent": "optional-agent-name",
  "event": {
    "id": "evt_...",
    "event": "plugin.event",
    "plugin_event": "plugin.github.pr.merged",
    "source": "plugin:github-watcher",
    "payload": {}
  }
}
```

The operator resolves the lifecycle event name from `event.plugin_event` when
non-empty, otherwise `event.event`. Empty event names return `400`; valid but
unmatched events return `202` without changing status. `completeOn` matches set
`Completed`, `finishedAt`, and reason `Completed by lifecycle event <event>`.
`failOn` matches set `Failed`, `finishedAt`, and the equivalent failed reason.
Existing terminal phases (`Completed`, `Failed`, `DeadlineExceeded`) are not
overwritten by callbacks or by later Pod status sync.

This controller slice creates the ConfigMap, per-run token Secrets, broker
policy entry, and Pod, accepts lifecycle callbacks, syncs basic status, and
deletes the owned Pod after completed/failed terminal Pod TTLs. AgentRun CR
cleanup, `DeadlineExceeded` cleanup, scheduler logic, external Ingress, and a
broker admin API remain future work. Static broker providers remain outside
`AgentRun`; the run only requests dynamic grants against them.

Runtime plugins remain normal runtime plugins. Operator extensions and
schedulers remain separate from runtime plugins.

## Broker POC Deployment

`operator/config/broker/broker.yaml` provides local/kind POC manifests for the
broker endpoint used by AgentRun Pods:

```text
http://nvt-broker:7347
```

The manifest creates:

- `nvt-broker-config` ConfigMap with `broker.yaml`
- `nvt-broker-agents` ConfigMap with initial `agents.yaml`
- `nvt-broker` Deployment using `nvt-broker:latest`
- `nvt-broker` ClusterIP Service on port `7347`

Create broker root secrets separately before applying the manifest:

```sh
cat > nvt-broker-env.env <<'EOF'
GITHUB_APP_ID=<app-id>
GITHUB_APP_INSTALLATION_ID=<installation-id>
GITHUB_APP_PRIVATE_KEY_BASE64=<base64-private-key>
EOF
chmod 600 nvt-broker-env.env
kubectl create secret generic nvt-broker-env --from-env-file=nvt-broker-env.env
```

No real Secret values are committed. Avoid putting private key material directly
in shell command arguments. Static broker providers live in `broker.yaml` and
can reference these env var names:

```text
GITHUB_APP_ID
GITHUB_APP_INSTALLATION_ID
GITHUB_APP_PRIVATE_KEY_BASE64
```

Dynamic agent identities and grants live in `agents.yaml`. For this POC,
`agents.yaml` is mounted from the `nvt-broker-agents` ConfigMap and starts as:

```yaml
agents: []
```

This mirrors the local `.broker/agents.yaml` model. Kubernetes projected
ConfigMap updates are eventually reflected in mounted files, and the broker
live-reloads its agents policy file; the kind POC should verify that the broker
sees operator-written updates through this mounted file path.

The operator now updates `nvt-broker-agents` for each `AgentRun` in the same
namespace as the run. A generated entry looks like:

```yaml
agents:
  - id: default/example
    token-sha256: sha256:<sha256-of-NVT_BROKER_TOKEN>
    grants:
      - provider: github-main-app
        repositories:
          - mirkoSekulic/nvt-agent
```

The raw token stays in the owned Secret and is not written to the ConfigMap.
Broker providers remain static in `broker.yaml`; AgentRun CR cleanup,
`DeadlineExceeded` cleanup, scheduler logic, and a broker admin API remain
future work.
