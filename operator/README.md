# nvt Kubernetes Operator

This directory contains the initial API contract and controller scaffold for the
nvt Kubernetes operator.

The first resources are `AgentRun` and `AgentSchedule`:

```text
apiVersion: nvt.dev/v1alpha1
kind: AgentRun

apiVersion: nvt.dev/v1alpha1
kind: AgentSchedule
```

`AgentRun` is the generic execution unit for one disposable nvt agent run. It
does not know whether it was created manually, by GitOps, by a scheduler, or by
some future extension.

`AgentSchedule` is a generic admission pool. Trusted scheduler plugins submit a
complete `AgentRun` spec to the operator endpoint, and the operator applies only
generic controls such as suspend, parallelism, and duplicate active work ids.

## Files

- `config/crd/bases/nvt.dev_agentruns.yaml`: AgentRun v1alpha1 CRD manifest
- `config/crd/bases/nvt.dev_agentschedules.yaml`: AgentSchedule v1alpha1 CRD
  manifest
- `config/broker/broker.yaml`: local/kind broker Deployment, Service, and
  ConfigMaps for POC clusters
- `examples/agentrun-basic.yaml`: example disposable agent run
- `docs/agentrun.md`: AgentRun API and intended v1 behavior notes
- `docs/agentschedule.md`: AgentSchedule admission-pool behavior notes
- `cmd/manager`: controller-runtime manager entrypoint
- `internal/controller`: AgentRun reconciler

## Scope

The current controller initializes empty `status.phase` values to `Pending`,
renders `spec.agent.config` into an owned ConfigMap named
`<agentrun-name>-agent-config` with the `agent.yaml` key, creates stable
per-run broker and callback token Secrets, writes the AgentRun broker identity
and requested grants into the shared `nvt-broker-agents` ConfigMap, and creates
one owned Pod named `<agentrun-name>-agent`. The Pod runs the configured agent
image next to a native Kubernetes sidecar-style init container for
Docker-in-Docker, mounts the rendered config at `/nvt-agent/agent.yaml`, wires
token Secrets into the agent container environment, and uses an ephemeral
`emptyDir` workspace. The agent container starts after the DinD startup probe
can run `docker info`.

The AgentRun controller syncs basic Pod-phase status only: it records `status.podName`,
sets `Running` and `startedAt` when the Pod is running, sets `Failed` when the
Pod fails, and accepts cluster-internal lifecycle callbacks that can mark the
run `Completed` or `Failed`. Completed and failed runs delete their owned agent
Pod after the matching terminal Pod TTL. AgentRun CR cleanup remains
intentionally future work.

The AgentSchedule controller syncs generic admission-pool status and the
operator HTTP server accepts cluster-internal schedule admissions at
`POST /v1/schedules/{namespace}/{name}/runs`. The schedule admission endpoint is
same-namespace and assumes trusted cluster-internal callers for this POC; it has
no authentication and must not be exposed publicly. Admissions are guarded by a
per-schedule lock inside one active operator process, so the POC assumes a
single active HTTP process, normally via leader election.

This directory does not include GitHub-specific operator logic. Runtime plugins
remain configured through the embedded agent config under `spec.agent.config`.

Future scheduler plugins may submit `AgentRun` resources through
`AgentSchedule`, but those plugins are separate from `AgentRun` itself and
separate from runtime plugins. Auth, template mode, per-key limits,
multi-namespace behavior, and concrete scheduler plugins remain future work.

## Broker POC Manifests

`config/broker/broker.yaml` installs a service-internal broker for local/kind
POCs:

```sh
cat > nvt-broker-env.env <<'EOF'
GITHUB_APP_ID=<app-id>
GITHUB_APP_INSTALLATION_ID=<installation-id>
GITHUB_APP_PRIVATE_KEY_BASE64=<base64-private-key>
EOF
chmod 600 nvt-broker-env.env
kubectl create secret generic nvt-broker-env --from-env-file=nvt-broker-env.env

kubectl apply -f config/broker/broker.yaml
```

The Secret and local env file are intentionally not committed. Avoid putting the
private key directly in shell command arguments. The manifest expects these keys
when the example GitHub App provider is enabled in `nvt-broker-config`:

```text
GITHUB_APP_ID
GITHUB_APP_INSTALLATION_ID
GITHUB_APP_PRIVATE_KEY_BASE64
```

Broker providers are static in `broker.yaml`. Dynamic agent identities and
grants live in `agents.yaml`; for the POC, `agents.yaml` is the shared
`nvt-broker-agents` ConfigMap mounted into the broker, matching the local
`.broker/agents.yaml` model. The controller assumes this ConfigMap is in the
same namespace as the `AgentRun`, updates only the entry for that run, and does
not set `AgentRun` ownership on the shared ConfigMap.

For an `AgentRun` named `default/example`, the controller writes an entry shaped
like:

```yaml
agents:
  - id: default/example
    token-sha256: sha256:<sha256-of-NVT_BROKER_TOKEN>
    grants:
      - provider: github-main-app
        repositories:
          - mirkoSekulic/nvt-agent
```

The raw broker token stays in the owned `<agentrun-name>-broker-token` Secret
and is never written to the ConfigMap. The controller adds an `AgentRun`
finalizer so deletion removes only that run's `agents.yaml` entry. If the broker
ConfigMap has already been removed during deletion, cleanup fails open to avoid
leaving local/kind POC runs stuck terminating.

Kubernetes projected ConfigMap updates are eventually reflected in mounted
files, and the broker already live-reloads its agents policy file locally. The
kind POC should verify that the broker observes operator-written ConfigMap
updates through this mounted file path.

AgentRun Pods receive `NVT_BROKER_URL=http://nvt-broker:7347` and a
per-run `NVT_BROKER_TOKEN`. Broker provider configuration remains static;
AgentRun CR cleanup, concrete scheduler plugins, and a broker admin API remain
future work.

## AgentRun Callback Endpoint

The manager exposes a cluster-internal callback HTTP listener on
`--callback-bind-address` (default `:8082`). A Service for the operator should
route to that port for POC clusters; no external Ingress is included.

The event-webhook plugin should post lifecycle events to:

```text
POST /v1/agentruns/{namespace}/{name}/events
```

Requests must use:

```text
Authorization: Bearer <NVT_OPERATOR_CALLBACK_TOKEN>
```

The token is read from the same-namespace Secret
`<agentrun-name>-callback-token` key `NVT_OPERATOR_CALLBACK_TOKEN` and compared
without logging or echoing token material.

For event-webhook payloads, the operator resolves the lifecycle event name from
`event.plugin_event` when set, otherwise from `event.event`. Missing event names
are rejected with `400`. Unknown events are accepted as no-ops with `202`.

When the event name matches `spec.lifecycle.completeOn`, the operator sets
`status.phase=Completed`, `status.finishedAt`, and
`status.reason="Completed by lifecycle event <event-name>"`. Matching
`spec.lifecycle.failOn` sets `Failed` with the equivalent failed reason. Existing
terminal phases (`Completed`, `Failed`, `DeadlineExceeded`) are not overwritten,
and Pod status sync also avoids downgrading terminal phases.

## Active Deadline

`spec.ttl.activeDeadlineSeconds` is optional. When omitted, the run is allowed
to run indefinitely, which is the supported long-running/manual `AgentRun` mode.
When set, the controller starts enforcing it after `status.startedAt` is set.
Before the deadline expires, the reconciler requeues for the remaining duration.
After `startedAt + activeDeadlineSeconds`, the controller marks the run
`DeadlineExceeded`, sets `status.finishedAt` and a clear reason, and deletes the
owned `<agentrun-name>-agent` Pod so the workload stops. The `AgentRun` CR is
kept for status/history.

## Terminal Pod Cleanup

Completed and failed runs keep the `AgentRun` CR for status/history, but delete
the owned `<agentrun-name>-agent` Pod after the configured terminal TTL:

```yaml
ttl:
  completedTTLSeconds: 300
  failedTTLSeconds: 3600
```

`Completed` uses `completedTTLSeconds`; `Failed` uses `failedTTLSeconds`.
Lifecycle failure callbacks and Kubernetes Pod `Failed` status both stamp
`status.finishedAt`, so both failure paths are eligible for failed-Pod TTL
cleanup. If the matching TTL or `status.finishedAt` is unset, the Pod is left in
place. Before the TTL expires, the reconciler requeues for the remaining
duration. If the Pod is already gone, cleanup is treated as complete.
AgentRun CR deletion remains future work.
