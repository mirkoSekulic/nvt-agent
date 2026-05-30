# nvt Kubernetes Operator

This directory contains the initial API contract and controller scaffold for the
nvt Kubernetes operator.

The first resource is `AgentRun`:

```text
apiVersion: nvt.dev/v1alpha1
kind: AgentRun
```

`AgentRun` is the generic execution unit for one disposable nvt agent run. It
does not know whether it was created manually, by GitOps, by a scheduler, or by
some future extension.

## Files

- `config/crd/bases/nvt.dev_agentruns.yaml`: v1alpha1 CRD manifest
- `examples/agentrun-basic.yaml`: example disposable agent run
- `docs/agentrun.md`: API and intended v1 behavior notes
- `cmd/manager`: controller-runtime manager entrypoint
- `internal/controller`: AgentRun reconciler

## Scope

The current controller initializes empty `status.phase` values to `Pending`,
renders `spec.agent.config` into an owned ConfigMap named
`<agentrun-name>-agent-config` with the `agent.yaml` key, and creates one owned
Pod named `<agentrun-name>-agent`. The Pod runs the configured agent image next
to a Docker-in-Docker sidecar, mounts the rendered config at
`/nvt-agent/agent.yaml`, and uses an ephemeral `emptyDir` workspace.

The controller syncs basic Pod-phase status only: it records `status.podName`,
sets `Running` and `startedAt` when the Pod is running, and sets `Failed` when
the Pod fails. Broker token registration, operator callbacks, lifecycle
completion rules, and TTL cleanup remain intentionally future work.

This directory does not include scheduler CRDs or GitHub-specific operator
logic. Runtime plugins remain configured through the embedded agent config under
`spec.agent.config`.

Future scheduler extensions may create `AgentRun` resources, but those
extensions are separate from `AgentRun` itself and separate from runtime
plugins.
