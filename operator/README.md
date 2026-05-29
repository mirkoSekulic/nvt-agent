# nvt Kubernetes Operator

This directory contains the initial API contract for a future nvt Kubernetes
operator. It is intentionally API and documentation only; no controller is
implemented here yet.

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

## Scope

This directory does not include scheduler CRDs, controller code, or
GitHub-specific operator logic. Runtime plugins remain configured through the
embedded agent config under `spec.agent.config`.

Future scheduler extensions may create `AgentRun` resources, but those
extensions are separate from `AgentRun` itself and separate from runtime
plugins.
