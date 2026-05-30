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
- `config/broker/broker.yaml`: local/kind broker Deployment, Service, and
  ConfigMaps for POC clusters
- `examples/agentrun-basic.yaml`: example disposable agent run
- `docs/agentrun.md`: API and intended v1 behavior notes
- `cmd/manager`: controller-runtime manager entrypoint
- `internal/controller`: AgentRun reconciler

## Scope

The current controller initializes empty `status.phase` values to `Pending`,
renders `spec.agent.config` into an owned ConfigMap named
`<agentrun-name>-agent-config` with the `agent.yaml` key, creates stable
per-run broker and callback token Secrets, and creates one owned Pod named
`<agentrun-name>-agent`. The Pod runs the configured agent image next to a
native Kubernetes sidecar-style init container for Docker-in-Docker, mounts the
rendered config at `/nvt-agent/agent.yaml`, wires token Secrets into the agent
container environment, and uses an ephemeral `emptyDir` workspace. The agent
container starts after the DinD startup probe can run `docker info`.

The controller syncs basic Pod-phase status only: it records `status.podName`,
sets `Running` and `startedAt` when the Pod is running, and sets `Failed` when
the Pod fails. Broker policy registration, callback HTTP endpoints, lifecycle
completion rules, and TTL cleanup remain intentionally future work.

This directory does not include scheduler CRDs or GitHub-specific operator
logic. Runtime plugins remain configured through the embedded agent config under
`spec.agent.config`.

Future scheduler extensions may create `AgentRun` resources, but those
extensions are separate from `AgentRun` itself and separate from runtime
plugins.

## Broker POC Manifests

`config/broker/broker.yaml` installs a service-internal broker for local/kind
POCs:

```sh
kubectl create secret generic nvt-broker-env \
  --from-literal=GITHUB_APP_ID='<app-id>' \
  --from-literal=GITHUB_APP_INSTALLATION_ID='<installation-id>' \
  --from-literal=GITHUB_APP_PRIVATE_KEY_BASE64='<base64-private-key>'

kubectl apply -f config/broker/broker.yaml
```

The Secret is intentionally not committed. The manifest expects these keys when
the example GitHub App provider is enabled in `nvt-broker-config`:

```text
GITHUB_APP_ID
GITHUB_APP_INSTALLATION_ID
GITHUB_APP_PRIVATE_KEY_BASE64
```

Broker providers are static in `broker.yaml`. Dynamic agent identities and
grants live in `agents.yaml`; for the POC, `agents.yaml` is the
`nvt-broker-agents` ConfigMap mounted into the broker, matching the local
`.broker/agents.yaml` model.

Kubernetes projected ConfigMap updates are eventually reflected in mounted
files, and the broker already live-reloads its agents policy file locally. The
kind POC should verify this mounted ConfigMap live-reload path before the
operator starts writing broker agent policy.

AgentRun Pods already receive `NVT_BROKER_URL=http://nvt-broker:7347`. The
operator does not update the broker agents ConfigMap yet; hashing AgentRun
broker tokens into `agents.yaml` is the next slice.
