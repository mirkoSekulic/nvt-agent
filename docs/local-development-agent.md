# Native local workstations

`nvt-local-controller` creates persistent local workstations and disposable
producer runs from one administrator-owned YAML file.

## Configure

Build the trusted images, copy the example, and edit only non-secret policy:

```sh
make runtime-build dind-build broker-build local-controller-build gateway-build egressd-build captured-build
mkdir -p .broker
cp templates/local-controller.yaml .broker/local-controller.yaml
```

The top-level profiles, workflows, execution backends, and retention policies
are reusable. A persistent workstation selects them by name:

```yaml
workstations:
  - name: nvt
    principal:
      issuer: https://local.nvt.invalid
      subject: workstation-nvt
      display_name: NVT development
    profile: engineering
    workflow: nvt-development
    retention: persistent
    backend: local-docker
```

The `name` is the durable run and route identity. Principal authorization uses
exact issuer plus immutable subject; display name is presentation only.
Producer schedules in the same document select the same profiles/workflows and
use private bearer files by reference. Producers cannot submit profiles,
providers, grants, repositories, runtime controls, retention, or backend
settings.

Provider implementations and credential values stay in `.broker/broker.yaml`
and broker-owned credential state. The local platform file contains only
provider references, broker grants/capabilities, repository identifiers, and
non-secret runtime/egress policy. Never place tokens, passwords, private keys,
credential documents, or credential-bearing command arguments in it.

The checked-in template is an intentionally credential-free direct example.
Replace its illustrative shell profile with reviewed broker-backed mediated
profiles for real Codex, Claude, GitHub App, or PAT use. The shared resolved-run
contract is provider-neutral; the local controller has no provider branches.

## Start and operate

```sh
make infra-up
```

`infra-up` detects `.broker/local-controller.yaml` and supplies its read-only
in-container path. Open stable routes such as:

```text
http://localhost:4090/agents/nvt/
http://nvt.agent.localhost:4090/
```

Optional local credential management is described in
[`local-credential-portal.md`](local-credential-portal.md). It adds the existing
credential portal to the gateway without giving credentials to the gateway,
controller, producer, or agent containers.

Every workstation uses `/workspace` inside the agent, matching the Kubernetes
runtime contract.

Adding a workstation and restarting the controller creates it atomically.
Unchanged entries replay idempotently. Workspace, runtime/session state, Docker
data, and route identity survive controller, agent-container, and ordinary
Docker daemon/Desktop restarts; the runtime uses its generic `resume` command.

Removing an entry from YAML never stops or deletes the existing run. Destructive
cleanup requires the separately authenticated controller delete API. This
prevents an accidental configuration edit from deleting retained volumes.
Changing the resolved profile/workflow/policy for an existing name is immutable
drift and fails startup; explicitly delete and recreate when that is intended.

The raw management, exact-schedule producer, and gateway route-reader APIs use
separate credentials and cannot be substituted for one another. Agent
containers receive neither the Docker socket nor controller credentials.

## Troubleshooting

- `workstation-configuration-unavailable`: validate the YAML API version,
  references, duplicate names, persistent retention, and immutable drift.
- `backend-unavailable`: verify Docker, broker, gateway, images, and configured
  network ranges.
- A run in `preparing` is retried after dependency recovery. A confirmed
  ownership conflict remains fail closed and is never adopted or deleted.
- Do not delete or prune the controller state and named Docker volumes when
  testing restart recovery.

The normative configuration, API, recovery, and cleanup rules are in
[`protocol/local-controller.md`](../protocol/local-controller.md).
