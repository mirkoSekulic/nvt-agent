# Operator kind smoke harness

This folder contains reusable kind smoke-test plumbing for the nvt Kubernetes
operator. The harness is intentionally case-oriented so future tests can add new
scenarios without expanding one large script.

```text
tests/operator/kind/
  smoke.sh                # entrypoint and case runner
  lib.sh                  # shared HTTP/assert/wait helpers
  agentrun-payload.py     # no-GitHub AgentSchedule admission payload renderer
  cases/
    parallel-lifecycle.sh # current smoke case
```

## Modes

Use render mode for cheap local or CI validation without a Kubernetes cluster:

```sh
make operator-kind-smoke-render
KIND_SMOKE_MODE=render make operator-kind-smoke
```

Render mode validates the Helm chart render/lint path and case-specific payload
generation. For `parallel-lifecycle`, it checks deterministic `metadata.name`,
the per-run event-webhook callback URL, callback token env wiring,
`smoke-complete`, and `completeOn: plugin.smoke.completed`.

Use kind mode for the full cluster smoke:

```sh
make operator-kind-smoke
KIND_SMOKE_MODE=kind make operator-kind-smoke
```

`KIND_SMOKE_MODE=kind` is the default.

The reusable kind environment setup is exposed through Make targets:

```sh
make operator-kind-cluster
make operator-kind-images
make operator-kind-install OPERATOR_KIND_HELM_ARGS='--set agentSchedule.maxParallelism=3'
make operator-kind-setup OPERATOR_KIND_HELM_ARGS='--set agentSchedule.maxParallelism=3'
make operator-kind-delete
```

Future kind cases should call `operator-kind-setup` with only their
case-specific Helm args, then keep scenario assertions in the case file.

## Real Codex Auth Secret

For local/dev testing of a real Codex `AgentRun`, create or refresh a
same-namespace Secret from your local Codex auth directory:

```sh
make operator-codex-auth-secret
```

Defaults:

```text
SOURCE=$HOME/.codex
CODEX_AUTH_SOURCE=$SOURCE
NAMESPACE=nvt
SECRET=codex-auth
CODEX_AUTH_SECRET=$SECRET
CLUSTER=nvt-smoke
KUBECTL_CONTEXT=kind-$(CLUSTER)
```

Override values as needed:

```sh
make operator-codex-auth-secret CODEX_AUTH_SOURCE=$HOME/.nvt/k8s-auth/codex CODEX_AUTH_SECRET=codex-auth NAMESPACE=nvt CLUSTER=nvt-smoke
```

This filters the current local Codex auth material to `auth.json`,
`config.toml`, and `installation_id` before creating the Kubernetes Secret.
It intentionally excludes logs, SQLite state, sessions, cache, skills, shell
snapshots, history, tmp files, and other large runtime data. Re-run the helper
after refreshing local Codex auth. The operator references the Secret through
`spec.runtimeAuth.secretName`; it never reads host paths.

```yaml
spec:
  runtime:
    type: codex
    autonomy: trusted-local
  runtimeAuth:
    secretName: codex-auth
```

For `codex`, the mount path defaults to `/root/.codex`. The Secret is mounted
read-only into a copy init container, copied into a writable `emptyDir`, and the
writable home is mounted into the agent container only. Runtime auth is not
mounted into the DinD sidecar. This is POC/local-dev auth, separate from broker
Secrets; production auth may use API keys or another Secret provisioning model
later.

## Cases

Select a case with `KIND_SMOKE_CASE`:

```sh
KIND_SMOKE_CASE=parallel-lifecycle make operator-kind-smoke
KIND_SMOKE_MODE=render KIND_SMOKE_CASE=parallel-lifecycle make operator-kind-smoke
```

The current case is `parallel-lifecycle`. It exercises this no-GitHub,
no-secret lifecycle:

```text
Helm chart -> operator + broker -> AgentSchedule admission -> AgentRun Pods ->
event-webhook + smoke-complete -> operator callback -> Completed AgentRuns ->
terminal Pod cleanup
```

Future cases can be added under `tests/operator/kind/cases/`, for example:

- `single-lifecycle.sh`
- `broker-policy.sh`
- `scheduler-admission.sh`
- `github-issue-scheduler.sh`

Each case should define:

```sh
case_validate_config
case_render
case_kind_setup
case_run
```

Keep reusable cluster/image/chart setup in the Makefile, keep generic runtime
helpers in `lib.sh`, and keep scenario-specific names, payload
assertions, admission expectations, and lifecycle waits in the case file.

## Full Kind Prerequisites

- Docker
- kind
- kubectl
- Helm
- curl
- Python 3

The AgentRun Pod starts a privileged Docker-in-Docker sidecar, so the local kind
environment must allow privileged Pods. This is a local smoke test, not a
production security model.

## Configuration

Useful environment variables:

```text
KIND_SMOKE_MODE=kind
KIND_SMOKE_CASE=parallel-lifecycle
CLUSTER=nvt-smoke
NAMESPACE=nvt
PARALLELISM=3
COMPLETED_TTL_SECONDS=10
ACTIVE_DEADLINE_SECONDS=600
CREATE_CLUSTER=1
DELETE_CLUSTER=0
SMOKE_DELAY_SECONDS=10
PORT_FORWARD_PORT=18082
```

By default the script creates the kind cluster if missing and leaves it in place
for debugging. Set `DELETE_CLUSTER=1` to remove it on exit.

## What `parallel-lifecycle` Validates

Render mode validates:

- Helm chart rendering and linting.
- Smoke AgentRun admission payload generation.

Full kind mode validates:

- Local runtime, broker, and operator images build and load into kind.
- The core Helm chart installs successfully.
- Broker and operator Deployments become available.
- `AgentSchedule` accepts `PARALLELISM` deterministic no-GitHub AgentRuns.
- An additional active admission is rejected with
  `max-parallelism-reached`.
- Each AgentRun reaches `Running` or directly `Completed`, then `Completed`.
- `event-webhook` forwards `plugin.smoke.completed` from `smoke-complete` to
  the operator callback endpoint.
- Completed AgentRun Pods are deleted after the configured completed TTL.

## Limitations

- No GitHub access, scheduler plugin, external ingress, Flux HelmRelease,
  production auth, or broker admin API is included.
- This uses cluster-internal operator HTTP callbacks and local kind networking.
- Full kind mode assumes privileged DinD support in kind.
