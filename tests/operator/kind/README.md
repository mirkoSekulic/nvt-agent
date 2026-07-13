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
    mediated-egress.sh    # mediated routing and admission smoke
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
For `mediated-egress`, it checks mediated admission payloads for a
header-inject grant with route hosts plus the runtimeAuth, missing-route, and
file-bundle rejection shapes.
For enforced egress, the completion smoke uses the credential-less
termination-message lifecycle path. Its acceptance scan checks provider,
broker, egress, callback, service-account, and CA-key non-possession across Pod
specs, environments, process arguments, readable files, mounts, and logs.

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

## Demo Smoke Scheduler Job

Create one in-cluster scheduler Job that submits a single smoke `AgentRun`
through the operator Service:

```sh
make operator-smoke-schedule NAME=demo-1
```

Common overrides:

```sh
make operator-smoke-schedule NAME=demo-1 CLUSTER=nvt-smoke NAMESPACE=nvt SMOKE_DELAY_SECONDS=5
```

The target renders a Kubernetes JSON Job and creates it with create-only
semantics as `smoke-scheduler-<NAME>` in the
target namespace. The Job runs inside the cluster and posts one admission
request to:

```text
http://nvt-operator:8082/v1/schedules/<namespace>/default/admissions
```

The submitted work id is `smoke:<NAME>`, and the submitted `AgentRun` uses
`metadata.name: <NAME>`, an ephemeral workspace, no broker grants, `bash -lc
'echo ready; sleep infinity'`, the `event-webhook` and `smoke-complete`
plugins, `completeOn: plugin.smoke.completed`, and a short completed Pod TTL.

This is a demo/test scheduler path for kind clusters. It is not core scheduler
logic and does not replace the reusable smoke harness cases. Reusing a previous
`NAME` fails with Kubernetes `AlreadyExists` for the existing Job instead of
updating or reusing a completed scheduler Job.

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

## Local POC Secret Setup

For the GitHub comments producer POC, create or refresh the three local/kind
Secrets before installing the charts:

For the full reproducible local GitHub producer setup, including example local
values files and the real Codex AgentRun flow, see
[`docs/local-kind-github-producer.md`](../../../docs/local-kind-github-producer.md).

```sh
make operator-codex-auth-secret
make github-comments-producer-secret GITHUB_APP_PRIVATE_KEY_FILE=/path/to/private-key.pem
make broker-env-secret BROKER_ENV_FILE=.broker/env
```

These Secrets are separate on purpose:

- `operator-codex-auth-secret` creates the Codex runtime auth Secret consumed
  by AgentRun Pods through `spec.runtimeAuth.secretName`.
- `github-comments-producer-secret` creates the GitHub App private key Secret
  consumed by `charts/nvt-github-comments-producer`.
- `broker-env-secret` creates the broker env Secret consumed by the core
  `charts/nvt` broker deployment through `broker.envSecretName`.

The producer GitHub App Secret and broker env Secret may use different GitHub
Apps later. Do not commit real private keys, `.broker/env`, or other secret
files.

With local values prepared, build, load, and install the GitHub comments
producer into the kind cluster:

```sh
make producer-kind-setup PRODUCER_VALUES=values.github-comments.yaml
```

`producer-kind-setup` runs `producer-kind-load` and `producer-kind-install`.
It does not create Secrets because the producer private key and broker env file
paths are user-provided. The local `values.github-comments.yaml` file should be
uncommitted and include the target repository, GitHub App IDs, allowed author,
broker grants, real Codex yolo runtime config, and runtime plugins.

Full local POC setup sequence:

```sh
make operator-kind-setup CREATE_CLUSTER=1
make operator-codex-auth-secret
make github-comments-producer-secret GITHUB_APP_PRIVATE_KEY_FILE=/path/to/private-key.pem
make broker-env-secret BROKER_ENV_FILE=.broker/env
make producer-kind-setup PRODUCER_VALUES=values.github-comments.yaml
```

## Cases

Select a case with `KIND_SMOKE_CASE`:

```sh
KIND_SMOKE_CASE=parallel-lifecycle make operator-kind-smoke
KIND_SMOKE_MODE=render KIND_SMOKE_CASE=parallel-lifecycle make operator-kind-smoke
KIND_SMOKE_MODE=render KIND_SMOKE_CASE=mediated-egress make operator-kind-smoke
```

The current case is `parallel-lifecycle`. It exercises this no-GitHub,
no-secret lifecycle:

```text
Helm chart -> operator + broker -> AgentSchedule admission -> AgentRun Pods ->
event-webhook + smoke-complete -> operator callback -> Completed AgentRuns ->
terminal Pod cleanup
```

The `mediated-egress` case exercises mediated wiring for one redirectable
header-inject grant:

```text
AgentSchedule admission -> mediated AgentRun -> egressd sidecar present ->
egress broker token mounted only into egressd -> mismatch admissions rejected
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
