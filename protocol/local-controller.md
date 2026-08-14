# Local controller protocol

`nvt-local-controller` owns durable lifecycle metadata and reconciliation for
local resolved agent runs. Its controller loop uses a deliberately small local
backend contract: idempotent `Ensure`, `Inspect`, and `Delete`, plus dependency
readiness. The first implementation reconciles Docker resources; later QEMU or
sandbox backends can implement the same contract without changing the run API
or `agentd`.

The local Docker backend does not change the Kubernetes `AgentRun` contract or
existing hand-written Compose agents. It is additive to the shared local
control plane.

The controller consumes only a complete, already-authorized
`nvt.resolved-agent-run/v1` value. Resolution and caller authorization happen
before this boundary. Real credentials are invalid in the resolved-run contract
and must remain in the broker and trusted egress path.

## Trust boundary

The HTTP API and Docker socket are trusted control-plane interfaces, not agent
interfaces. The Compose
service has no published host port and is attached only to the internal
`local-control-plane` network. Agent containers, the public proxy network, and
repository code are not attached to that network and never receive the host
Docker socket. A later producer or gateway
integration must authenticate and authorize requests before supplying a
resolved value; this service must not be exposed directly to untrusted clients.

Requests and responses use `application/json`. JSON decoding rejects duplicate
or unknown fields, trailing data, malformed content types, and bodies larger
than 1,088 KiB. All timestamps are UTC RFC 3339 values. Error responses contain
only a stable reason and `request denied`; raw database, configuration, and
resolved-run diagnostics are never returned.

## Run API

The version for request envelopes and responses is `nvt.local-runs/v1`.

### Create

`POST /v1/runs` accepts:

```json
{
  "api_version": "nvt.local-runs/v1",
  "idempotency_key": "opaque-request-key-1234",
  "resolved_run": {
    "contract_version": "nvt.resolved-agent-run/v1",
    "run_id": "infra"
  }
}
```

The abbreviated `resolved_run` above is illustrative; the actual value must be
complete and pass the shared resolved-run validator. A new run returns HTTP 201
and `created: true`. Replaying the same bounded idempotency key with the same
canonical resolved snapshot returns HTTP 200, the original run, and
`created: false`. Reusing the key or run ID for a different snapshot fails with
HTTP 409. A key whose deleted run is retained as a tombstone returns HTTP 410
and cannot create a second logical run.

Admission and the configured active-run limit are serialized in one SQLite
transaction. Idempotent replay is checked before capacity, so a retry remains
available while the controller is full.

### Inspect and request termination

- `GET /v1/runs/{run_id}` returns non-secret lifecycle metadata.
- `GET /v1/runs?limit=100&after={run_id}` lists visible runs in stable run-ID
  order. `limit` is 1 through 500; `next_after` continues a bounded page.
- `POST /v1/runs/{run_id}/cancel` requests `stopping`. It is idempotent for an
  already stopping or terminal run.
- `DELETE /v1/runs/{run_id}` requests `stopping` plus cleanup. Active or
  visible-terminal cleanup returns HTTP 202. Only after cleanup commits is the
  run hidden; repeated deletion of its retained tombstone returns HTTP 204.

Delete never skips backend cleanup. An active or visible terminal record enters
`stopping`; it becomes invisible only after the backend has removed the
resources selected by its retention policy and the trusted broker registration.
A repeated delete of the resulting retained tombstone returns HTTP 204. Its
idempotency tombstone remains durable.

### Reconciliation ownership and status

Reconciliation is optimistic and lease-based. A backend first calls:

`POST /v1/runs/{run_id}/claim`

```json
{
  "api_version": "nvt.local-runs/v1",
  "owner": "controller-instance-a",
  "expected_revision": 3,
  "lease_seconds": 30
}
```

The owner is an opaque, bounded controller-instance name. The claim succeeds
only for the exact current revision and when no different unexpired owner holds
the run. Claiming increments the revision. An expired lease can be replaced by
another owner. A stale owner cannot update status after takeover, cancellation,
or deletion. Controller configuration requires the claim lease to exceed the
complete backend-operation timeout by at least 30 seconds; the default is 180
seconds for a 120-second operation. Thus an idempotent `Ensure` or `Delete`
cannot outlive its ownership claim.

The owner then calls `PUT /v1/runs/{run_id}/status` with the claimed revision:

```json
{
  "api_version": "nvt.local-runs/v1",
  "owner": "controller-instance-a",
  "expected_revision": 4,
  "state": "preparing",
  "reason": "backend-started"
}
```

Reasons are optional, bounded machine-readable values. They are never raw
backend errors. A successful transition increments the revision and releases
the claim, so the next reconciliation step must claim again.

The backend boundary distinguishes only deterministic desired-state rejection
from dependency uncertainty. Unsupported local transport/kind or an ownership
collision may move `preparing` into cleanup with terminal target `failed`.
Broker startup/HTTP uncertainty, Docker/image availability, storage I/O, and
operation timeouts leave the run in `preparing` for an idempotent retry. During
`running`, a successful inspection that confirms the managed agent is absent or
stopped enters cleanup; an inspection error leaves `running` unchanged. Cleanup
errors always retain the claimable `stopping` state and retry.

A transition into cleanup also supplies the exact terminal target:

```json
{
  "api_version": "nvt.local-runs/v1",
  "owner": "controller-instance-a",
  "expected_revision": 8,
  "state": "stopping",
  "terminal_target": "failed",
  "reason": "backend-runtime-failed"
}
```

Allowed transitions are:

| From | To |
| --- | --- |
| `pending` | `preparing`, `stopping` |
| `preparing` | `running`, `stopping` |
| `running` | `stopping` |
| `stopping` | `completed`, `failed`, `expired` |

`completed`, `failed`, and `expired` are terminal. Entering `stopping` records
one immutable `terminal_target`; cleanup may report only that target. Every
other transition is rejected with HTTP 409. Backend creation failure, runtime
loss, cancellation, deadline expiry, explicit deletion, and retention cleanup
all enter this claimable cleanup state. Terminal/tombstone state is committed
only after idempotent backend cleanup succeeds. This prevents a lease or
deadline race from stranding owned Docker resources.

## Docker backend

Each run has a deterministic opaque Compose project name derived from the run
ID. The controller writes a mode-0600 `compose.yaml` below its private state
directory and creates only exact named volumes, networks, and containers whose
labels bind the controller owner, run ID, and resolved-snapshot digest. A
same-name resource without all three labels is never adopted or deleted.
Cleanup also filters by all three labels and then re-verifies each result.

The stack contains the runtime agent and, when `runtime.docker` is configured,
its private DinD service. Runs without Docker use a minimal fixed network
namespace anchor instead. Egressd, captured, transparent network initialization,
and durable CA initialization are added when mediated egress requires them. The
agent shares only that per-run network namespace; it never receives the host
socket. Workspace, runtime-home, and optional DinD data use named volumes
according to the resolved persistence policy. Bounded `expose.http` entries are
projected into deterministic proxy routes, and non-root runs use a fixed init
step to make the named workspace writable without a host bind.
Controller-owned config volumes are populated with `docker cp` tar streams, so
the Docker daemon never needs a controller-container path as a host bind.

The local backend accepts `egress.enforced: true` only with the transparent
transport, whose `NET_ADMIN` initialization captures the complete shared agent
network namespace. Enforced redirect and forward-proxy runs fail as unsupported:
proxy variables or selected URLs are not treated as network confinement. This
restriction is local-backend-specific and does not change the portable resolved
run or Kubernetes transport contracts.

Compose is used only to converge declared services; the controller never uses
Compose orphan or project-wide teardown. Cleanup enumerates resources using all
three NVT ownership labels and re-verifies them immediately before deletion, so
an unmanaged same-project container remains untouched.

The controller derives stable per-run broker identities from a private
startup-only key. Only SHA-256 token hashes and the resolved grants are written
atomically into the existing live-reloaded broker agent registry. The agent
bearer is used in controller memory only to prepare inert placeholder files and
is never mounted into the agent. The paired egress bearer is copied through
stdin into an egress-private volume and read by egressd through
`NVT_BROKER_TOKEN_FILE`; it is not present in Compose, container arguments,
environment, inspect output, or controller logs. Real provider credentials stay
inside the broker/provider and are injected only by egressd. Direct runs with
no broker grants remain valid; a credential-bearing direct run is rejected
because this backend has no zero-secret direct materialization path.

Registry replacement preserves the existing `agents.yaml` owner and group.
Controller-created lock files use the bind directory owner and group, with
mode 0600, so a root controller does not take ownership away from native Linux
Compose users.

## Durable state and recovery

SQLite is stored on the `local-controller-state` volume. The dedicated directory
must already be private or is created mode 0700; a broad or symlinked state path
fails closed without changing existing directory permissions. The database is
created mode 0600 before SQLite opens it. WAL mode with `synchronous=FULL` is used,
and creates, capacity checks, state changes, ownership changes, expiry, and
deletion are transactions.

The canonical validated resolved-run snapshot and its SHA-256 digest are stored
for deterministic in-process backend recovery. HTTP get/list/status responses
expose only the digest and bounded non-secret metadata, never the snapshot,
prompt, agent configuration, idempotency key, or backend diagnostic. The trusted
store returns a defensive copy of the snapshot only to the trusted in-process
backend reconciler.

Schema changes use explicit SQLite `user_version` migrations in the same
transaction as their DDL. Startup performs an integrity check and validates
every bounded record, snapshot digest, state, timestamp, and ownership tuple.
Unknown future schema versions, corrupt databases, invalid snapshots, and
inconsistent records fail startup as `state-unavailable`; the controller never
silently recreates or partially recovers uncertain state.

## TTL and retention

`ttl.active_seconds`, when non-zero, fixes the active deadline at creation.
Crossing it changes an active run to `stopping` with terminal target `expired`,
releases any claim, and leaves it claimable until backend cleanup completes.

For a disposable run (no persistent workspace, runtime state, or Docker data),
terminal retention is the smaller non-zero value of the state-specific
`completed_seconds`/`failed_seconds` and `run_retention_seconds`. For a
persistent run, only `run_retention_seconds` applies. Zero means no automatic
removal for that dimension. Automatic removal first enters the same cleanup
path, then hides the run and retains its idempotency tombstone.

## Health and readiness

- `GET /healthz` reports only that the process and HTTP server are alive.
- `GET /readyz` separately verifies that the durable SQLite store, Docker
  engine, and broker registry file are available.

A failed readiness check never changes or recreates state. Provider health,
runtime health, and individual run health are outside these probes.

## Configuration

All settings are startup-only and fail closed when malformed:

| Environment variable | Default | Bound |
| --- | --- | --- |
| `NVT_LOCAL_CONTROLLER_BIND` | `0.0.0.0:7480` | valid host and TCP port |
| `NVT_LOCAL_CONTROLLER_STATE` | `/state/controller/local-controller.sqlite3` | clean absolute `.sqlite3` path under a dedicated private directory |
| `NVT_LOCAL_CONTROLLER_MAX_ACTIVE_RUNS` | `32` | 1 through 10,000 |
| `NVT_LOCAL_CONTROLLER_MAX_CLAIM_LEASE_SECONDS` | `180` | backend timeout plus at least 30 seconds, through 3,600 |
| `NVT_LOCAL_CONTROLLER_SWEEP_SECONDS` | `1` | 1 through 60 |
| `NVT_LOCAL_CONTROLLER_RECONCILE_SECONDS` | `1` | 1 through 60 |
| `NVT_LOCAL_CONTROLLER_BACKEND_TIMEOUT_SECONDS` | `120` | 1 through 300 |
| `NVT_LOCAL_CONTROLLER_DOCKER_HOST` | `unix:///var/run/docker.sock` | bounded Docker endpoint |
| `NVT_LOCAL_CONTROLLER_RUNS_DIR` | `/state/controller/runs` | clean absolute private path |
| `NVT_LOCAL_CONTROLLER_BROKER_URL` | `http://broker:7347` | exact HTTP(S) endpoint; plaintext requires the resolved local-dev opt-in |
| `NVT_LOCAL_CONTROLLER_BROKER_CA_FILE` | omitted | optional absolute CA file |
| `NVT_LOCAL_CONTROLLER_BROKER_AGENTS` | `/broker-state/agents.yaml` | existing broker registry file |
| `NVT_LOCAL_CONTROLLER_IDENTITY_KEY_FILE` | `/broker-state/local-controller.key` | private regular file, 32-4096 bytes, no group/other permissions |
| `NVT_LOCAL_CONTROLLER_OWNER` | `nvt-local-controller` | stable bounded ownership label |
| `NVT_LOCAL_CONTROLLER_EXTERNAL_NETWORK` | `agents-proxy` | pre-created proxy/broker network |
| `NVT_LOCAL_CONTROLLER_PROXY_PORT` | `4090` | public local proxy port recorded in generated workspace guidance |
| `NVT_LOCAL_CONTROLLER_DIND_PROTECTED_CIDRS` | `127.0.0.0/8 169.254.0.0/16` | bounded administrator-owned protected CIDR list, validated by DinD before transparent capture |
| `NVT_LOCAL_CONTROLLER_DIND_IMAGE` | `nvt-dind:latest` | administrator image |
| `NVT_LOCAL_CONTROLLER_EGRESSD_IMAGE` | `nvt-egressd:latest` | administrator image |
| `NVT_LOCAL_CONTROLLER_CAPTURED_IMAGE` | `nvt-captured:latest` | administrator image |
| `NVT_LOCAL_CONTROLLER_SEED_IMAGE` | `nvt-agent-runtime:latest` | trusted fixed config-seed image |
