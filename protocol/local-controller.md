# Local controller protocol

`nvt-local-controller` owns durable lifecycle metadata for local resolved agent
runs. The v1 API and state store are backend-neutral: this layer does not create
containers, volumes, routes, broker identities, or any other execution
resource. It does not change the Kubernetes `AgentRun` contract and it does not
add lifecycle responsibilities to `agentd`.

The controller consumes only a complete, already-authorized
`nvt.resolved-agent-run/v1` value. Resolution and caller authorization happen
before this boundary. Real credentials are invalid in the resolved-run contract
and must remain in the broker and trusted egress path.

## Trust boundary

The HTTP API is a trusted control-plane API, not an agent API. The Compose
service has no published host port and is attached only to the internal
`local-control-plane` network. Agent containers, the public proxy network, and
repository code are not attached to that network. A later producer or gateway
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
- `DELETE /v1/runs/{run_id}` requests `stopping` plus cleanup. Active cleanup
  returns HTTP 202. A terminal run is hidden immediately and returns HTTP 204;
  repeated deletion of its retained tombstone also returns HTTP 204.

Delete never skips backend cleanup for an active run. The record becomes
invisible only after a reconciler reports a terminal state, or immediately when
the run was already terminal. Its idempotency tombstone remains durable.

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
or deletion.

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

Allowed transitions are:

| From | To |
| --- | --- |
| `pending` | `preparing`, `stopping`, `failed`, `expired` |
| `preparing` | `running`, `stopping`, `failed`, `expired` |
| `running` | `stopping`, `completed`, `failed`, `expired` |
| `stopping` | `completed`, `failed`, `expired` |

`completed`, `failed`, and `expired` are terminal. Every other transition is
rejected with HTTP 409. This child has no execution backend, so it never advances
normal `pending` runs on its own. The deadline sweeper may atomically mark an
active run `expired`; no resource exists to clean up in this child layer.

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
store returns a defensive copy of the snapshot to a future in-process backend.

Schema changes use explicit SQLite `user_version` migrations in the same
transaction as their DDL. Startup performs an integrity check and validates
every bounded record, snapshot digest, state, timestamp, and ownership tuple.
Unknown future schema versions, corrupt databases, invalid snapshots, and
inconsistent records fail startup as `state-unavailable`; the controller never
silently recreates or partially recovers uncertain state.

## TTL and retention

`ttl.active_seconds`, when non-zero, fixes the active deadline at creation.
Crossing it changes an active run to `expired` and releases any claim.

For a disposable run (no persistent workspace, runtime state, or Docker data),
terminal retention is the smaller non-zero value of the state-specific
`completed_seconds`/`failed_seconds` and `run_retention_seconds`. For a
persistent run, only `run_retention_seconds` applies. Zero means no automatic
removal for that dimension. Automatic removal hides the run but retains its
idempotency tombstone.

## Health and readiness

- `GET /healthz` reports only that the process and HTTP server are alive.
- `GET /readyz` separately verifies that the durable SQLite store is available.

A failed readiness check never changes or recreates state. Provider health,
runtime health, and future backend resource health are outside these probes.

## Configuration

All settings are startup-only and fail closed when malformed:

| Environment variable | Default | Bound |
| --- | --- | --- |
| `NVT_LOCAL_CONTROLLER_BIND` | `0.0.0.0:7480` | valid host and TCP port |
| `NVT_LOCAL_CONTROLLER_STATE` | `/state/controller/local-controller.sqlite3` | clean absolute `.sqlite3` path under a dedicated private directory |
| `NVT_LOCAL_CONTROLLER_MAX_ACTIVE_RUNS` | `32` | 1 through 10,000 |
| `NVT_LOCAL_CONTROLLER_MAX_CLAIM_LEASE_SECONDS` | `30` | 1 through 3,600 |
| `NVT_LOCAL_CONTROLLER_SWEEP_SECONDS` | `1` | 1 through 60 |
