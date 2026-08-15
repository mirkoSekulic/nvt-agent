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

The raw run API consumes only a complete, already-authorized
`nvt.resolved-agent-run/v1` value. The optional scheduling API instead resolves
an administrator-authorized selection itself from the same shared contract.
Real credentials are invalid in the resolved-run contract
and must remain in the broker and trusted egress path.

## Trust boundary

The Docker socket and raw management API are trusted control-plane interfaces,
not agent interfaces. The Compose
service has no published host port and is attached only to the internal
`local-control-plane` network. Agent containers, the public proxy network, and
repository code are not attached to that network and never receive the host
Docker socket. The gateway and producer integrations remain on this private
network; this service must not be exposed directly to browser or repository
traffic. Network privacy is not an authorization boundary: every supported
non-health API request is authenticated for exactly one audience.

Three credentials are deliberately non-interchangeable. A producer token is
bound to one configured schedule and authorizes only that schedule's
admission/status/cancel endpoints. The gateway route token authorizes only
bounded `GET /v1/routes` metadata. A separately mounted administrator token
authorizes only `/v1/runs` create/list/get/cancel/delete/claim/status. Missing,
wrong, duplicated, or cross-audience bearer values are rejected before request
body decoding or state access. Startup rejects reuse of a token across any two
audiences. Omitting the administrator token disables the raw management API;
the gateway never receives that token or the producer tokens.

Each local run receives unique exact-owned internal/private Docker networks.
The untrusted agent network namespace never joins `agents-proxy` or another
run's network. The controller verifies the configured gateway container's
fixed trust label, running state, and configured healthy state before attaching
that container to the run-internal network; failure, non-running state,
unhealthy state, or an ownership mismatch leaves the run unavailable. Cleanup
requires only the fixed identity label, so it can safely detach a stopped or
unhealthy gateway before exact-owned network removal. No per-run Traefik router or
agent-reachable private proxy entrypoint participates in authorization.

Requests and responses use `application/json`. JSON decoding rejects duplicate
or unknown fields, trailing data, malformed content types, and bodies larger
than 1,088 KiB. All timestamps are UTC RFC 3339 values. Error responses contain
only a stable reason and `request denied`; raw database, configuration, and
resolved-run diagnostics are never returned.

## Run API

The version for request envelopes and responses is `nvt.local-runs/v1`.

The administrator-authenticated raw run API consumes only a complete,
already-authorized value. It is disabled when
`NVT_LOCAL_CONTROLLER_ADMIN_TOKEN_FILE` is omitted. The bounded
controller-to-gateway route API is documented separately in
[`local-routes.md`](local-routes.md). It exposes active non-secret route and
readiness metadata only; gateway authorization never moves into the controller.

### Trusted producer scheduling

Dynamic scheduling is disabled when `NVT_LOCAL_CONTROLLER_SCHEDULING_CONFIG`
is omitted. When enabled, the referenced canonical absolute JSON file uses
`nvt.local-scheduling/v1` and contains one shared `resolved_run_config` plus
bounded `schedules`, administrator-owned `local_runs`, or both. Each producer policy binds an administrator identity and
private bearer-token file to exact allowed principal issuers,
workflow-to-profile selections, one default workflow, retention policy, and
execution backend. The token file must be a private regular file (no
group/other permissions), 32-4096 bytes. Its contents are hashed at startup and
never logged, returned, or stored in SQLite.

The policy shape is intentionally small (the `resolved_run_config` value is the
complete contract documented in `resolved-agent-run.md`):

```json
{
  "api_version": "nvt.local-scheduling/v1",
  "resolved_run_config": {},
  "schedules": [{
    "name": "github",
    "producers": [{
      "identity": "github-comments",
      "token_file": "/run/secrets/nvt-local-controller/producer-token",
      "allowed_principal_issuers": ["https://github.com"],
      "selections": [{"profile": "engineering", "workflow": "review-pr"}],
      "default_workflow": "review-pr",
      "retention": "disposable",
      "backend": "container"
    }]
  }]
}
```

Named local workstations use the same resolver without exposing the raw-run
administrator API. Each entry contains only an immutable principal and the
trusted profile/workflow/retention/backend selection:

```json
{
  "local_runs": [{
    "run_id": "nvt-dev",
    "principal": {"issuer": "https://local.nvt.invalid", "subject": "workstation-nvt-dev"},
    "profile": "nvt-dev",
    "workflow": "nvt-dev",
    "retention": "persistent",
    "backend": "local-docker"
  }]
}
```

At startup the controller resolves and creates these selections through the
same immutable contract. Replay after restart is idempotent. Changing the
resolved value for an existing run ID fails startup as configuration drift;
the controller never silently rewrites an existing run or its provenance.
The migration tool described in [local controller migration](../docs/local-controller-migration.md)
generates this document without copying provider configuration or credential
values.

The empty object above is only a placeholder; startup rejects an incomplete
resolved-run configuration. Mount the policy and token directory read-only
into the controller and set the scheduling-config environment variable to the
in-container policy path.

The existing GitHub comments profiled-admission payload is accepted at
`POST /v1/schedules/{schedule}/admissions`. It contains only work metadata,
prompt, immutable principal issuer+subject, display-only name, and an optional
workflow. Strict decoding rejects attempts to supply a profile, resolved run,
provider, grant, repository checkout, image, plugin, runtime, retention,
capability, or egress setting. The authenticated policy maps the workflow to an
exact authorized profile before the shared resolver runs, so denial happens
before durable state or Docker resources exist.

The idempotency key and local run ID are deterministic hashes of the schedule,
administrator producer identity, and producer work ID. An identical retry
returns HTTP 202 with `duplicate-work`; serialized active-run capacity returns
HTTP 429 with `max-parallelism-reached`. Stable policy denials use bounded 403
reasons. Malformed input, resolution failure, state uncertainty, and dependency
failure fail closed without backend fallback. Existing reaction/comment
handling remains advisory because these are the same authoritative scheduling
outcomes used by Kubernetes admission.

Authenticated status and cancellation avoid placing work IDs in path segments:

- `GET /v1/schedules/{schedule}/work?work_id={exact-work-id}`;
- `POST /v1/schedules/{schedule}/work/cancel?work_id={exact-work-id}`.

Cancellation and deadlines enter the existing durable `stopping` cleanup path.
TTL and retention come only from the selected administrator policy.

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

The owner is an opaque, bounded controller-instance name generated from fresh
randomness at each process start. It is deliberately distinct from the stable
administrator-configured Docker resource-label owner, so two live controller
processes with identical deployment configuration cannot share or immediately
reclaim one lease. The claim succeeds
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
| `running` | `preparing` during controller startup recovery, `stopping` |
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
Compose orphan or project-wide teardown. Before `up --no-recreate`, the
controller enumerates every existing container for the project and refuses to
invoke Compose if a declared service lacks the exact three NVT ownership
labels. It repeats the ownership check after convergence. Cleanup enumerates
resources using all three labels and re-verifies them immediately before
deletion, so unmanaged same-project orphan and declared-service containers
remain untouched.

The backend creates both per-run networks itself from deterministic `/28`
candidates within the administrator-owned run-network pool. Bounded probing
handles occupied subnets, while an existing named network must retain exact
ownership labels and a subnet inside the configured pool. The pool must not
overlap the reserved `172.30.0.0/15` DinD range or any administrator-declared
IPv4 protected CIDR, and must contain at least two subnets per configured
active run. Mixed IPv4/IPv6 protected lists remain supported; IPv6 ranges do
not conflict with the IPv4 run pool. Compose's default network is explicitly
mapped to the owned internal network, so Compose cannot create an unmanaged
project network.

At each controller process start, every durable `running` record is moved back
to `preparing` with reason `backend-recovery-requested`. Its immutable snapshot
is then rendered again and reconciled with `up --no-recreate`. Existing exact-
owned containers are retained, stopped services are started, and missing
ephemeral containers are recreated under the same run ID, project, routes, and
named volumes. A successful pass returns to `running` with reason
`backend-recovered`. `pending`, already `preparing`, `stopping`, and terminal
records retain their existing restart-safe semantics.

The runtime home volume contains `NVT_STATE_DIR`. When the administrator's
generic agent configuration includes `runtime.resume.command` and optional
`runtime.resume.args`, the existing runtime startup contract writes its durable
non-secret session marker only after the first session is established. A
recreated agent container therefore selects the generic resume command when the
marker exists and the normal command when it does not. The local controller,
Docker backend, runtime core, and `agentd` contain no provider-specific resume
branches.

Runtime inspection distinguishes an active/healthy process, bounded startup
uncertainty, successful exit, and failed/OOM exit. Confirmed successful and
failed exits enter the ordinary claimable cleanup path with reasons
`backend-completed` and `backend-runtime-failed`; raw container diagnostics are
never persisted or logged.

The Docker backend also observes the append-only agentd event log through the
already-owned agent container. The in-container reader discards payloads and
returns at most 1,024 bounded event names plus an opaque file-generation/byte
cursor per pass. The trusted backend compares only those names with the
resolved `lifecycle.complete_on` and `lifecycle.fail_on` sets. A match produces
the same bounded completed/failed observation and cleanup path as a confirmed
runtime exit; unrelated events only advance the cursor. A configured matching
event is authoritative over a later process exit or OOM result: `fail_on`
followed by exit 0 remains failed, and `complete_on` followed by a nonzero exit
remains completed.

For an exact-owned stopped agent, the backend does not restart or execute the
mutable agent container. It first verifies the deterministic runtime-home
volume's exact owner/run/digest labels, then mounts that volume read-only into
the administrator-configured trusted seed image. The short-lived reader runs
as root with no network, capabilities, writable root, Docker socket, broker
identity, portal/config secrets, or credential-bearing environment. A missing
or ownership-conflicting volume and any helper uncertainty fail closed before
process-exit classification.

The cursor is private non-secret SQLite state (maximum 256 ASCII token bytes),
not part of the local-run API, logs, or resolved snapshot. Cursor advancement
and a terminal transition are committed under the reconciliation lease. A
controller crash before commit may replay bounded event names, while a commit
prevents old events from becoming newly terminal after restart. Missing,
replaced, truncated, malformed, oversized, or ambiguous event logs fail closed
as backend uncertainty. Event payloads and raw records never cross the Docker
boundary or enter controller persistence/diagnostics. This observation belongs
to the local backend; `agentd` remains unchanged and owns only append/event I/O.

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
Compose users. Registry flock acquisition is nonblocking with bounded retry and
the backend operation context; a held static-agent lock therefore yields a
retryable operation before the claim lease can expire.

Every ensure pass prunes only obsolete containers, networks, and volumes that
carry the exact owner/run/digest labels for that same durable snapshot.
Unmanaged, partial-label, ownership-conflicting, and other-run objects are not
adopted or removed. Cleanup removes all exact-owned containers and routes,
broker and paired-egress identities, per-run networks, generated config/egress
volumes, and the private generated Compose directory. Workspace, runtime-home,
and DinD data volumes survive terminal cleanup only when the resolved
persistence policy explicitly retains them; explicit deletion removes those
retained volumes too. Every step is bounded and idempotent, so a crash during
create or delete resumes from the durable `preparing` or `stopping` record.
Before deleting each deterministic expected network or removable volume, the
backend inspects that exact name. Missing is already clean, exact owner/run/
digest labels permit deletion, and any partial or mismatched label set remains
untouched while cleanup stays retryable. Exact-label inventory is used only to
remove additional stale owned objects.

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
| `NVT_LOCAL_CONTROLLER_MAX_ACTIVE_RUNS` | `32` | 1 through 500, matching the bounded complete route-consumer contract |
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
| `NVT_LOCAL_CONTROLLER_OWNER` | `nvt-local-controller` | stable bounded Docker ownership label; not the per-process lease identity |
| `NVT_LOCAL_CONTROLLER_EXTERNAL_NETWORK` | `agents-proxy` | pre-created proxy/broker network |
| `NVT_LOCAL_CONTROLLER_RUN_NETWORK_POOL` | `100.64.0.0/10` | canonical IPv4 pool, at least two `/28`s per active run, disjoint from `172.30.0.0/15` and every protected IPv4 CIDR |
| `NVT_LOCAL_CONTROLLER_PROXY_PORT` | `4090` | public local proxy port recorded in generated workspace guidance |
| `NVT_LOCAL_CONTROLLER_ROUTE_BASE_DOMAIN` | `agent.localhost` | canonical lower-case DNS suffix for local run hosts |
| `NVT_LOCAL_CONTROLLER_ROUTE_PATH_PREFIX` | `/agents` | canonical stable gateway path prefix |
| `NVT_LOCAL_CONTROLLER_GATEWAY_CONTAINER` | `nvt-local-gateway` | fixed trusted gateway container; it must carry `nvt.dev/local-gateway=true` and is attached to exact-owned run networks |
| `NVT_LOCAL_CONTROLLER_SCHEDULING_CONFIG` | omitted | optional canonical absolute `nvt.local-scheduling/v1` schedules/named-runs file; omission disables both |
| `NVT_LOCAL_CONTROLLER_ADMIN_TOKEN_FILE` | omitted | optional private regular 32-4096 byte bearer file; omission disables all raw `/v1/runs` management operations |
| `NVT_LOCAL_CONTROLLER_ROUTE_TOKEN_FILE` | none | required private regular 32-4096 byte gateway route-reader bearer file |
| `NVT_LOCAL_CONTROLLER_DIND_PROTECTED_CIDRS` | `127.0.0.0/8 169.254.0.0/16` | bounded canonical mixed-family prefixes, validated at startup and by DinD; IPv4 ranges must be disjoint from the run-network pool |
| `NVT_LOCAL_CONTROLLER_DIND_IMAGE` | `nvt-dind:latest` | administrator image |
| `NVT_LOCAL_CONTROLLER_EGRESSD_IMAGE` | `nvt-egressd:latest` | administrator image |
| `NVT_LOCAL_CONTROLLER_CAPTURED_IMAGE` | `nvt-captured:latest` | administrator image |
| `NVT_LOCAL_CONTROLLER_SEED_IMAGE` | `nvt-agent-runtime:latest` | trusted fixed config-seed image |
