# Guest runtime identity protocol

Status: v1 contract.

This document defines authentication and rotation for the opaque control-plane
identity returned by [`nvt.guest-enrollment/v1`](guest-enrollment.md). It is
provider-neutral. The identity is not a cloud/provider credential, an egress
identity, a gateway routing credential, or an AgentRun field.

## Trust and storage boundary

- The broker issuer is authoritative for the exact enrollment binding and the
  identity's issuance and expiry windows.
- The native guest is the only bearer. It authenticates directly to the broker
  over an administrator-trusted TLS connection.
- The identity and any proposed successor are sensitive bearer material. They
  MUST NOT enter AgentRun/AgentSchedule objects, execution-driver desired
  state/fingerprints, provider state, status, events, logs, audit attributes,
  diagnostics, image layers, or Helm values.
- The broker persists only `sha256:<lowercase hex>` digests and non-secret
  binding/lifecycle metadata. It MUST NOT persist either plaintext identity.
  Each enrollment lifecycle also retains a bounded digest-only predecessor
  history so no identity previously used by that lifecycle can be revived.
- Execution-scope or exact-binding revocation invalidates whichever rotated
  identity is current. Rotation does not change cleanup ownership.

The v1 contract identifier is `nvt.guest-runtime-identity/v1`. The existing
bearer type remains `nvt.runtime-identity/v1`.

## Exact binding

Every operation repeats the complete enrollment binding:

```json
{"agent_run_uid":"uid","execution_id":"execution","driver_registration":"driver","desired_generation":1,"guest_instance_id":"guest"}
```

All five fields compare byte-for-byte with the durable record. A valid bearer
cannot be moved to another run, generation, registration, or guest instance.

## Authentication and status

`POST /v1/guest-runtime-identity/status` uses
`Authorization: Bearer <current-runtime-identity>` and this body:

```json
{"contract_version":"nvt.guest-runtime-identity/v1","binding":{"agent_run_uid":"uid","execution_id":"execution","driver_registration":"driver","desired_generation":1,"guest_instance_id":"guest"}}
```

Success proves that the exact identity is current, active, unexpired, and
bound to the request. The response contains no bearer material:

```json
{"contract_version":"nvt.guest-runtime-identity/v1","identity_type":"nvt.runtime-identity/v1","binding":{"agent_run_uid":"uid","execution_id":"execution","driver_registration":"driver","desired_generation":1,"guest_instance_id":"guest"},"issued_at":"2026-07-28T12:00:00Z","expires_at":"2026-07-28T13:00:00Z"}
```

## Atomic rotation

The guest creates a fresh canonical 256-bit successor with a cryptographically
secure random source. `POST /v1/guest-runtime-identity/rotate` authenticates
with the current identity in the Authorization header and sends:

```json
{"contract_version":"nvt.guest-runtime-identity/v1","binding":{"agent_run_uid":"uid","execution_id":"execution","driver_registration":"driver","desired_generation":1,"guest_instance_id":"guest"},"successor":"<43-character unpadded base64url value>"}
```

The broker performs one durable compare-and-swap transaction:

1. require a healthy store and validate the indexed exact active predecessor
   plus its bounded lifecycle history;
2. reject an expired/revoked identity, wrong binding, reused successor, or
   identity digest currently or historically owned by any record;
3. add the predecessor digest to history and replace the current digest with
   the successor digest atomically;
4. assign a broker-owned canonical issuance/expiry window; and
5. commit before returning the non-secret status response above.

Exactly one concurrent rotation from a predecessor can commit. Once committed,
the predecessor cannot authenticate and it can never be selected as a later
successor. A successful response never echoes the successor.

History is bounded to 20,000 predecessor digests per enrollment. The issuer
reserves that complete allowance atomically when it admits the enrollment; if
the configured aggregate capacity cannot fund another complete allowance,
issue fails with `capacity-exceeded` before returning an envelope. If the
one-time enrollment expires before exchange, the issuer atomically releases
the complete unused reservation while retaining the expired enrollment record
and its replay semantics. After a runtime identity has been issued, only
exact-binding or execution-scope revocation releases the reservation; that
operation also deletes the corresponding current identity and history. An
admitted live lifecycle therefore cannot lose its promised renewal budget to
another lifecycle, and live history is never evicted to admit a rotation. The
production default
aggregate capacity is 2,000,000 predecessor records (100 complete lifecycle
reservations); administrators may configure a bounded value from 20,000 to
10,000,000 and must size durable storage accordingly.

The enrollment row durably stores its reservation and used count. Rotation
increments that count in the same transaction as predecessor insertion and the
current-identity compare-and-swap. Indexed digest membership rejects replay;
normal status and rotation never enumerate predecessor history. Startup and
explicit recovery stream a complete integrity sweep, while steady readiness
and maintenance validate bounded metadata and do not deserialize fleet history.
Schema migration cannot reconstruct historical digests: an already-consumed
pre-history record remains usable for status but rotation fails closed until
the orchestrator revokes and re-enrolls that binding. Early schema-v4 review
stores retain and validate every history row, reserve a complete allowance for
each history-capable issued or consumed lifecycle, assign no allowance to an
already-expired never-consumed record, and discard only the obsolete first-come
global counter. Migration fails closed if the configured aggregate cannot fund
the live reservations; no predecessor record is evicted.

The production identity window is one hour. A compliant guest implementation
SHOULD rotate no more often than every 30 minutes and MUST finish before expiry. The
20,000-entry allowance covers at least 365 days (about 416 days) only when the
guest follows that planning interval; the broker does not enforce a minimum
time between rotations. The guest must durably count
committed rotations, resolving ambiguous responses before advancing its count.
The administrator/orchestrator must schedule controlled replacement before the
allowance is exhausted: provision a new guest instance binding, complete its
one-time enrollment, then revoke and clean up the old exact binding. Unbounded
rotation of one binding is deliberately unsupported; silent history eviction
would revive predecessor replay.

### Ambiguous response recovery

The guest MUST retain the predecessor and the one proposed successor until the
outcome is resolved. After a timeout, disconnect, process restart, or response
loss it MUST NOT generate or submit a new successor blindly:

1. call `status` with the already-known successor and exact binding;
2. if it succeeds, retain the successor and erase the predecessor;
3. if the successor is unauthorized, call `status` with the predecessor;
4. if the predecessor succeeds, retry `rotate` with the same successor;
5. if neither authenticates, fail closed and require control-plane recovery.

The broker never stores plaintext material for recovery. Recovery works because
the guest already knows both candidates and the broker durably stores exactly
one current digest.

## Revocation, restart, and expiry

Broker restart reconstructs authentication solely from the durable current
digest, predecessor digest history, exact binding, and lifecycle timestamps.
Process memory is not part of correctness. Existing exact-binding and
execution-scope revocation delete the record containing the current digest and
its history, regardless of rotation count. Runtime expiry is broker-owned; a
caller cannot extend it. Wall-clock rollback MUST NOT create a persisted window
rejected by durable validation.

## Framing and failures

Requests and responses use strict UTF-8 JSON objects. Unknown or recursively
duplicate keys, trailing JSON, non-canonical base64url, invalid timestamps, and
over-limit input fail closed. Status requests are limited to 4 KiB; rotation
requests and responses are limited to 16 KiB. Broker connection, TLS/header,
body, concurrency, rate, and time bounds from [broker.md](broker.md) apply.

Unknown, expired, revoked, replayed predecessor, and wrong-binding
authentication all return generic `unauthorized`. Malformed input returns
`invalid-request`, admission saturation returns `capacity-exceeded`, and
durable-store failure returns `issuer-storage-failed`. No response or audit/log
record includes a bearer, digest, successor, request body, or SQLite diagnostic.

Authentication is completed by an indexed digest lookup before a runtime body
is admitted. Body concurrency and rate limits include per-enrollment bounds,
so unknown or noisy identities cannot consume another identity's quota.
Complete-store integrity validation occurs at startup and explicit recovery.
A detected integrity failure on either a complete scan or an indexed runtime
path latches the issuer unhealthy and all runtime requests fail closed until
maintenance completes a successful full recovery validation. Steady readiness
checks only the latched state and bounded durable metadata; it does not perform
or trigger recovery. Normal status and rotation validate only their indexed
record, counters, and digest membership; recurring guest work does not scan
predecessor history or unrelated identities and does not hold the SQLite writer
lock during a global scan.

## Native guest client

The host bundle contains the provider-neutral static `nvt-guest-identityd`.
It is separate from `agentd` and the untrusted agent session. Provider
bootstrap supplies only root-owned path configuration, explicit CA trust, and
the one-time envelope file. The daemon never accepts a bearer through argv or
environment and emits only stable non-secret health classes.

The daemon durably records one of these states in a strict bounded mode `0600`
document below a root-owned mode `0700` directory:

1. current identity with broker-owned issue/expiry metadata;
2. current identity plus exactly one proposed successor while rotation outcome
   is ambiguous; or
3. a non-secret terminal `replacement-required` marker after expiry,
   revocation, or unrecoverable authentication.

Writes use a same-directory temporary file, file `fsync`, atomic rename, and
parent-directory `fsync`. On restart, an unresolved successor is probed before
the predecessor; the daemon retries only that successor when the predecessor
is still current. It reports identity readiness only after broker status
authenticates the exact durable binding. Production rotation is scheduled no
earlier than the 30-minute planning interval, with deterministic per-binding
jitter and a recovery window before the one-hour broker expiry. The schedule
is a client invariant; the broker remains authoritative for timestamps and
capacity.

TLS uses only the explicitly provisioned CA pool, direct HTTPS without ambient
proxy configuration, exact endpoint paths, no redirects, and bounded
DNS/connect/TLS/header/body/overall time and message sizes. Plaintext envelope,
identity, and successor values exist only in bounded trusted memory and the
root-only state document. They do not enter readiness, logs, diagnostics,
bundle metadata, the agent workspace, or `agentd`.

The broker implements the authority when guest enrollment is enabled, and the
native daemon implements its guest lifecycle. The runtime identity may
authenticate issuance under the separate
[`nvt.guest-session-identity/v1`](guest-session-identity.md) contract, but it is
not itself exposed to a gateway, agent session, or egress path. The test-only
QEMU reference is only a real-guest conformance consumer; no provider-specific
branch is present in the daemon or protocol. The separate
[`nvt.native-session/v1`](native-session.md) guest client obtains only a
derived short-lived session credential over a root-only local socket; it never
receives this bearer. The production gateway accepts that bounded control
session. The production guest and gateway also establish the separate
[`nvt.native-workspace/v1`](native-workspace.md) yamux transport using the same
derived credential, and authorized external-VM browser routing consumes its
exact active stream boundary. The purpose-separated
[`nvt.native-egress/v1`](native-egress.md) identity/session/confinement contract
is frozen separately. Its production broker authority consumes this runtime
bearer only to issue the purpose-separated short-lived egress credential; no
other process receives this runtime bearer. The host bundle now includes the
separate opt-in native-egress client that obtains only that derived credential
over root-only IPC and establishes the strictly trusted outbound flow session.
The standalone relay terminates the matching bounded data plane and may use an
explicit process-owned exact-binding adapter into the run's existing egressd
CONNECT listener. Captured agent traffic integration, dynamic operator target
publication/readiness, and provider network enforcement do not exist yet.
