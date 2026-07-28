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

History is bounded to 1,024 predecessor digests per enrollment and 10,000
history entries per issuer. Saturation fails with `capacity-exceeded`; live
history is never evicted to admit a rotation. Exact-binding and execution-scope
revocation delete the corresponding current identity and all its history.
Schema migration cannot reconstruct historical digests: an already-consumed
pre-history record remains usable for status but rotation fails closed until
the orchestrator revokes and re-enrolls that binding.

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
rejected by readiness validation.

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
Complete-store integrity validation occurs at startup, readiness, and
maintenance. A detected integrity failure latches the issuer unhealthy and all
runtime requests fail closed. Normal status and rotation validate only their
indexed record and bounded lifecycle history; recurring guest work does not
scan unrelated identities or hold the SQLite writer lock during a global scan.

## Current implementation boundary

The broker implements this authority when guest enrollment is enabled. This
phase does not add a guest daemon/rotation loop, gateway routing, production
runtime-identity consumers, or mediated VM networking. The test-only QEMU
reference remains only a conformance consumer; no provider-specific branch is
present in this contract or broker implementation.
