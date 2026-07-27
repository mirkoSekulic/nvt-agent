# VM guest enrollment protocol

`nvt.guest-enrollment/v1` is the provider-neutral, one-time handoff used to
bootstrap one native NVT guest runtime identity. It is a sensitive contract
between trusted control-plane components and the intended guest; it is not part
of the execution-driver desired-state protocol.

This document freezes lifecycle and data semantics, not a deployment topology.
The conformance package under `protocol/guestenrollment` can be used by an
in-process test issuer, a broker-backed service, or a future dedicated control
workload without changing the contract.

## Roles and trust boundaries

- The **operator orchestrator** authorizes one AgentRun, selects one exact
  administrator-owned execution driver and class, derives the stable execution
  ID and desired generation, and requests/revokes enrollment.
- The **enrollment issuer** creates a cryptographically random token, durably
  stores only its one-way digest and exact binding, atomically consumes it, and
  issues/revokes the guest runtime identity. A production issuer is expected to
  be broker-backed, but no broker endpoint is added in this phase.
- The **exact selected execution driver** receives one separately delivered
  encoded bootstrap envelope and places it into the intended VM's protected
  bootstrap channel. It treats the envelope as opaque, never places it in
  provider tags, ordinary durable state, diagnostics, or desired state, and
  never tries another driver.
- The **guest bootstrap** obtains the envelope through that protected channel,
  verifies the local guest/bootstrap instance binding, exchanges it once over
  authenticated HTTPS, persists the returned runtime identity securely, and
  erases the token and envelope.

The driver is a trusted control-plane extension and may possess infrastructure
credentials in its isolated driver-host workload. Those credentials never
enter the envelope or guest. The returned **runtime identity** authenticates the
NVT guest to future control-plane services. It is distinct from both provider
credentials and the separate egress identity used by mediated outbound traffic.
This contract does not issue or deliver an egress identity.

## Non-possession boundary

The plaintext one-time token and resulting runtime identity are forbidden in:

- AgentRun and AgentSchedule specifications, status, annotations, events, and
  conditions;
- execution profiles/classes and opaque class configuration;
- `DesiredExecution`, desired generation/fingerprint inputs, portable driver
  status, external resource IDs, and ordinary provider state;
- host-bundle OCI artifacts, manifests, completion metadata, and logs; and
- operator, driver, issuer, guest, broker, gateway, or cloud-provider logs and
  diagnostics.

The sensitive handoff is a distinct envelope passed outside
`nvt.execution-driver/v1`. Adding it to `DesiredExecution` would make retries,
provider state, and fingerprinting credential-bearing and is prohibited. A
future transport may add a separate authenticated host operation, but must not
change or overload the frozen reconcile payload.

## Binding

Every issuance and exchange carries this complete tuple:

| Field | Meaning and bound |
| --- | --- |
| `agent_run_uid` | Immutable AgentRun UID, non-empty printable UTF-8, at most 128 bytes. |
| `execution_id` | Stable opaque execution ID used by the exact driver, at most 256 bytes. |
| `driver_registration` | Exact administrator-selected DNS-label registration, at most 63 bytes. |
| `desired_generation` | Positive generation of the complete non-secret desired execution tuple. |
| `guest_instance_id` | Intended provider/bootstrap instance, non-empty printable UTF-8, at most 256 bytes. |

Equality is byte-for-byte across all five fields. The issuer rejects a token
presented with any differing field before identity issuance and without
consuming the valid binding. A new desired generation or replacement guest uses
a new binding and token. Driver fallback is never permitted.

The guest instance ID is a provider-neutral opaque value selected before
issuance. It is not authorization by itself; it prevents a token intended for
one bootstrap instance from being exchanged by another.

Cleanup and restart recovery use the stable **execution scope**, which is the
`agent_run_uid`, `execution_id`, and exact `driver_registration` subset of the
binding. It intentionally excludes generation and guest instance. The immutable
AgentRun and selected backend are therefore sufficient to revoke every earlier
or replacement guest without persisting sensitive envelope state or enumerating
provider resources.

## Sensitive envelope and exchange

An authorized issuance request is bounded to 4 KiB:

```json
{
  "contract_version": "nvt.guest-enrollment/v1",
  "binding": {
    "agent_run_uid": "3f203e6c-e244-4a75-9445-c24f34b26cd9",
    "execution_id": "nvt-exec-0123456789abcdef",
    "driver_registration": "qemu-lab",
    "desired_generation": 7,
    "guest_instance_id": "guest-boot-42"
  },
  "ttl_seconds": 300
}
```

The issuer returns one envelope, bounded to 16 KiB:

```json
{
  "contract_version": "nvt.guest-enrollment/v1",
  "binding": {"agent_run_uid":"...","execution_id":"...","driver_registration":"qemu-lab","desired_generation":7,"guest_instance_id":"guest-boot-42"},
  "exchange_url": "https://enrollment.nvt-system.svc/v1/guest-enrollment/exchange",
  "token": "<32 random bytes encoded as canonical base64url without padding>",
  "issued_at": "2026-07-27T12:00:00Z",
  "expires_at": "2026-07-27T12:05:00Z"
}
```

`exchange_url` is exact issuer-owned configuration. An issuance caller cannot
provide or override it. The issuer validates its canonical endpoint at startup
and places only that value in every envelope. It is HTTPS with no userinfo,
query, or fragment. Transport trust, server authentication, and reachability
are deployment-owned and must be provided independently of the token. The URL
is not a bearer credential, but misdirecting the bearer token is a credential
disclosure and therefore fails closed.

The token contains 256 bits from a cryptographic random source. V1 permits a
TTL from 1 through 900 seconds. The issuer stores and compares
`sha256:<64-lowercase-hex>` of the exact canonical token string; it never stores
the plaintext after returning the envelope. The driver and guest keep the
plaintext only for the bounded bootstrap exchange and erase it afterward.

The guest sends a bounded exchange request containing the exact envelope token
and binding. A successful response contains the same binding and one sensitive
runtime identity:

```json
{
  "contract_version": "nvt.guest-enrollment/v1",
  "binding": {"agent_run_uid":"...","execution_id":"...","driver_registration":"qemu-lab","desired_generation":7,"guest_instance_id":"guest-boot-42"},
  "runtime_identity": {
    "type": "nvt.runtime-identity/v1",
    "opaque": "<canonical base64url identity material>",
    "issued_at": "2026-07-27T12:00:01Z",
    "expires_at": "2026-07-27T13:00:01Z"
  }
}
```

The opaque identity material decodes to 32 through 65,536 bytes and has a
maximum lifetime of 24 hours in v1. This contract intentionally does not assign
provider, gateway, or egress semantics to it. A later broker-backed issuer
defines how the guest uses and rotates that runtime identity without widening
this one-time bootstrap envelope.

All JSON is UTF-8 and uses strict object shapes. Unknown fields, trailing
values, invalid UTF-8, and duplicate keys at any nesting depth (including
escaped-equivalent keys) fail closed. Request and response handlers also apply
the stated byte limits before decoding. Issuance, exchange, and revocation each
have an absolute 30-second v1 operation ceiling; callers and implementations
may select a shorter deadline.

## Lifecycle and atomicity

An enrollment record has exactly four issuer-owned states:

```text
issued -> consumed
   |         |
   +-> expired
   +-> revoked <- consumed
```

- **issued**: the token digest and complete binding are durable and the token
  may be exchanged once before expiry.
- **consumed**: exactly one transaction accepted the token and issued one
  runtime identity. Every concurrent or later exchange is a replay and fails.
- **expired**: the `expires_at` deadline was reached before successful
  consumption. This transition occurs at `expires_at` whether or not an
  exchange request observes it.
- **revoked**: AgentRun cleanup or explicit recovery invalidated the token and,
  if already consumed, revoked the resulting runtime identity.

The compare, staged runtime identity, consumed transition, and identity
activation are one atomic durable-store transaction. Before commit, neither the
consumed state nor an active runtime identity may be visible. After commit, both
must be visible even if the response is lost. Under concurrent exchange,
exactly one caller may receive an identity. An invalid token, wrong binding,
expiry, revocation, replay, capacity limit, storage failure, or identity failure
never falls back, never issues a second identity, and returns only a bounded
stable failure class.

Consumed/revoked digest records and revocation tombstones contain no plaintext.
All token records, exact-binding tombstones, and execution-scope tombstones
share one hard limit of 10,000 durable entries per issuer partition;
deployments may choose a lower bound and must also bound request concurrency.
Creating a record or tombstone at capacity fails explicitly. It never evicts or
overwrites a live enrollment or active identity.

Terminal records and tombstones use a retention deadline no later than 24 hours
after their terminal transition. Issuers must garbage-collect them once that
deadline has passed and the authoritative orchestrator has completed cleanup
for the execution scope, provided its authorization source will permanently
reject new issue requests for that deleted AgentRun. A later cleanup completion
makes an already-expired tombstone eligible immediately. Binding tombstones
covered by an execution tombstone may be compacted into the single scope
tombstone. Saturation remains fail-closed until eligible cleanup frees capacity.
Issuer maintenance must recognize an `issued` record whose `expires_at` is at
or before the current time as expired without waiting for an exchange. Its
retention clock starts at `expires_at`; late observation must not extend it.

Exact-binding revocation is idempotent and durably abandons one handoff even
when no token record is currently present. It is useful for uncertain envelope
delivery, but it is not AgentRun cleanup.

The exact-binding revocation request is bounded to 4 KiB and carries
`contract_version` plus the complete `binding`. The authoritative execution
revocation request is also bounded to 4 KiB and has this implementation-neutral
shape:

```json
{
  "contract_version": "nvt.guest-enrollment/v1",
  "execution_scope": {
    "agent_run_uid": "3f203e6c-e244-4a75-9445-c24f34b26cd9",
    "execution_id": "nvt-exec-0123456789abcdef",
    "driver_registration": "qemu-lab"
  }
}
```

Execution-scoped revocation is the authoritative cleanup operation. It
atomically installs one durable scope tombstone, revokes all issued tokens and
all active runtime identities for every matching generation/guest instance,
and rejects future issuance for that scope. Unrelated scopes remain unchanged.
AgentRun cleanup ordering is:

1. durably revoke the stable execution scope and retry until acknowledged;
2. converge exact-driver resource deletion and all other operator cleanup; and
3. only then complete the finalizer/AgentRun deletion and make the scope
   eligible for bounded tombstone garbage collection.

An operator or issuer restart resumes step 1 from the immutable AgentRun and
selected exact driver. Removing the VM or driver resource alone is never proof
of token or runtime-identity revocation.

## Restart and uncertain-delivery semantics

Production correctness depends on a transactional durable issuer store, not
process memory. A fresh issuer process must accept an unexpired issued token,
reject a consumed/revoked/expired token, and continue execution-scoped
revocation from durable state. The conformance fake replaces issuer/orchestrator
objects while retaining only a digest/binding store. Its explicit transaction
seam injects failure before commit and response loss after commit; this models
the required atomic boundary without claiming that an in-memory mutex simulates
a power loss or production database. Deterministic clock/random sources and
in-memory plaintext delivery are test-only seams; the reusable token generator
uses `crypto/rand`, and durable snapshots never retain plaintext.

The plaintext response cannot be reconstructed from a digest. If issuance may
have succeeded but the envelope was not durably delivered, the orchestrator
must revoke that exact binding and explicitly issue a new token bound to a new
intended guest/bootstrap instance; it must not blindly retry into a second
active enrollment or reuse a revoked binding. If an exchange response is lost
after consumption, replay still fails and no second identity is issued.
Recovery uses explicit revocation plus a new intended guest/bootstrap instance,
never an implicit replay or fallback driver.

The orchestrator may hold the envelope only in bounded memory while performing
the sensitive handoff. An orchestrator restart invokes execution-scoped
revocation from stable AgentRun ownership; it does not need to query tokens,
remember every prior guest binding, or expect token bytes in an AgentRun or
provider record. Production operator/broker wiring is intentionally deferred.

## Diagnostics

Errors expose only stable classes such as `invalid-request`, `invalid-token`,
`binding-mismatch`, `expired`, `revoked`, `already-consumed`,
`capacity-exceeded`, `issuer-storage-failed`, and
`identity-issuance-failed`. They never include request bodies, tokens, token
digests, runtime identity material, credential values, provider responses, or
guest bootstrap content. Normal state snapshots may include the one-way token
digest, binding, timestamps, lifecycle state, and a non-secret revocation
handle, but no plaintext token or identity.

## Compatibility and next phase

This phase adds no CRD, status, chart, controller, broker endpoint, guest
service, or driver-host operation. Existing Pod, Kata, and Compose behavior is
unchanged. `DesiredExecution` remains the same non-secret, level-triggered
contract, and host bundles remain credential-free.

Issue #127 contains historical public-Git execution-driver language. The merged
repository contract is authoritative: production execution drivers are complete
OCI images pinned by digest and run in isolated driver-host workloads. Git
loading remains supported only for the separate runtime-plugin and executable
broker-provider contracts.

The next implementation step is a broker-backed durable issuer and a separate
authenticated operator-to-exact-driver sensitive handoff. After that, a QEMU
reference driver can provision a guest and exercise enrollment; gateway
routing, runtime identity use, broker identity, and mediated egress remain
separate production gates.
