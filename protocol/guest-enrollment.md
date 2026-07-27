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
  "issuer_url": "https://enrollment.nvt-system.svc/v1/guest-enrollment/exchange",
  "ttl_seconds": 300
}
```

The issuer returns one envelope, bounded to 16 KiB:

```json
{
  "contract_version": "nvt.guest-enrollment/v1",
  "binding": {"agent_run_uid":"...","execution_id":"...","driver_registration":"qemu-lab","desired_generation":7,"guest_instance_id":"guest-boot-42"},
  "issuer_url": "https://enrollment.nvt-system.svc/v1/guest-enrollment/exchange",
  "token": "<32 random bytes encoded as canonical base64url without padding>",
  "issued_at": "2026-07-27T12:00:00Z",
  "expires_at": "2026-07-27T12:05:00Z"
}
```

`issuer_url` is exact HTTPS with no userinfo, query, or fragment. Transport
trust, server authentication, and reachability are deployment-owned and must be
provided independently of the token. The URL is not a bearer credential.

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
- **expired**: the deadline was reached before successful consumption.
- **revoked**: AgentRun cleanup or explicit recovery invalidated the token and,
  if already consumed, revoked the resulting runtime identity.

The compare, state transition, and identity issuance are one atomic durable
operation. Under concurrent exchange, exactly one caller may receive an
identity. An invalid token, wrong binding, expiry, revocation, replay, capacity
limit, storage failure, or identity failure never falls back, never issues a
second identity, and returns only a bounded stable failure class.

Consumed/revoked digest tombstones may remain for a bounded audit/replay window;
they contain no plaintext. Expired and terminal tombstones must be garbage
collected under explicit issuer count/time limits. V1 permits at most 10,000
outstanding records per issuer partition; deployments may choose a lower bound
and must also bound request concurrency. Saturation fails explicitly rather
than evicting a live enrollment.

Revocation is exact-binding, idempotent, and durable even when no token record
is currently present. A later issuance for that revoked exact binding is
rejected, closing the issue-versus-cleanup race. AgentRun deletion asks the
issuer to revoke before operator cleanup is complete. The issuer must revoke
both an unconsumed token and any runtime identity resulting from that binding.
Removing the VM or driver resource alone is not proof of revocation.

## Restart and uncertain-delivery semantics

Production correctness depends on a transactional durable issuer store, not
process memory. A fresh issuer process must accept an unexpired issued token,
reject a consumed/revoked/expired token, and continue exact revocation from
durable state. The conformance fake models this by replacing the issuer process
object while retaining only a store containing token digests and bindings. Its
deterministic clock/random sources and in-memory plaintext delivery are explicit
test seams; the reusable token generator uses `crypto/rand`, and the fake's
durable snapshots never retain plaintext.

The plaintext response cannot be reconstructed from a digest. If issuance may
have succeeded but the envelope was not durably delivered, the orchestrator
must revoke that exact binding and explicitly issue a new token bound to a new
intended guest/bootstrap instance; it must not blindly retry into a second
active enrollment or reuse a revoked binding. If an exchange response is lost
after consumption, replay still fails and no second identity is issued.
Recovery uses explicit revocation plus a new intended guest/bootstrap instance,
never an implicit replay or fallback driver.

The orchestrator may hold the envelope only in bounded memory while performing
the sensitive handoff. An orchestrator restart must recover by querying/revoking
issuer state, not by expecting token bytes in an AgentRun or provider record.
Production operator/broker wiring is intentionally deferred.

## Diagnostics

Errors expose only stable classes such as `invalid-request`, `invalid-token`,
`binding-mismatch`, `expired`, `revoked`, `already-consumed`, and
`capacity-exceeded`. They never include request bodies, tokens, token digests,
runtime identity material, credential values, provider responses, or guest
bootstrap content. Normal state snapshots may include the one-way token digest,
binding, timestamps, lifecycle state, and a non-secret revocation handle, but no
plaintext token or identity.

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
