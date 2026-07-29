# Native guest session identity protocol

Status: versioned provider-neutral contract (`nvt.guest-session-identity/v1`).

This contract derives a short-lived, purpose-scoped session credential from the
root-owned guest runtime identity in [guest-runtime-identity.md](guest-runtime-identity.md).
It authenticates the outbound guest hello defined by the separate
[native-session transport](native-session.md). Neither contract defines or
ships a production gateway route, reverse tunnel, browser publication path, or
mediated VM network.

## Security boundary

The three credentials remain distinct:

- the runtime identity authenticates only trusted guest lifecycle operations;
- the session credential authenticates only establishment of the fixed native
  guest control audience defined here;
- provider credentials and the separate mediated-egress identity never enter
  the guest through this contract.

The session credential MUST NOT enter AgentRun or AgentSchedule objects,
execution-driver desired state/status/fingerprints, execution-class
configuration, provider-visible resource metadata, logs, events, diagnostics,
OCI metadata, argv, environment, agentd, or the agent user/workspace. The
broker persists only its SHA-256 digest and non-secret lifecycle metadata.

The exact active `nvt.runtime-identity/v1` bearer authenticates issuance. A
session credential cannot issue another session credential and cannot call
runtime-identity status or rotation. An agent, egress, producer, gateway, or
orchestrator credential cannot use either session endpoint.

## Constants and bounds

| Item | v1 value |
|---|---|
| Contract version | `nvt.guest-session-identity/v1` |
| Credential type | `nvt.guest-session-credential/v1` |
| Audience | `nvt.native-guest-control/v1` |
| Credential form | opaque positive 63-bit per-lifecycle sequence encoded as 8-byte big-endian, plus 32 random bytes, canonical unpadded base64url |
| Maximum lifetime | 5 minutes |
| Maximum simultaneously live credentials per exact binding | 2 |
| Issue request | 8 KiB |
| Authenticate request | 4 KiB |
| Response | 16 KiB |
| Operation duration | 30 seconds |

The audience is a protocol constant, not an arbitrary scope. A request with
any other audience is malformed. Future audiences require a new reviewed
contract version.

All request and response bodies are UTF-8 JSON objects. Decoders MUST reject
unknown fields, recursively duplicate keys, invalid UTF-8, non-canonical
credential encoding, trailing values, oversized framing, and malformed
timestamps. Timestamps are canonical UTC RFC 3339 values with whole-second
precision.

## Exact binding

Every operation carries the complete enrollment binding:

```json
{
  "agent_run_uid": "...",
  "execution_id": "...",
  "driver_registration": "...",
  "desired_generation": 1,
  "guest_instance_id": "..."
}
```

Equality is byte-for-byte after strict decoding. The authenticating runtime or
session credential MUST be owned by that same binding. No field may be guessed,
defaulted, or selected by the untrusted agent session.

## Issue

`POST /v1/guest-session-identity/issue`

The transport uses `Authorization: Bearer <active-runtime-identity>`. The broker
MUST authenticate the indexed runtime identity before admitting or reading a
slow request body.

```json
{
  "contract_version": "nvt.guest-session-identity/v1",
  "binding": { "...": "..." },
  "audience": "nvt.native-guest-control/v1"
}
```

After exact authentication, the broker atomically:

1. removes expired session credentials for this binding;
2. rejects issuance if two credentials remain live;
3. increments a durable per-lifecycle issuance sequence and combines it with
   32 bytes from a cryptographic random source;
4. bounds expiry to the earlier of five minutes and the current runtime
   identity expiry;
5. persists only the credential digest, binding owner, audience, and
   broker-owned timestamps; and
6. commits before returning the plaintext credential once.

```json
{
  "contract_version": "nvt.guest-session-identity/v1",
  "binding": { "...": "..." },
  "credential": {
    "type": "nvt.guest-session-credential/v1",
    "opaque": "<sensitive>",
    "audience": "nvt.native-guest-control/v1",
    "issued_at": "2026-07-28T12:00:00Z",
    "expires_at": "2026-07-28T12:05:00Z"
  }
}
```

At most two concurrent issue transactions may commit for one binding. This is
also the response-loss recovery bound: if the first committed response is lost,
the trusted guest component may issue once more. A third request fails with
`capacity-exceeded` until one of the two credentials expires. The broker never
reconstructs or returns plaintext from a prior commit, never extends a prior
credential, and never creates an unbounded set. Its monotonic lifecycle
sequence prevents a retired credential from being recreated within that
enrollment even if a random source repeats. The client discards any
credential whose response was not completely validated.

## Authenticate

`POST /v1/guest-session-identity/authenticate`

The transport uses `Authorization: Bearer <session-credential>`. A trusted
gateway-side relay presents:

```json
{
  "contract_version": "nvt.guest-session-identity/v1",
  "binding": { "...": "..." },
  "audience": "nvt.native-guest-control/v1"
}
```

The broker MUST perform an indexed digest lookup before admitting or reading a
slow body, then revalidate the selected durable record and exact binding during
the bounded operation. The selected session expiry MUST NOT exceed the current
parent runtime-identity expiry, and authentication requires that parent
identity lifecycle to remain active and unexpired. Rotation of the parent
runtime bearer does not invalidate an otherwise live session for the same
enrollment lifecycle. Success returns non-secret metadata only:

```json
{
  "contract_version": "nvt.guest-session-identity/v1",
  "credential_type": "nvt.guest-session-credential/v1",
  "binding": { "...": "..." },
  "audience": "nvt.native-guest-control/v1",
  "issued_at": "2026-07-28T12:00:00Z",
  "expires_at": "2026-07-28T12:05:00Z"
}
```

The operation is authentication, not a bearer refresh. Repeated presentation
of the same still-live bearer for reconnect is permitted. "Replay" rejection
means an expired, removed, wrong-binding, wrong-audience, or revoked bearer can
never regain authority.

## Revocation and cleanup

The existing orchestrator-authenticated enrollment operations are
authoritative:

- exact-binding revocation removes every session credential for that binding
  in the same durable transaction as its runtime identity;
- execution-scope revocation removes credentials for every generation and
  replacement guest under the stable execution scope; and
- broker restart preserves all live credential digests and expiry metadata.

The operator cleanup order remains scope revocation, exact-driver deletion,
cleanup-complete acknowledgement, then finalizer removal. Session credentials
are invalid as soon as the first step commits. Expiry maintenance removes stale
session rows without affecting the enrollment tombstone retention contract.

## Admission and errors

Unknown syntactically valid bearers MUST NOT consume another credential's body
or rate quota. Each authenticated credential has independent rate and
concurrency admission beneath a broker-wide bound. Runtime-identity issuance,
session authentication, public enrollment exchange, and authoritative
revocation retain independent bounded admission so session traffic cannot
starve cleanup.

External failures use only generic classes such as `invalid-request`,
`unauthorized`, `capacity-exceeded`, `identity-issuance-failed`, and
`issuer-storage-failed`. Responses, logs, audits, and exceptions MUST NOT echo
request bodies, bearer values, digests, SQLite diagnostics, or provider data.
Detected semantic or SQLite corruption latches the issuer unhealthy; recovery
requires a successful complete integrity validation.

## Implementation boundary

The host bundle implements the trusted guest-side credential request and
outbound native-session client. The production gateway implements the opt-in
TLS acceptor and bounded process-local control registry, and the hermetic
test-only QEMU fixture exercises that listener. The separate
[`nvt.native-workspace/v1`](native-workspace.md) contract proves bounded yamux
multiplexing with this same identity and fixed audience, without adding a
second credential or arbitrary scope. The production guest and gateway
workspace endpoints now use it, but it is not wired to a gateway browser
handler. There is still no production browser route,
mediated VM egress, cloud provider, or production VM runtime. Pod, Kata,
Compose, agentd, and runtime plugins remain unchanged.
