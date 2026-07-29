# Native guest session transport

Status: versioned provider-neutral contract (`nvt.native-session/v1`).

This contract defines the first authenticated outbound connection from a
native NVT guest to a trusted gateway implementation. The guest is always the
network initiator. The production gateway has an opt-in acceptor and bounded
process-local registry for this contract. It does not multiplex browser
HTTP/WebSocket traffic, carry mediated VM egress, or implement a provider. The
separate
[`nvt.native-workspace/v1`](native-workspace.md) yamux data-plane contract and
trusted guest forwarder and production acceptor now exist, but this control
connection is not multiplexed. Authorized external-VM browser routing uses the
separate workspace connection. The provider-neutral
[`nvt.native-egress/v1`](native-egress.md) contract is also separate and has no
production tunnel/provider enforcement yet.

## Trust boundary

The root-owned `nvt-guest-identityd` remains the only process that may read the
longer-lived `nvt.runtime-identity/v1` bearer. A separate root-owned
`nvt-guest-sessiond` may hold one short-lived
`nvt.guest-session-credential/v1` only in bounded process memory while it
establishes or maintains this transport. Neither bearer may enter argv,
environment, the non-root supervisor, agentd, the tmux/agent session,
workspace, logs, events, diagnostics, bundle metadata, or provider state.

The trusted gateway authenticates the hello credential through the broker's
`POST /v1/guest-session-identity/authenticate` operation and requires the exact
binding and fixed `nvt.native-guest-control/v1` audience. Network reachability
alone is never authentication.

The gateway does not retain the bearer after authentication. It enforces the
broker-owned expiry locally and closes an established connection at a bounded
administrator-configured revalidation interval. Reconnect presents the same
still-live credential to the broker again; a revoked, expired, malformed, or
unreachable authority fails closed. The v1 registry is process-local and
therefore requires exactly one gateway replica.

## Root-only credential issuance socket

`nvt-guest-identityd` owns the Unix socket
`/run/nvt-agent-identity/session-credential.sock`. Both production daemons
refuse non-root startup. The parent is therefore root-owned mode `0700`, the
socket is root-owned mode `0600`, and the server requires the Linux
`SO_PEERCRED` UID to equal its own daemon UID (UID 0 in production). It admits
at most four handlers, accepts one request per connection, and applies one
absolute five-second read/write deadline. It removes the socket before exit.
No caller-supplied binding, audience, broker URL, or bearer is accepted.

The request is one UTF-8 JSONL object bounded to 32 KiB:

```json
{"contract_version":"nvt.native-session-local/v1","type":"issue_guest_session"}
```

The caller half-closes its write side after that line. The authority requires
EOF before issuance, so a second line or trailing framing is rejected rather
than silently ignored.

Success returns the exact broker response. Failure returns only a stable
reason plus `temporary` and `uncertain` booleans. Both forms use
`nvt.native-session-local/v1`; unknown fields, duplicate keys, invalid UTF-8,
trailing JSON, extra lines, and oversized messages fail closed. The session
daemon may retry exactly once when the first issuance result is uncertain,
matching the broker's two-live response-loss bound. It never loops issuance
blindly.

## Gateway TLS and framing

The configured endpoint is one canonical `tls://host:port` value. The client
uses an explicitly configured CA pool, derives the exact TLS server name from
that endpoint, requires TLS 1.2 or newer, uses no ambient proxy or credential
helper, and applies bounded DNS/connect/TLS/read/write/overall deadlines.
Redirects and plaintext HTTP do not exist in this transport.

The stream is UTF-8 JSONL with one compact JSON object per line and a 64 KiB
line limit including newline. Duplicate keys are forbidden recursively. The
first guest frame is:

```json
{"contract_version":"nvt.native-session/v1","type":"hello","binding":{"agent_run_uid":"...","execution_id":"...","driver_registration":"...","desired_generation":1,"guest_instance_id":"..."},"audience":"nvt.native-guest-control/v1","credential":"<sensitive>"}
```

The gateway responds only after broker authentication:

```json
{"contract_version":"nvt.native-session/v1","type":"hello_ack","binding":{"agent_run_uid":"...","execution_id":"...","driver_registration":"...","desired_generation":1,"guest_instance_id":"..."},"audience":"nvt.native-guest-control/v1"}
```

The acknowledgement binding and audience must match byte-for-byte. A denial,
malformed frame, timeout, credential expiry, or revocation removes session
readiness before the connection is discarded.

## Bounded agentd relay

After authentication the gateway may send only an `agentd_request` containing
one JSON object of at most 32 KiB and an opaque request ID of at most 128
characters:

```json
{"contract_version":"nvt.native-session/v1","type":"agentd_request","request_id":"request-1","payload":{"type":"health"}}
```

The trusted guest client forwards that single object and newline to the fixed
local agentd Unix socket, reads one bounded response, and returns:

```json
{"contract_version":"nvt.native-session/v1","type":"agentd_response","request_id":"request-1","payload":{"status":"ready"}}
```

The native supervisor starts agentd with socket mode `0660`; the socket remains
owned by the dedicated `nvt-agent:nvt-agent` service identity. This gives the
root session daemon's sole supplementary/primary `nvt-agent` group bounded
read/write access even after systemd removes every capability. Existing
container/Compose agentd launches omit that flag and retain mode `0600`.

The client does not add agentd methods, touch its event log, open caller-chosen
paths or ports, execute commands, or expose credentials. One request is
processed at a time in v1. Request IDs must be unique on a connection, and a
connection is limited to 1,024 requests; a duplicate or overflow fails closed
instead of growing replay state without bound. `ping` and `pong` frames provide
bounded liveness; either peer may initiate a ping. While awaiting its own pong,
the client continues to answer a peer ping and process bounded agentd requests
under the original absolute pong deadline. User-space checks guard buffered
frames, and the local agentd relay plus gateway response write inherit the
remaining budget rather than starting new timeouts. The client also verifies
local agentd health while the gateway is idle.

## Renewal, reconnect, and readiness

Broker timestamps are authoritative. The client renews on a deterministic
per-binding schedule no later than one minute before the five-minute session
expiry and retains at most one returned replacement candidate at a time.
It also derives conservative monotonic local renewal/expiry deadlines capped by
the broker window, so a backward guest wall-clock step cannot extend bearer
use indefinitely; a forward step fails closed at the broker timestamp.
An ordinary transport disconnect may reconnect with the same still-live
credential. Renewal is make-before-break: the established predecessor
connection and readiness remain active while the client obtains and
authenticates one replacement. Only then does it switch connections and drop
references to the predecessor. A temporary broker or gateway failure retains
the still-live predecessor and retries the same pending credential where one
was returned. If response-loss recovery consumes the two-live broker allowance
without returning a usable candidate, the client never issues a third; it
serves the predecessor until its authoritative or monotonic local expiry and
then fails closed.

A process restart has no plaintext recovery file: it requests a fresh
credential through the local socket. At most two live credentials can exist;
capacity denial remains temporary until an older credential expires. A first
issuance response lost after broker commit permits one bounded retry. A second
ambiguous result, authentication denial, expiry, revocation, malformed success,
or inability to establish a safe window fails closed without requesting a
third candidate.

`nvt-guest-sessiond` publishes `session-ready` only after the exact hello is
acknowledged and local agentd health succeeds. It preserves readiness across a
make-before-break renewal and removes it before an actual disconnect or
failure. The non-root supervisor waits for and continuously monitors this
file, so a disappeared gateway session or agentd cannot leave stale overall
guest readiness.

When the optional workspace configuration is enabled, the control connection
and the separate workspace TLS/yamux connection form one readiness unit. Both
must authenticate with the same current credential before readiness appears.
Renewal builds both replacement legs with one pending credential before
switching; a partial replacement is closed while the ready predecessor pair is
retained. A temporary leg loss removes readiness, closes the pair, and retries
the same still-live credential before requesting another. Omission retains
the original control-only lifecycle and wire behavior.
