# Native guest session transport

Status: versioned provider-neutral contract (`nvt.native-session/v1`).

This contract defines the first authenticated outbound connection from a
native NVT guest to a trusted gateway implementation. The guest is always the
network initiator. This phase ships a guest client and a hermetic fake gateway;
it does not add a production gateway listener, browser route, reverse-tunnel
routing, mediated VM networking, or a provider implementation.

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

The client does not add agentd methods, touch its event log, open caller-chosen
paths or ports, execute commands, or expose credentials. One request is
processed at a time in v1. Request IDs must be unique on a connection, and a
connection is limited to 1,024 requests; a duplicate or overflow fails closed
instead of growing replay state without bound. `ping` and `pong` frames provide
bounded liveness; the client also verifies local agentd health while the
gateway is idle.

## Renewal, reconnect, and readiness

Broker timestamps are authoritative. The client renews on a deterministic
per-binding schedule no later than one minute before the five-minute session
expiry and never requests more than one replacement per established session.
It also derives conservative monotonic local renewal/expiry deadlines capped by
the broker window, so a backward guest wall-clock step cannot extend bearer
use indefinitely; a forward step fails closed at the broker timestamp.
An ordinary transport disconnect may reconnect with the same still-live
credential. Renewal obtains one new credential, establishes and authenticates
the replacement connection, then drops references to the predecessor.

A process restart has no plaintext recovery file: it requests a fresh
credential through the local socket. At most two live credentials can exist;
capacity denial remains temporary until an older credential expires. A first
issuance response lost after broker commit permits one bounded retry. A second
ambiguous result, authentication denial, expiry, revocation, malformed success,
or inability to establish a safe window fails closed without requesting a
third candidate.

`nvt-guest-sessiond` publishes `session-ready` only after the exact hello is
acknowledged and local agentd health succeeds. It removes readiness before
disconnect, renewal, or failure. The non-root supervisor waits for and
continuously monitors this file, so a disappeared gateway session or agentd
cannot leave stale overall guest readiness.
