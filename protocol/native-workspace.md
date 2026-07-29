# Native workspace reverse-tunnel contract

Status: versioned provider-neutral contract, conformance proof, trusted
host-bundle guest forwarder, opt-in production gateway acceptor, and authorized
external-VM browser routing (`nvt.native-workspace/v1`).

This contract defines a separate guest-initiated data-plane connection through
which a trusted gateway may open bounded raw TCP streams to one fixed native
workspace service. The initial service is code-server on a trusted loopback
endpoint such as `127.0.0.1:4090`.

The existing [`nvt.native-session/v1`](native-session.md) connection remains
the control plane for ping/pong and the bounded agentd JSON relay. It is not
upgraded, extended, or reused for workspace bytes. The workspace connection
has a distinct contract version and registry purpose so browser traffic cannot
block agentd health or control messages.

## Trust and authentication

The VM guest is always the outer TCP/TLS initiator. It uses the same explicit
gateway DNS endpoint, TLS 1.2-or-newer policy, configured CA trust, complete
enrollment binding, fixed `nvt.native-guest-control/v1` audience, and
short-lived `nvt.guest-session-credential/v1` defined by
[guest-session-identity.md](guest-session-identity.md). It does not create a
new credential type or audience.

The trusted gateway authenticates that bearer through the broker before
acknowledging the workspace hello. It requires the returned binding, audience,
broker-owned window, and non-secret positive issuance sequence to match
exactly. The authentication boundary returns that sequence with the binding
and authoritative issued/expiry timestamps; `Accept` derives the conservative
local deadline and drops the bearer before creating the multiplexer. Neither
an authority adapter nor a yamux constructor may extend local trust beyond the
broker-owned window or the five-minute credential maximum. A definitive
authority denial may receive `hello_reject`; transport, TLS, DNS, timeout,
`429`, `5xx`, or malformed-authority failures close silently so a guest may
retry the same still-live credential. Network reachability is never
authentication.

The bearer MUST NOT enter yamux metadata or any logical stream. It also MUST
NOT enter logs, metrics, errors, events, status, diagnostics, AgentRun data,
execution-driver state, the agent user/workspace, argv, or environment. HTTP
authorization headers and all other application bytes are opaque raw stream
payload; the tunnel MUST NOT parse, buffer as a whole, log, or diagnose them.

The workspace registry purpose is the tuple `(nvt.native-workspace/v1,
complete-binding)`. It is separate from the control registry purpose even when
both connections authenticate with the same still-live credential.

## Handshake

The pre-yamux handshake is UTF-8 JSONL. One compact object plus newline is
bounded to 64 KiB. Strict decoding rejects unknown fields, recursive duplicate
keys, invalid UTF-8, trailing JSON, oversized input, malformed credentials,
and any binding or audience mismatch.

The guest sends exactly:

```json
{"contract_version":"nvt.native-workspace/v1","type":"hello","binding":{"agent_run_uid":"...","execution_id":"...","driver_registration":"...","desired_generation":1,"guest_instance_id":"..."},"audience":"nvt.native-guest-control/v1","credential":"<sensitive>"}
```

After broker authentication the gateway returns:

```json
{"contract_version":"nvt.native-workspace/v1","type":"hello_ack","binding":{"agent_run_uid":"...","execution_id":"...","driver_registration":"...","desired_generation":1,"guest_instance_id":"..."},"audience":"nvt.native-guest-control/v1"}
```

A definitive denial uses only:

```json
{"contract_version":"nvt.native-workspace/v1","type":"hello_reject","reason":"unauthorized"}
```

Both sides use one absolute five-second handshake deadline. The guest MUST NOT
pipeline yamux bytes before validating `hello_ack`; the gateway rejects bytes
buffered beyond the hello newline. Immediately after the acknowledgement the
same connection switches to the yamux wire format. There are no later NVT
JSON frames on this connection.

The conformance suite composes this handshake with a synthetic guest-initiated
TLS connection and explicit CA/server-name trust. It proves success with TLS
1.2 or newer and rejection of an untrusted CA, wrong server name, and a
TLS-1.1-only peer. Production certificate/Secret mounting remains part of the
later wiring phase.

## Pinned yamux profile

The v1 wire implementation is HashiCorp yamux release `v0.1.2`, identified as
`github.com/hashicorp/yamux/v0.1.2`. Implementations MUST configure every
load-bearing value explicitly and MUST NOT inherit library defaults:

| Setting | v1 value |
|---|---:|
| Gateway/guest role | gateway `yamux.Client`; guest `yamux.Server` |
| Accept backlog | 8 streams |
| Maximum pending gateway opens | 8 |
| Maximum active application streams | 32 |
| Maximum rejected guest-initiated streams before teardown | 8 |
| Maximum stream window | 256 KiB |
| Copy buffer per direction | 32 KiB |
| Keepalive | enabled, 10 seconds |
| Connection write timeout | 5 seconds |
| Stream open timeout | 5 seconds |
| Stream close timeout | 5 seconds |
| Stream inactivity timeout | 2 minutes |
| Fixed local dial timeout | 3 seconds |
| Yamux log output | discarded |

Yamux's client/server labels describe logical stream-ID ownership, not which
side initiated the outer TCP connection. The gateway is `yamux.Client` so only
gateway-opened odd-ID application streams are allowed. The guest is
`yamux.Server` and only accepts those streams. If a compromised guest opens an
even-ID stream, the gateway accepts only far enough to close/reset it. One such
violation does not disturb valid gateway streams; eight violations terminate
the complete session. No application goroutine or buffer is created for a
guest-opened stream.

## Fixed destination and stream semantics

One yamux stream is one raw backend TCP connection. The guest's trusted,
root-owned configuration supplies one canonical literal loopback endpoint:
`127.0.0.1:<1..65535>` or `[::1]:<1..65535>`. DNS names, wildcard addresses,
URLs, Unix paths, port zero, and non-loopback literals are invalid.

The destination is never present in the workspace hello, yamux stream,
browser request, AgentRun, producer input, execution-driver response, or any
other data-plane frame. Every accepted stream dials the same configured
endpoint. Host headers, request targets, WebSocket data, and arbitrary payload
bytes cannot select another host or port.

The guest copies bytes incrementally in both directions with fixed 32 KiB
buffers and TCP/yamux half-close behavior. It preserves backpressure and does
not buffer an HTTP body, WebSocket message, or stream as a whole. A stream is
closed on local dial failure, inactivity, cancellation, either-side failure,
or session teardown. Any successful traffic in either direction refreshes the
single connection-wide inactivity deadline; a quiet read side cannot expire
while the opposite direction remains active. At most 32 forwarding workers
and 64 copy operations may exist for one authenticated session.

The gateway exposes only an implementation-neutral `OpenStream(context)`
boundary returning `net.Conn`; gateway routing must not depend on yamux types.
The guest exposes no application-stream open operation.

## Lifetime, replacement, and cleanup

The outer authenticated lifecycle remains authoritative. Credential expiry,
bounded broker revalidation, revocation, malformed protocol, connection loss,
gateway shutdown, or guest shutdown removes registry readiness first and then
closes the yamux session. Closing a session closes every pending and active
stream, its timers, local workspace connection, and bounded workers.

Production make-before-break follows the control-session rule: one active
workspace connection plus one authenticated equal/newer-sequence standby for
the same complete binding and workspace purpose; an older or third connection
cannot preempt active. Existing streams stay on the active connection. Only
after active closes may the registry promote the ready standby. Streams are
never migrated between yamux sessions. A new active session can open new
streams only after exact authentication.

The implementation-neutral registry is bounded to 128 complete bindings. Its
`StreamOpener` boundary exposes only the complete binding, validated non-secret
issuance sequence, stream open, and close operations; it does not expose a
credential or yamux type. Equal sequence permits an overlapping ordinary
reconnect, newer sequence permits make-before-break renewal, older sequence is
rejected, and a third connection is rejected while the standby slot is held.
Activating a standby never preempts active; removal of active atomically
promotes an already-ready standby.

The conformance adapter receives a conservative local trust deadline and
closes itself at that deadline. A production registry must additionally apply
the broker revalidation deadline and the bounded global/per-binding admission
from the native session gateway.

## Selection and tradeoffs

Yamux is used instead of an NVT-specific multiplexing implementation because
the released library already provides stream IDs, flow-control windows,
backpressure, keepalive, bounded open/close behavior, and deterministic session
shutdown over one ordered connection. Pinning the release and all settings
keeps the proof reproducible and makes later implementation replacement a
reviewed wire-contract change rather than an accidental dependency upgrade.

All logical streams share one outer TCP/TLS connection. Packet loss can
therefore cause TCP head-of-line blocking across otherwise independent yamux
streams. This is accepted for v1's bounded workspace access and is not a claim
that yamux has QUIC-like loss isolation.

## Current implementation boundary

The repository includes a hermetic race-tested conformance adapter and the
optional trusted `nvt-guest-sessiond` guest integration using the real pinned
yamux library. They prove the synthetic TLS boundary, exact
authentication/window derivation, older/equal/newer standby selection, Go
reverse-proxy/custom `DialContext` HTTP, Upgrade-style bidirectional traffic,
concurrent streams, payloads larger than one window, bidirectional inactivity,
limits, direction enforcement, teardown/promotion, same-credential paired
control/workspace renewal, fixed-target reachability, and redacted
observability.

The production gateway has an opt-in workspace listener and bounded
process-local active/standby `StreamOpener` registry. The operator publishes
only the complete non-secret routing binding of the currently accepted guest
in the AgentRun status subresource and clears it before that guest ceases to be
authoritative. A gateway resolver requires exact status, desired generation,
driver and execution identity plus ready control/workspace registries; it never
guesses or enumerates bindings. After browser authentication and AgentRun
authorization, the production HTTP reverse proxy uses only that exact
`StreamOpener`. Its dial boundary ignores browser network/authority input and
cannot fall back to a Pod for an external VM. Production native code-server
browser access is therefore wired. The provider-neutral native VM mediated
egress contract and conformance boundary are frozen separately, but its
production tunnel/provider enforcement, cloud providers, and public VM
listeners remain later reviewed production gates.
