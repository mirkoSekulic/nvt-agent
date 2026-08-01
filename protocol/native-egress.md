# Native VM mediated-egress contract

Status: versioned provider-neutral contract and hermetic conformance proof
(`nvt.native-egress/v1`) with a production broker identity authority, trusted
host-bundle guest client, standalone cluster relay, bounded yamux flow
transport, and an optional exact-binding adapter into an existing per-run
`egressd` CONNECT listener. The opt-in native host bundle now separates a
credential-less capture process from the credential-bearing tunnel process;
captured guest TCP opens only authenticated native-egress flows. Opt-in
operator deployment, exact target publication, readiness, and cleanup ordering
exist. The operator now emits the provider-neutral desired attachment and
requires its exact infrastructure read-back. The separately packaged Azure
driver is the first production-shaped consumer: it supplies the plan to an
immutable guest-image receiver, installs a per-run NSG deny boundary, and
requires exact Azure read-back. Live image/network infrastructure and its
credentialed proof remain installation-owned gates rather than CI claims.

This contract freezes the boundary needed to carry an independently managed
VM's outbound TCP flows into that exact AgentRun's trusted cluster egress path.
It does not claim that guest-local proxying or redirect rules confine a VM.

## Threat model and enforcement boundary

The agent process, its tools, and runtime plugins inside the VM are untrusted.
The strong mediated mode assumes they may obtain root and may replace local
routes, firewall rules, proxy variables, capture processes, or host services.
Consequently:

- guest-local redirect, transparent capture, a loopback proxy, or a root-owned
  daemon is transport plumbing, not bypass prevention;
- hiding a short-lived credential from ordinary agent files reduces accidental
  disclosure but is not a security boundary against hostile guest root;
- the trusted execution driver/provider MUST establish durable NIC/network
  confinement outside the VM before starting the untrusted agent;
- after trusted bootstrap, the confined VM may reach only explicitly approved
  NVT bootstrap, enrollment, identity, tunnel, and deployment-reviewed DNS/time
  endpoints. It has no direct general-Internet, cluster, private, metadata, or
  provider-control-plane route; and
- provider confinement prevents bypass while the authenticated tunnel chooses
  the exact run and carries flow intent. Both MUST be ready before the operator
  may report a mediated external VM ready.

The VM has no public inbound listener. Enrollment, control, workspace, and
egress connections are guest-initiated outbound connections.

## Roles and exact identity

- **Operator orchestrator:** authorizes the AgentRun, selects one exact driver,
  owns lifecycle/finalizers, and combines portable driver confinement with
  tunnel and target readiness.
- **Execution driver/provider:** owns infrastructure outside the guest. It
  provisions the NIC/network policy, reads it back durably, and reports only
  the portable non-secret confinement assertion.
- **Broker identity authority:** authenticates the exact active root runtime
  identity and issues a purpose-separated short-lived
  `nvt.native-egress-credential/v1`. It persists only credential digests and
  non-secret lifecycle metadata.
- **Trusted guest egress tunnel:** retains the egress credential transiently,
  establishes the outbound session, and exposes a root-only local flow socket.
  It never parses agent-controlled HTTP/TLS prefaces.
- **Credential-less guest capture:** runs as a separate native process, recovers
  transparent destinations or consumes a bounded explicit CONNECT, and sends
  only canonical destination intent and raw bytes over the local flow socket.
  The local wire cannot represent a bearer or exact binding. It is not the
  bypass boundary.
- **Native egress relay:** authenticates the credential and binding, keeps a
  bounded exact-binding registry, and selects the one preconfigured trusted
  target for that binding. It never resolves a target by partial scope or guest
  destination.
- **Per-run trusted egress target:** remains authoritative for hostname/DNS and
  IP validation, private-address denial, broker grants, quotas, audit, TLS
  mediation, and credential injection. The optional relay adapter can use the
  current per-run `egressd` CONNECT service from trusted configuration, but no
  endpoint or Kubernetes Service name is part of this protocol or guest input.

Every identity and session is bound by exact equality to all five existing
`guestenrollment.Binding` fields:

- AgentRun UID;
- stable execution ID;
- exact driver registration;
- desired generation; and
- guest instance ID.

There is no binding enumeration, guest guessing, alternate driver, cross-run
reuse, or Pod fallback.

## Purpose-separated identity

The identity contract is `nvt.native-egress-identity/v1`; the only audience is
`nvt.native-egress/v1`. It is distinct from enrollment tokens,
`nvt.runtime-identity/v1`, `nvt.guest-session-credential/v1`, provider
credentials, and the separate native control/workspace purpose.

The reserved implementation-neutral operations and paths are:

| Operation | Path | Transport authorization |
| --- | --- | --- |
| issue | `/v1/native-egress-identity/issue` | exact active runtime identity |
| authenticate | `/v1/native-egress-identity/authenticate` | egress credential |
| revoke exact binding | `/v1/native-egress-identity/revoke-binding` | trusted orchestrator |
| revoke execution scope | `/v1/native-egress-identity/revoke-execution` | trusted orchestrator |

The broker implements these paths when its opt-in guest-enrollment authority is
enabled. Bodies repeat only the exact non-secret binding/scope, fixed audience,
and version. Bearers are transport authorization, never body fields.

Issuance authenticates possession, ownership, and lifecycle: the presented
runtime-identity digest MUST be the current active identity, its broker-owned
expiry MUST be in the future, it MUST be durably associated with the complete
Binding in the issue body, and all five fields MUST match exactly. An expired or
revoked identity, a rotated predecessor, or an identity for an older generation,
replacement guest, other execution, or other driver cannot authorize a
caller-selected binding.

The canonical egress credential uses a purpose-specific `nvt_eg1_` prefix,
an eight-byte positive durable issuance sequence, and 32 bytes from
`crypto/rand`, encoded base64url without padding. It expires no later than five
minutes after issuance. An authority permits at most two live credentials per
binding so one lost response or make-before-break replacement is recoverable
without unbounded live authority. Control/workspace credentials fail syntactic
egress validation and egress credentials fail control validation; the broker
also keeps a domain-separated digest namespace. The durable digest is
`sha256("nvt.native-egress-credential/v1" || 0x00 || credential)`, formatted as
lowercase `sha256:<hex>`; plaintext is not retained after issue returns.

Plaintext enrollment tokens, runtime identities, egress credentials, provider
credentials, and injected upstream secrets never enter AgentRun/AgentSchedule
spec or status, execution desired state/fingerprints, portable driver status,
class configuration, provider tags/state, logs, events, diagnostics, argv,
environment, or ordinary agent workspace/configuration. No provider credential
or real injected secret enters the VM. The short-lived egress credential exists
only at the trusted identity/session boundary for the time needed to establish
or replace an exact session.

The root identity daemon exposes the purpose-separated local IPC contract
`nvt.native-egress-local/v1` on its existing root-owned mode `0600` Unix
socket. The only request is the exact JSONL object
`{"contract_version":"nvt.native-egress-local/v1","type":"issue_native_egress"}`.
It deliberately has no identity, binding, audience, broker URL, target,
destination, or provider member. The daemon serializes issuance with runtime
identity rotation and derives the complete binding, current active runtime
bearer, broker URL, and fixed audience from protected state. The bounded reply
is either one strict broker issue result or a stable reason with temporary and
uncertain flags. Caller UID must equal the identity daemon UID; production
command gates require UID 0. Messages are at most 32 KiB and complete within
five seconds. Unknown, duplicate, or trailing input closes without a response.

Only equal-sequence reconnect or a higher sequence may stand by. Older replay
is rejected. One active plus one already-authenticated standby is the maximum;
a third fails closed. A standby never preempts active and cannot open flows
until atomic promotion. The obsolete transport session is withdrawn and closed
after the ready replacement is promoted. Exact
binding or execution-scope revocation atomically denies all current and future
credentials/sessions for its ownership key.

The authority admits at most 10,000 durable entries shared by binding
lifecycles, exact-binding tombstones, and execution-scope tombstones; no
tombstone map has a separate unbounded allowance. Cleanup may atomically replace
its own lifecycle entries with a tombstone at capacity, but an absent-binding or
absent-execution revocation that needs a new entry fails closed at the same
bound. The authority never evicts a live credential to admit another run.
Expired credential records may be reclaimed by bounded maintenance.
Revocation tombstones remain until authoritative execution cleanup makes their
scope eligible for the existing bounded retention/GC policy; restart recovery
must not depend on process memory.

## Handshake and replaceable transport

The authentication preface is strict UTF-8 JSONL. The first message is:

```json
{"contract_version":"nvt.native-egress/v1","type":"hello","binding":{"agent_run_uid":"...","execution_id":"...","driver_registration":"...","desired_generation":1,"guest_instance_id":"..."},"audience":"nvt.native-egress/v1","credential":"<sensitive>"}
```

The relay authenticates the bearer and exact body through the authority before
acknowledging. Definitive credential/binding/purpose denial may return the
fixed `unauthorized` rejection. Broker timeout, transport/storage failure, or
capacity closes silently so a client can retry the same still-live credential.
Responses and errors never echo a body, binding, bearer, digest, endpoint, or
backend diagnostic.

The relay caps local trust at the earlier of broker expiry and 30 seconds. It
does not retain the bearer for in-place validation. At the cutoff it withdraws
the session and closes its flows; a still-valid guest reconnects with the same
credential and the broker is consulted again. Denial, revocation, malformed
authority status, or temporary revalidation failure stays fail closed.

After `hello_ack`, that same TLS connection switches to the pinned
`github.com/hashicorp/yamux` v0.1.2 protocol with explicit NVT-owned settings.
The guest is the yamux client and sole application-stream opener; the relay is
the yamux server and accepts streams. A relay-initiated stream is a protocol
failure. Yamux types remain private to this package: callers receive only the
transport-neutral `FlowOpener`/`net.Conn` boundary, and targets continue to
implement only `EgressTarget`.

Each logical stream starts with exactly one strict `flow_open` JSONL frame.
The relay validates its session-unique flow ID and canonical Destination,
opens only through the `EgressTarget` already selected by the authenticated
five-field Binding, and returns the matching `flow_open_ack` before raw bytes
begin. An authoritative target policy denial returns only the matching fixed
`flow_open_reject` with reason `denied`; capacity, timeout, malformed framing,
target unavailability, duplicate/replayed IDs, or transport faults close the
stream or session without internal diagnostics. One stream is one TCP flow.
Copies preserve backpressure and TCP half-close semantics; payloads are never
whole-buffered. Closing a stream before sending any frame is an ordinary
stream-local canceled open; a partial frame, malformed frame, duplicate ID, or
extra buffered frame is session-fatal.

The explicit yamux profile uses an eight-stream accept backlog, 256 KiB maximum
stream window, five-second connection writes/stream opens/stream closes,
ten-second keepalive, discarded library logs, and at most 1,024 remembered
flow IDs per authenticated transport. Exhausting the non-evicting replay set
requires reconnecting the exact session; IDs are never evicted and revived.

The current Pod transparent path recovers TCP original destination and presents
ordinary CONNECT host/port plus an optional provider capability hint to
`egressd`. Native egress therefore uses a **TCP flow abstraction**, not raw IP
packets: `network=tcp`, a canonical hostname or IP, port, and optional bounded
capability hint. This preserves the information the existing trusted policy
and injection path consumes without embedding a guest network stack. UDP,
QUIC, and arbitrary packets are not v1 features.

This does not trust the destination. Host, port, and hint are untrusted outbound
intent, even if recovered from a socket. The exact binding selects the trusted
target first. That target independently resolves and validates the destination
and rejects cluster/private/metadata/control-plane addresses. Supplying another
run's target name or any internal service as intent cannot select that target.

The production relay owns a bounded in-memory snapshot mapping each complete
exact Binding to one canonical `http://host:port` per-run `egressd` CONNECT
listener. It starts unpublished and deny-all after every process start. Only
the separate authenticated target-publication contract below can replace the
complete snapshot. No topology is persisted, patched, discovered, or accepted
from a guest. Malformed, duplicate, or over-capacity descriptors reject the
complete publication. Two different Bindings MUST NOT name the same canonical
egressd listener: the target is a per-run authority and cannot be shared
across exact bindings.

For this adapter, each validated Destination becomes exactly one HTTP/1.1
`CONNECT` request whose request authority and `Host` are the canonical
destination host and port. The optional canonical capability hint is copied
only to `X-NVT-Capability`. The adapter sends no proxy authorization, broker
bearer, runtime identity, session credential, provider credential, or injected
secret. It uses structured HTTP request/response handling with a bounded
response header and flow-open deadline. An authoritative egressd `403` maps to
the fixed flow denial; malformed, unavailable, timeout, or other non-success
responses fail closed generically. Only an accepted CONNECT yields the raw
backpressured connection, including TCP half-close semantics.

The workspace yamux purpose is not reused: workspace streams are initiated by
the gateway toward one fixed guest loopback service, while egress flows are
initiated by the guest toward untrusted requested destinations and terminate at
a separately trusted policy service. They use separate TLS sessions,
registries, directional stream rules, and transport implementations despite
pinning the same reviewed yamux release.

## Authenticated target publication

`nvt.native-egress-target-publication/v1` is the implementation-neutral,
operator-to-relay control contract. It is served on a distinct TLS listener and
is never present in guest or agent configuration. The only endpoints are:

| Operation | Method and path |
| --- | --- |
| replace complete snapshot | `POST /v1/native-egress-targets/snapshot` |
| read applied state | `POST /v1/native-egress-targets/status` |

Both require one purpose-specific `nvt_rc1_` bearer in HTTP Authorization.
The relay reads that credential from a private process-owned file and compares
it in constant time. It is never accepted in JSON, flags, argv, environment,
logs, diagnostics, or status. The production operator publisher uses one
explicit HTTPS origin, explicit CA roots, exact DNS server-name verification,
TLS 1.2 or newer, no redirects, and no ambient proxy or credential helper.
Relay and operator processes load the purpose bearer, serving identities, and
CA roots only at startup. A deployment MUST coordinate their rotation as one
fail-closed generation. The Helm integration requires a bounded non-secret
rollout revision on both Pod templates; it MUST change whenever the control
Secret, control/data TLS material, control CA, or broker CA changes. Projected
Secret refresh without that coordinated restart is not credential reload.

A snapshot request contains `contract_version`, `type=replace_snapshot`, a
strictly positive and monotonically increasing 64-bit `generation`, a
`sha256:<lowercase-hex>` content digest, and the complete `targets` array. Each
target contains the complete five-field Binding, fixed target type
`nvt.egressd-connect/v1`, and one canonical CONNECT URL. The array MUST be in
lexicographic raw UTF-8 byte order (AgentRun UID, execution ID, driver
registration, numeric desired generation, guest instance ID; target type and
URL break any remaining tie). The digest is SHA-256 over
the ASCII contract version, one zero byte, the target count as unsigned
32-bit big-endian, then every canonical target. Each string is its UTF-8 byte
length as unsigned 32-bit big-endian followed by those exact bytes. Target
fields are AgentRun UID, execution ID, driver registration, desired generation
as unsigned 64-bit big-endian, guest instance ID, target type, and CONNECT URL.
This binary digest input is independent of JSON escaping and implementation
language. The empty array is valid and intentionally applies deny-all.

Only complete replacement exists. An applied generation may advance with an
identical digest. Equal generation and identical digest is idempotent success;
equal generation with another digest and every lower generation fail closed.
The acknowledgement repeats the exact active generation, digest, and bounded
target count only after target replacement is active and every removed or
replaced exact session has synchronously lost registry readiness and flow-open
authority. An invalid entry or pre-commit cancellation leaves both the prior
complete mapping and publication metadata unchanged. A client disconnect after
the in-memory atomic commit is ordinary response loss: authenticated status or
an idempotent retry confirms the applied pair.

Authenticated status exposes only `published`, the applied generation/digest,
and target count. `published=false`, generation zero, empty digest, and count
zero means process-start unpublished deny-all. `published=true` with a positive
generation, a digest, and count zero means an intentionally applied empty
snapshot. Status never enumerates bindings, endpoints, target types, or
listeners. Process restart always returns to the first state; the trusted
operator lists current exact AgentRun bindings and republishes its complete
desired snapshot before reporting native mediated egress ready. An acknowledged
snapshot without the departing binding is required before identity revocation
or driver cleanup.

Failures use only the versioned `error` body and one of `not-found`,
`capacity-exceeded`, `unauthorized`, `invalid-request`, `conflict`, or
`unavailable`. They do not include a credential, binding, target, digest
diagnostic, parser detail, path, or backend error.

## Bounds and failure behavior

| Resource | v1 maximum/deadline |
| --- | --- |
| JSONL handshake/flow frame | 8 KiB including newline |
| exact active bindings per process | 128 |
| durable identity bindings per authority | 10,000 |
| concurrent identity-authority operations | 64 |
| identity-authority operation | 30 seconds monotonic absolute, from admission through the final pre-commit authorization point |
| active flows per authenticated session | 64 |
| concurrent pending flow opens per session | 8 |
| yamux accept backlog / stream window | 8 / 256 KiB |
| remembered flow IDs per session | 1,024, non-evicting |
| yamux keepalive / connection write | 10 seconds / 5 seconds |
| flow ID | 128 bytes, restricted token syntax |
| destination hostname/IP | 253 canonical ASCII bytes; DNS labels at most 63 bytes, unscoped canonical IP |
| capability hint | 128 bytes, restricted token syntax |
| handshake | 5 seconds absolute |
| broker revalidation/reconnect | no later than 30 seconds |
| target flow open | 5 seconds absolute |
| bidirectional flow inactivity | 2 minutes |
| guest capture TCP connections | 64 total across transparent and explicit CONNECT |
| guest capture readiness lease | exactly one live lease |
| guest capture preface inspection | 16 KiB / 2 seconds |
| target publication snapshot / response | 256 KiB / 4 KiB |
| target publication HTTP headers | 8 KiB |
| target publication targets / concurrent connections | 128 / 16 |
| target publication operation | 10 seconds absolute |
| bounded shutdown | 5 seconds |
| credential lifetime | at most 5 minutes |
| live credentials/sessions per binding | two credentials; active plus standby |

Duplicate keys at any depth, invalid UTF-8, trailing JSON, oversized frames,
non-canonical hosts, unknown operations, guest attempts to select/enumerate a
target, invalid flow IDs, capacity overflow, timeout, cancellation, and target
failure all fail closed. Successful reads or writes refresh one connection-wide
idle deadline so sustained one-way streams are not truncated. No whole payload
is buffered by the contract. Session close, expiry, revocation, replacement,
or process shutdown withdraws registry readiness before closing every flow.
Shutdown initiates closing all bounded sessions/flows concurrently and returns
within the five-second absolute deadline even if a transport's `Close`
implementation does not return; such a transport is failed and cannot retain
registry readiness.

The authority deadline is active before bearer-backed storage lookup. SQLite
busy waits use only its remaining budget, and the operation checks the same
deadline after lock acquisition and immediately before commit. Expiry before
that final authorization point withdraws commit authority and rolls the
transaction back. The timer does not return the operation's capacity lease:
only the owning request releases it after all of its work has unwound. A
blocked hook or OS call can therefore retain a lease past the client cutoff,
but cannot allow replacement work to exceed the bounded concurrency ceiling.
Once the final check has passed and SQLite's synchronous commit system call has
begun, the broker cannot safely interrupt the filesystem commit; a commit
completed across the client cutoff has the ordinary committed-response-loss
semantics and consumes one of the two live slots. The broker never begins a
commit after observing deadline expiry.

## Provisioning and readiness choreography

For a mediated external VM, the trusted owners converge in this order:

1. The operator resolves the installation-owned
   `nvt.native-egress-attachment/v1` plan and durably records only its
   generation/digest in AgentRun status. Missing/inconsistent configuration
   fails before a provider mutation. The exact driver then provisions compute
   with bootstrap networking limited to the relay data endpoint and the plan's
   bounded NVT bootstrap/control destinations;
   the untrusted agent has not started.
2. The driver installs the provider-owned redirect/capture intent and makes
   infrastructure-level allowlist/default-deny confinement durable outside the
   guest. It reads back the exact current attachment before reporting
   `egress_confinement:{boundary:"infrastructure",ready:true,attachment_generation:<current>,attachment_digest:<current>}`.
3. The existing one-time exact guest enrollment completes inside that confined
   bootstrap network. Its separately authenticated handoff may carry the
   operator-owned public per-run interception CA (certificate PEM only, at
   most 16 KiB) to the exact guest after the confinement read-back. The CA
   private key remains solely with egressd. No provider or egress credential is
   carried in the envelope, desired fingerprint, driver status, or provider
   tags.
4. The active runtime identity obtains the short-lived egress credential under
   the fixed purpose. `nvt-guest-egressd` authenticates the outbound session
   and activates its root-only local flow socket. The separate
   `nvt-guest-captured` process accepts transparent traffic with no capability
   hint or a bounded explicit CONNECT carrying the existing per-flow provider
   selector, consumes that preface, and opens only through the current socket.
   The provider still owns redirect installation; this guest-local plumbing is
   not a confinement assertion.
5. The relay resolves only the exact binding to its already-ready separate
   trusted per-run egress target. A test flow/readiness exchange confirms the
   complete route.
6. When configured, the trusted guest supervisor holds a live
   capture-plus-tunnel readiness lease before starting the untrusted agent.
   Capture process death or tunnel withdrawal closes the lease, removes guest
   readiness, and stops the session; no stale file can remain authoritative.
   The operator may report mediated VM readiness only after the current
   attachment generation/digest and driver confinement assertion, current exact tunnel,
   and current target are all ready. Driver `ready` alone is insufficient.

`NativeEgressAttachment` and `EgressConfinementStatus` are optional additive
members of `nvt.execution-driver/v1` desired/status. Their provider-neutral
shape, canonical digest, and bounds are frozen in
[`execution-driver.md`](execution-driver.md). The only confinement boundary
token is `infrastructure`; guest-local controls cannot assert it. Omission
preserves the wire behavior of existing Pod and non-mediated drivers. The
operator gate requires the exact current desired observation and never infers
it from an endpoint, provider ID, class configuration, or guest report.

Provider state, execution desired state, the binding status, and broker durable
identity state—not in-memory call history—must recover convergence after an
operator, driver, relay, target, or guest restart.

## Revocation and cleanup ordering

Generation change, guest replacement, AgentRun deletion/deadline/terminal
state, broker denial, credential expiry, or revalidation failure first removes
egress readiness and stops new flows. The relay closes existing flows and
removes exact routing, then the broker durably revokes the exact binding or
execution scope. Cleanup retries until both routing removal and revocation are
acknowledged. Only then may the driver relax/delete provider network
confinement and remove the VM/NIC. Finalizers remain until the complete order
converges. No fallback binding, driver, target, or Pod may be tried.

## Conformance and current boundary

`protocol/guestenrollment/nativeegress` provides strict framing, authentication,
exact target routing, the pinned bounded yamux transport, idle deadlines, and a
concurrent active/standby registry. Its hermetic tests use real multiplexed byte
streams and a fake policy target. They cover exact and mismatched bindings,
wrong purpose, expiry/revocation, restart/response loss, cross-run/private
intent, flow framing, concurrent and large transfers, half-close, one-way
activity, capacity, cancellation, replacement, shutdown, ordering, and
redaction under the race detector.

The production broker implements the four identity operations and shares their
SQLite lifecycle, exact revocation, tombstones, and maintenance with guest
enrollment/runtime identity. The host bundle includes a separate opt-in trusted
client/service which obtains only the short-lived purpose credential through
root-only IPC, validates explicit relay CA/SNI/TLS, reconnects with the current
credential, and renews make-before-break with at most current plus pending in
memory. The standalone relay core terminates explicit TLS, authenticates the
bearer through that broker authority, resolves a target only by complete exact
Binding, and owns the shared bounded active/standby registry. Its production
command starts deny-all and exposes a distinct authenticated TLS publication
surface for complete in-memory snapshots. The coordinated non-root relay OCI
image contains only the static relay binary. The opt-in chart deployment and
operator publication loop now consume that boundary. Once a current snapshot
is applied, the relay routes
every flow only through the exact binding's selected adapter. Mapping
replacement or removal synchronously stops new opens, withdraws the associated
session, and does not migrate existing flows to another target. The relay sends
`hello_ack` only after the authenticated session has secured both the exact
target and its bounded active/standby reservation, then switches the connection
to the bounded flow data plane. The host-bundle client proves that yamux is
live and then exposes a strict root-only local stream socket. A separate
credential-less Linux process recovers the kernel original TCP destination,
optionally refines
the hostname from bounded HTTP Host/TLS SNI, and preserves the preface bytes.
Its transparent listener always carries an empty capability hint. Its explicit
CONNECT listener accepts the same bounded per-flow provider selector as the
Pod path, consumes CONNECT/proxy-auth framing, and forwards only raw bytes.
The canonical host/IP, port, and optional explicit capability are untrusted
flow intent; no flow chooses a relay target. Session withdrawal closes local
health leases and captured flows without fallback. The supervisor retains a
live readiness socket lease rather than trusting a reusable marker.

The operator now deploys the relay and per-run egressd target, republishes the
complete snapshot after either process restarts, gates `NativeEgressReady` on
the acknowledged exact mapping and the current attachment/confinement
observation, and withdraws it before authority or driver cleanup. The optional
desired plan now tells a provider what it must attach without vendor fields.
The unpublished QEMU reference driver consumes that plan and provides the
hermetic provider proof: `restrict=on` is enforced by QEMU outside the
guest, exact host-owned forward rules admit only the relay/bootstrap/control
destinations, and live process-argument read-back gates enrollment. Its guest
redirect is explicitly non-authoritative. The TCG lifecycle reaches the
hermetic upstream only through capture, the authenticated relay, and the exact
per-run egressd; it also proves revocation, restart, and cleanup. The
separately packaged Azure driver is the first production-shaped provider
implementation: it uses Workload Identity, an embedded reviewed ARM template,
protected SSH bootstrap, and exact Azure NSG/resource readback. Its fake-ARM
conformance is automated, while live Azure infrastructure and public relay
ingress remain explicit installation gates; repository CI does not claim a
credentialed live-Azure proof.
Existing Pod/Kata/Compose egress and native control/workspace/browser routing
remain unchanged. A production Azure deployment still requires the separate
resource group/subnet fence, immutable image, UAMI/federated identity, custom
role, and relay ingress created by installation infrastructure. The QEMU
reference remains deliberately unpublished.
