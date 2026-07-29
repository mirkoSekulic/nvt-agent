# Native VM mediated-egress contract

Status: versioned provider-neutral contract and hermetic conformance proof
(`nvt.native-egress/v1`) with a production broker identity authority. No
production tunnel, host-bundle client, provider network implementation, or VM
egress wiring exists yet.

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
future egress connections are guest-initiated outbound connections.

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
- **Trusted guest egress client:** retains the egress credential transiently,
  establishes the outbound session, and turns locally captured TCP destinations
  into bounded untrusted flow intent. It is not the bypass boundary.
- **Native egress relay:** authenticates the credential and binding, keeps a
  bounded exact-binding registry, and selects the one preconfigured trusted
  target for that binding. It never resolves a target by partial scope or guest
  destination.
- **Per-run trusted egress target:** remains authoritative for hostname/DNS and
  IP validation, private-address denial, broker grants, quotas, audit, TLS
  mediation, and credential injection. A future adapter may use the current
  per-run `egressd` service, but no Kubernetes Service name is part of this
  generic contract.

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

Only equal-sequence reconnect or a higher sequence may stand by. Older replay
is rejected. One active plus one already-authenticated standby is the maximum;
a third fails closed. A standby never preempts active. The obsolete transport
session is withdrawn and closed after the ready replacement is promoted. Exact
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

After authentication, the transport maps one validated `flow_open` intent to
one backpressured byte stream. The generic interface deliberately does not
select a multiplexing, packet, VPN, cloud, or overlay technology. No library
type crosses the NVT interface.

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

The workspace yamux purpose is not reused: workspace streams are initiated by
the gateway toward one fixed guest loopback service, while egress flows are
initiated by the guest toward untrusted requested destinations and terminate at
a separately trusted policy service. A later implementation may choose a
reviewed multiplexing or packet transport behind this interface.

## Bounds and failure behavior

| Resource | v1 maximum/deadline |
| --- | --- |
| JSONL handshake/flow frame | 8 KiB including newline |
| exact active bindings per process | 128 |
| durable identity bindings per authority | 10,000 |
| concurrent identity-authority operations | 64 |
| identity-authority operation | 30 seconds absolute |
| active flows per authenticated session | 64 |
| concurrent pending flow opens per session | 8 |
| flow ID | 128 bytes, restricted token syntax |
| destination hostname/IP | 253 canonical ASCII bytes; DNS labels at most 63 bytes, unscoped canonical IP |
| capability hint | 128 bytes, restricted token syntax |
| handshake | 5 seconds absolute |
| broker revalidation/reconnect | no later than 30 seconds |
| target flow open | 5 seconds absolute |
| bidirectional flow inactivity | 2 minutes |
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

## Provisioning and readiness choreography

For a mediated external VM, the trusted owners converge in this order:

1. The exact driver provisions compute and a bootstrap-only NIC/network policy.
   The untrusted agent has not started.
2. The provider makes the infrastructure-level allowlist/default-deny policy
   durable and reads it back. Only then may the driver report
   `egress_confinement:{boundary:"infrastructure",ready:true}`.
3. The existing one-time exact guest enrollment completes inside that confined
   bootstrap network; no provider or egress credential is carried in the
   envelope, desired fingerprint, driver status, or provider tags.
4. The active runtime identity obtains the short-lived egress credential under
   the fixed purpose. The future guest client authenticates the outbound tunnel.
5. The relay resolves only the exact binding to its already-ready separate
   trusted per-run egress target. A test flow/readiness exchange confirms the
   complete route.
6. The trusted guest supervisor may start the untrusted agent. The operator may
   report mediated VM readiness only after the current driver generation's
   confinement assertion, current exact tunnel, and current target are all
   ready. Driver `ready` alone is insufficient.

`EgressConfinementStatus` is an optional additive field of
`nvt.execution-driver/v1` portable status. Its only boundary token is
`infrastructure`; guest-local controls cannot assert it. Omission preserves the
wire behavior of existing Pod and non-mediated drivers. A future mediated-VM
operator gate must require presence and `ready:true`; it must never infer the
assertion from an endpoint, provider ID, class configuration, or guest report.

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
exact target routing, bounded sessions/flows, idle deadlines, and a concurrent
active/standby registry. Its hermetic tests use real local byte streams and a
fake policy target. They cover exact and mismatched bindings, wrong purpose,
expiry/revocation, restart/response loss, cross-run/private intent, capacity,
cancellation, replacement, shutdown, ordering, and redaction under the race
detector.

The production broker implements the four identity operations and shares their
SQLite lifecycle, exact revocation, tombstones, and maintenance with guest
enrollment/runtime identity. This phase does not implement a production relay
or guest client, host-bundle wiring, egressd/captured behavior, provider network
policy, Azure/AWS/QEMU support, or operator readiness/cleanup orchestration.
Existing Pod/Kata/Compose egress and native control/workspace/browser routing
remain unchanged. Production VM mediated egress requires those later reviewed
implementation gates and a real provider enforcement proof.
