# Execution driver protocol

`nvt.execution-driver/v1` is the portable contract between the NVT operator and
a trusted execution implementation. It describes convergence and observation
of one approved execution independently of process or deployment topology.

`operator/executiondriver/host` provides a trusted local-executable transport.
Production drivers are distributed as complete OCI images pinned by SHA-256
digest and run in isolated driver-host workloads; source acquisition is not an
execution-driver runtime contract. AgentRun execution selects either the
behavior-preserving built-in Kubernetes Pod adapter or one exact registered
external driver host. Production provider drivers remain separate work.

The complete driver image is distinct from the
[native guest host bundle](host-bundle.md). The driver image is an executable
control-plane workload. The host bundle is a non-runnable OCI artifact that a
future provider driver installs by digest inside a provisioned Linux guest.
Neither contract uses Git acquisition in production.

Native VM bootstrap uses the separate sensitive
[guest enrollment contract](guest-enrollment.md). Its one-time token and
runtime identity are never fields of `DesiredExecution`, class configuration,
desired fingerprints, portable status, or ordinary driver state. A provider
driver may deliver only the opaque encoded envelope through the separately
versioned exact-registration handoff; reconcile remains credential-free.

An execution driver is trusted operator code, not an agent plugin or a sandbox
boundary. A future driver host may give it provider credentials. Drivers must
not expose credentials, provider response bodies, request headers, or other
secret material through protocol results, errors, stderr, resource IDs, or
endpoints.

## Ownership boundary

The operator owns:

- authenticating and authorizing the work principal and selecting one exact
  administrator-approved driver and class;
- resolving and canonicalizing the complete desired tuple, advancing its
  generation, and computing its opaque fingerprint;
- AgentRun conditions, history, timeouts, retries, requeues, and terminal
  lifecycle decisions;
- finalizers, broker revocation, and deciding when AgentRun deletion is
  complete;
- process supervision and the failure policy for crashes, malformed output,
  timeouts, and unavailable drivers; and
- ensuring producer input cannot choose a driver source, class configuration,
  executable, environment, or credential.

The driver owns:

- level-triggered convergence against its provider APIs;
- observing provider resources without creating them;
- removing every resource it owns for an execution; and
- reconstructing correctness from the request plus durable provider state after
  any operator or driver-process restart.

Initialization state for one protocol connection and disposable caches may be
in memory. Resource identity, convergence, and cleanup correctness may not be.
A driver must use the stable execution ID in durable provider identifiers,
tags, or equivalent indexes so a fresh process can find all owned resources.
A configured driver is exact: failure must never cause the operator to try a
different driver.

## Transport and framing

The protocol is JSON-RPC 2.0 over a long-lived process's stdin and stdout. Both
are UTF-8 JSONL streams with exactly one compact JSON object per line. stdout is
protocol-only. Request IDs are unique non-empty strings, and responses repeat
the exact ID. Responses may be produced out of order. The operator sends at
most one mutating request (`reconcile` or `delete`) at a time for an execution;
requests for different executions may overlap.

A line, including its newline, is limited to 1 MiB. Invalid UTF-8 is rejected
before JSON decoding; decoders must not replace invalid bytes with Unicode
replacement characters. Duplicate JSON object keys are forbidden recursively
in every request, response, result, error, and nested driver configuration.
This includes keys that become equal after JSON escape decoding. Oversized,
malformed, ambiguous, unknown-ID, duplicate-ID, or invalid-version responses
invalidate that process generation. Raw protocol lines and stderr must not be
copied into AgentRun status or ordinary operator logs.

Every request has this envelope:

```json
{"jsonrpc":"2.0","id":"request-1","method":"observe","params":{"execution_id":"opaque-stable-id"}}
```

A successful response contains `result` and no `error`:

```json
{"jsonrpc":"2.0","id":"request-1","result":{"phase":"running","ready":true,"endpoint":{"scheme":"https","host":"agent.internal","port":443},"external_resource_id":"provider-resource-123","observed_generation":4}}
```

An operation error contains `error` and no `result`:

```json
{"jsonrpc":"2.0","id":"request-1","error":{"code":-32000,"message":"driver error","data":{"reason":"provider-unavailable","message":"provider is temporarily unavailable","retryable":true}}}
```

Driver error codes are reserved from `-32000` through `-32099`. The outer
message is always the fixed string `driver error`. `data.reason` is a stable
lowercase token of at most 128 bytes; `data.message`, when present, is sanitized
UTF-8 text of at most 1024 bytes; and `data.retryable` is advisory. The operator
still owns retry and deadline policy.

There is no protocol cancellation operation in v1. When a request exceeds its
operator-owned deadline, the process generation is terminated and reaped. A
provider call may already have taken effect, so the replacement process must
recover through the same stable `execution_id` rather than assume that a timed
out create did nothing.

## Trusted local executable host

The optional local host starts one exact administrator-supplied absolute
executable path directly, without a shell, using `/` as its deterministic
working directory. Its child environment begins empty. Every name in `PassEnv`
is required to exist for every process generation; the host copies values for
those exact names and fails before launch if one is absent. No `PATH`, `HOME`,
credential, or other operator variable is inherited implicitly. Optional
variables require a separate future contract rather than implicit omission.
Scripts must therefore name an absolute interpreter or explicitly allowlist
every environment variable needed by that interpreter. The executable is
trusted operator extension code, not a sandbox.

The host implements a small `Client` interface using the portable desired and
status types. Its local-process implementation serializes all calls for v1; a
future dedicated driver-host workload can implement the same boundary without
changing callers. Initialization and every operation are bounded by both the
caller context and an explicit host deadline. Request IDs are unique for the
host lifetime, and strict JSONL framing, size, UTF-8, duplicate-key, response-ID,
and result validation are applied before a response is trusted.

Timeouts, malformed or unsolicited output, duplicate or mismatched responses,
and transport failures invalidate that exact process generation. The host
closes its pipes, terminates and then kills the isolated process group when
needed, and reaps the child. Raw stderr is drained into a small bounded private
buffer and is never returned or logged. A valid sanitized driver error remains
an operation result and does not invalidate an otherwise healthy process.

After a crash or invalid process generation, the failed call returns without
replay. Calls during the fixed bounded backoff fail explicitly. A later caller
may start and negotiate the same selected executable after backoff; the host
never chooses a fallback driver. Once `shutdown` begins, new calls fail closed.
An idle generation receives protocol shutdown followed by bounded
terminate/kill/reap cleanup. If an operation is active, shutdown terminates and
reaps that exact generation immediately instead of waiting for the serialized
operation; the failed operation is never replayed.

The standalone driver-host service uses this transport to launch the explicit
driver command already present in one digest-pinned provider image. The image
owns its language runtime and dependencies; the host performs no cloning,
build, package installation, hook, or source acquisition. External AgentRun
reconciliation reaches it only through the authenticated host API for the
exact logical registration.

### Dedicated OCI driver-host workload

The production distribution unit is one complete provider OCI image pinned by
`sha256` digest. The image contains the selected driver executable, its
language runtime, and every dependency. A coordinated static
`nvt-execution-driver-host` binary is copied into an `emptyDir` by an init
container and then becomes PID 1 inside the provider image. It invokes the
registered absolute command through `LocalExecutable`; it does not clone,
build, install packages, execute hooks, scan the image, or discover a fallback.

Registrations are administrator-owned installation configuration. Each
logical registration renders an independent Deployment, ClusterIP Service,
ServiceAccount selection, infrastructure-credential projection, TLS
certificate, bearer authentication token, and ingress NetworkPolicy. Reusing
one provider-image digest in two registrations still creates two process and
credential boundaries. Provider credentials enter only their matching Pod.
Explicit `passEnv` names allow approved workload-identity webhook variables
into the otherwise empty child environment; every name is required at process
start. Explicitly projected Secret environment names are included in the same
allowlist. Secret files use fixed, registration-owned mount roots. The operator
receives the per-host CA and transport token, not provider credentials.

The service wraps the portable operations in bounded HTTPS requests. It
requires both certificate validation and the exact registration bearer token;
NetworkPolicy is an additional ingress boundary, not authentication. Bodies
are limited to the protocol message bound and decoded with the same invalid
UTF-8, duplicate-key, and result validation rules. Transport failures expose a
fixed diagnostic rather than driver output or payloads. Kubernetes readiness
tracks the negotiated child process, and liveness restarts a host whose child
has exited; termination still applies the bounded protocol shutdown and
terminate/kill/reap behavior.

This deployment does not change the JSONL execution-driver protocol. The
AgentRun controller resolves only the immutable logical driver name snapshotted
by admission, adds its cleanup finalizer before the first mutating call, and
reconciles through that exact authenticated host. It never falls back to
Kubernetes or another registration. Runtime-plugin and executable
broker-provider Git loading are separate extension contracts and are
unchanged; Git acquisition is not an execution-driver distribution mechanism.

The operator derives the opaque execution ID from the immutable AgentRun UID
and computes the desired fingerprint over the snapshotted workload kind, class
name, and canonical configuration. Provider convergence therefore survives
operator and host restarts without in-memory call history. Removing a
registration while runs reference it is unsupported: cleanup retains the
finalizer until the same registration is restored. Driver readiness remains a
portable observation and does not by itself publish a gateway route.

The operator owns active deadlines, terminal operational-resource TTLs, and
AgentRun retention independently. A deadline or expired completed/failed
resource TTL drives level-triggered `delete` through the exact selected driver;
the cleanup finalizer remains until `deleted`, while the terminal AgentRun may
remain for its separate retention interval. Non-retryable convergence failure
is a sanitized terminal AgentRun failure. Once cleanup is owed, every failure
remains retryable by controller policy so a repaired exact registration can
finish deletion. External host calls are synchronously bounded and admitted
below the controller worker count so stalled hosts cannot consume all capacity
needed by the built-in Kubernetes backend.

## Version and operations

The exact v1 protocol string is `nvt.execution-driver/v1`. The first request on
each process generation is `initialize`. The advertised `reconcile`, `observe`,
and `delete` capabilities are all required in v1; `initialize` and `shutdown`
are process-lifecycle methods rather than advertised capabilities. Negotiation
lets a future protocol version evolve without assuming implementation language.

### `initialize`

```json
{"jsonrpc":"2.0","id":"initialize-1","method":"initialize","params":{"protocol_version":"nvt.execution-driver/v1","driver_instance_name":"approved-driver"}}
```

```json
{"jsonrpc":"2.0","id":"initialize-1","result":{"protocol_version":"nvt.execution-driver/v1","capabilities":["reconcile","observe","delete"]}}
```

`driver_instance_name` identifies operator configuration, not a producer value.
The result must contain each v1 capability exactly once and no unknown
capability. A version or capability mismatch fails initialization.

### `reconcile`

`reconcile` is level-triggered. `generation` represents the complete desired
tuple: `workload_kind`, `class_name`, and the fully resolved
`configuration`. The trusted operator/driver host canonicalizes that tuple,
computes its SHA-256 fingerprint, and sends the lowercase
`sha256:<64-hex-digits>` value as `desired_fingerprint`. The operator must
increment generation and change the fingerprint whenever any tuple member
changes. Execution ID and generation are not fingerprint inputs.

The driver durably stores the greatest accepted generation together with a
`desired_fingerprint`.
Repeating the same generation and tuple is idempotent and converges the same
logical resource. A lower generation is rejected as non-retryable
`stale-generation` without changing durable or provider state. The same
generation with a different fingerprint is rejected as non-retryable
`generation-conflict`, also without changing state. These checks apply after a
driver-process or operator restart. A higher generation updates the same
logical resource according to driver policy; it must not create an untracked
replacement.

The fingerprint is opaque to the external driver. It validates the bounded
shape, persists it, and compares it byte-for-byte; it does not canonicalize
configuration or recompute the digest. Canonicalization is operator-owned so
Python, JavaScript, Rust, shell, and other drivers do not need matching JSON
number or object-order algorithms. Duplicate keys remain invalid at the
operator protocol boundary rather than being resolved by order.
The host must snapshot or deterministically reproduce the same fingerprint for
an unchanged tuple across operator restarts and upgrades. Any intentional
fingerprint-algorithm transition requires a new generation.

A matching generation and fingerprint do **not** permit returning cached
status. Every `reconcile` must observe provider state and repair drift toward
the unchanged desired tuple while preserving the same logical resource.

The configuration is a bounded JSON object resolved from administrator-owned
class configuration. It is never an AgentRun producer surface and must not
carry credentials; future driver hosts provide explicitly
allowlisted provider credentials outside desired state.

```json
{"jsonrpc":"2.0","id":"reconcile-4","method":"reconcile","params":{"desired":{"execution_id":"opaque-stable-id","generation":4,"desired_fingerprint":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","workload_kind":"vm","class_name":"approved-small","configuration":{"region":"example-1"}}}}
```

`configuration` is limited to 256 KiB within the 1 MiB message bound.
`execution_id` is a stable opaque value of at most 256 bytes. Drivers must not
interpret it as a filesystem path or infer authorization from it.
`workload_kind` is exactly `pod` or `vm`; provider-specific workload kinds do
not belong in this portable version.

### `observe`

`observe` reports current provider state without creating or mutating provider
resources. It is safe to repeat. An execution that has no remaining
driver-owned resource returns the portable `deleted` phase. Provider
unavailability or an incomplete/unauthorized listing is an error, never proof
that the resource is deleted.

```json
{"jsonrpc":"2.0","id":"observe-4","method":"observe","params":{"execution_id":"opaque-stable-id"}}
```

### `delete`

`delete` is level-triggered and idempotent. It removes all resources owned by
the execution, including subordinate compute, disks, routes, and identities.
Absence is success. While deletion is still converging it returns `deleting`;
only a valid `deleted` observation means driver cleanup is complete. Deletion
intent and progress must be durable enough for a fresh process to rediscover
and continue cleanup. `observe` during that interval returns `deleting` without
creating resources, and repeated `delete` continues the same cleanup operation.

```json
{"jsonrpc":"2.0","id":"delete-4","method":"delete","params":{"execution_id":"opaque-stable-id"}}
```

The operator retains its finalizer until the selected driver returns `deleted`
and the operator's own cleanup and revocation are complete. A process exit,
`shutdown` response, request timeout, or missing provider resource is not by
itself permission to remove the finalizer.

### `shutdown`

```json
{"jsonrpc":"2.0","id":"shutdown-1","method":"shutdown","params":{}}
{"jsonrpc":"2.0","id":"shutdown-1","result":{}}
```

`shutdown` requests bounded process termination. It never means resource
deletion and must not mutate provider resources. The only valid successful
result is the exact empty JSON object shown above; `null`, arrays, and objects
with members are protocol failures. A valid response acknowledges the request
but does not complete shutdown: the host continues applying the same deadline
until the process exits. If it remains alive, the operator terminates and reaps
it. When an operation is already active, the host does not send another JSONL
request; it closes the client and terminates that process generation directly.

## Portable status

`reconcile`, `observe`, and `delete` return one complete status object:

| Field | Contract |
| --- | --- |
| `phase` | One of `pending`, `provisioning`, `running`, `succeeded`, `failed`, `deleting`, `deleted`, or `unknown`. |
| `ready` | `true` only for a `running` execution with a valid reachable endpoint after every driver-owned execution-class requirement has converged: compute, required storage, network isolation/enforcement, and any required egress attachment. |
| `endpoint` | Optional `{scheme,host,port}` using `http` or `https`; no credentials, URL userinfo, query, or fragment. |
| `external_resource_id` | Optional opaque sanitized provider identifier, at most 2048 bytes. It is diagnostic, never authorization. |
| `observed_generation` | Non-negative desired generation represented by this observation; zero is allowed when no desired resource exists. |
| `retry_after_seconds` | Optional bounded convergence hint from 1 through 3600. The operator decides the actual requeue. |
| `failure` | Required only for `failed`; the same bounded sanitized `{reason,message,retryable}` shape as error data. |

`deleted` must not retain readiness, endpoint, external resource ID, or failure
data. These portable phases are driver observations, not AgentRun conditions.
Only the operator maps a validated observation into AgentRun status and decides
whether a reported failure is terminal under the authorized lifecycle policy.
The driver's `ready` assertion is necessary but not sufficient for an AgentRun
to become routable: the operator combines it with operator-owned broker grants,
gateway routing, and workload-readiness conditions.

## Conformance fixture

`operator/executiondriver/testdata/fake-driver` is a test-only executable. Its
conformance suite starts real processes over JSONL and verifies initialization,
reconciliation, readiness, generation monotonicity/divergence, observation,
same-generation drift repair, durable asynchronous deletion, bounded shutdown,
repeated requests, abrupt restart recovery, recursively ambiguous JSON
rejection, malformed output, bounded timeout termination and reaping, sanitized
failures, and final resource-state cleanup. It is deliberately not a production
driver loader or a Kubernetes implementation.
