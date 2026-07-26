# Execution driver protocol

`nvt.execution-driver/v1` is the portable contract between the NVT operator and
a trusted execution implementation. It describes convergence and observation
of one approved execution; it does not describe how an executable is acquired,
configured, or supervised.

This first protocol phase does not load production drivers and does not place
the existing Kubernetes Pod reconciler behind this interface. Pod-backed
AgentRuns therefore render and reconcile exactly as before. Local executable
loading, immutable Git acquisition, execution profiles/classes, the Kubernetes
adapter, and production VM drivers are separate work.

An execution driver is trusted operator code, not an agent plugin or a sandbox
boundary. A future driver host may give it provider credentials. Drivers must
not expose credentials, provider response bodies, request headers, or other
secret material through protocol results, errors, stderr, resource IDs, or
endpoints.

## Ownership boundary

The operator owns:

- authenticating and authorizing the work principal and selecting one exact
  administrator-approved driver and class;
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

A line, including its newline, is limited to 1 MiB. Oversized, malformed,
unknown-ID, duplicate-ID, or invalid-version responses invalidate that process
generation. Raw protocol lines and stderr must not be copied into AgentRun
status or ordinary operator logs.

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

`reconcile` is level-triggered. Repeating the same desired generation must be
safe and must converge the same logical resource. A higher generation updates
that logical resource according to driver policy; it must not create an
untracked replacement. The configuration is a bounded JSON object resolved
from administrator-owned class configuration. It is not an AgentRun producer
surface in this protocol phase and must not carry credentials; future driver
hosts provide explicitly allowlisted provider credentials outside desired
state.

```json
{"jsonrpc":"2.0","id":"reconcile-4","method":"reconcile","params":{"desired":{"execution_id":"opaque-stable-id","generation":4,"workload_kind":"vm","class_name":"approved-small","configuration":{"region":"example-1"}}}}
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
only a valid `deleted` observation means driver cleanup is complete.

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
deletion and must not mutate provider resources. If it does not complete within
the host deadline, the operator terminates and reaps the process.

## Portable status

`reconcile`, `observe`, and `delete` return one complete status object:

| Field | Contract |
| --- | --- |
| `phase` | One of `pending`, `provisioning`, `running`, `succeeded`, `failed`, `deleting`, `deleted`, or `unknown`. |
| `ready` | `true` only for a `running` execution with a valid endpoint. |
| `endpoint` | Optional `{scheme,host,port}` using `http` or `https`; no credentials, URL userinfo, query, or fragment. |
| `external_resource_id` | Optional opaque sanitized provider identifier, at most 2048 bytes. It is diagnostic, never authorization. |
| `observed_generation` | Non-negative desired generation represented by this observation; zero is allowed when no desired resource exists. |
| `retry_after_seconds` | Optional bounded convergence hint from 1 through 3600. The operator decides the actual requeue. |
| `failure` | Required only for `failed`; the same bounded sanitized `{reason,message,retryable}` shape as error data. |

`deleted` must not retain readiness, endpoint, external resource ID, or failure
data. These portable phases are driver observations, not AgentRun conditions.
Only the operator maps a validated observation into AgentRun status and decides
whether a reported failure is terminal under the authorized lifecycle policy.

## Conformance fixture

`operator/executiondriver/testdata/fake-driver` is a test-only executable. Its
conformance suite starts real processes over JSONL and verifies initialization,
reconciliation, observation, deletion, shutdown, repeated requests, durable
restart recovery, malformed output, bounded timeout termination and reaping,
sanitized failures, and resource-state cleanup. It is deliberately not a
production driver loader or a Kubernetes implementation.
