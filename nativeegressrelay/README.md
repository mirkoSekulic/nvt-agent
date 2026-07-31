# Native egress relay core

`nvt-native-egress-relay` is the provider-neutral cluster-side authenticated
session boundary for [`nvt.native-egress/v1`](../protocol/native-egress.md).
It accepts the guest-initiated TLS connection, authenticates the
`nvt_eg1_` bearer through the broker, resolves only the complete five-field
guest binding through an in-process `TargetResolver`, and admits the shared
active/standby `SessionRegistry`. After admission it serves the bounded pinned
yamux flow transport and routes each validated stream only through that exact
session's already-selected `EgressTarget`.

Authentication is staged: the relay reads and authenticates the bounded hello,
resolves the exact target, and reserves the active/standby slot before sending
`hello_ack`. Capacity rejection and older replay therefore close without an
acknowledgement and cannot cause the guest to publish readiness. An ACK write
failure removes its reservation.

The command constructs a production `EgressdTargetRegistry` with no targets.
Every process start is unpublished and deny-all. A distinct authenticated TLS
control listener accepts only complete, monotonically versioned snapshots from
the trusted operator publisher. Each entry maps one complete five-field
Binding to exactly one canonical per-run egressd CONNECT listener. Each
canonical listener may appear for only one Binding; sharing it would cross the
per-run grant and credential boundary. Target lookup is exact-only, and guest
destination input can never choose an endpoint, run, or driver.

Publication is atomic and in-memory only. Invalid or pre-commit canceled
requests preserve the complete prior map and generation/digest. Removed or
replaced mappings synchronously lose flow-open authority and exact session
readiness before the ACK; unchanged bindings stay active. Restart discards all
topology and requires a fresh complete publication. There is no patch,
enumeration, fallback, endpoint discovery, persistence, or unauthenticated
registration API.

Target admission uses a per-target active/draining epoch. The global snapshot
lock protects only bounded map transitions; it is never retained while a guest
receives its acknowledgement or while egressd dial/CONNECT I/O runs. A changed
target first rejects and cancels new admissions, then drains its finite
admission references. Exact session flow authority is synchronously withdrawn
before the replacement snapshot becomes visible; that visibility transition
is the revocation linearization point. Unchanged target epochs remain
independently usable while another binding drains.

Configuration version 2 makes the separate control listener mandatory and
removes the version-1 startup `egressd_targets` member. Version 1 is rejected
rather than silently carrying target authority across a process restart.

The Helm chart can deploy this command only when explicitly enabled. It copies
administrator-owned projected TLS and control material into a memory-backed
owner-only volume for the non-root process, exposes separate ClusterIP data and
control Services, and restricts the control port to the operator. The operator
uses authenticated status after restart and republishes the complete snapshot
before setting per-run native-egress readiness. Provider ingress routing and
infrastructure confinement remain separate future gates.

The copy step runs as root and handles the serving private keys and control
bearer. Its chart default is therefore an exact multi-architecture image
digest, and an enabled installation rejects an init-image override without a
canonical `sha256` digest. Repository/digest changes are trusted-supply-chain
changes that must be reviewed with the fixed copy script; mutable tags are not
supported for this boundary.

Relay and operator clients load control credentials, serving identities, and
CA trust once at process start. The chart requires one shared non-secret
`nativeEgressRelay.rolloutRevision`; administrators MUST change it with every
control-token, control/data TLS, control CA, or broker CA rotation so both
Deployments roll as one fail-closed credential generation. Secret projection
alone is not a supported hot-reload mechanism. Both Deployments use `Recreate`
while this process-local single-replica contract is enabled, so old and new
publication/session owners never overlap.
The init-image digest is independent of credential generations: changing it
rolls the Pod template but does not replace the requirement to increment
`rolloutRevision` whenever any credential or CA rotates.

## Configuration

The command reads one strict process-owned JSON file. It does not read
credentials from flags or environment variables:

```json
{
  "version": 2,
  "listen_address": "0.0.0.0:7445",
  "tls_certificate_file": "/run/nvt-native-egress-relay/tls.crt",
  "tls_key_file": "/run/nvt-native-egress-relay/tls.key",
  "control_listen_address": "0.0.0.0:7446",
  "control_tls_certificate_file": "/run/nvt-native-egress-relay/control-tls.crt",
  "control_tls_key_file": "/run/nvt-native-egress-relay/control-tls.key",
  "control_credential_file": "/run/nvt-native-egress-relay/control-token",
  "control_timeout_seconds": 10,
  "broker_url": "https://nvt-broker.nvt.svc.cluster.local:8443",
  "broker_server_name": "nvt-broker.nvt.svc.cluster.local",
  "broker_ca_file": "/run/nvt-native-egress-relay/broker-ca.crt",
  "authentication_timeout_seconds": 5,
  "revalidation_interval_seconds": 30
}
```

The default path is `/etc/nvt-agent/native-egress-relay.json`; `--config` may
select another absolute file. The configuration, both private keys, and the
control credential must be owner-only, regular, non-symlink, single-link files
owned by the process effective UID. Serving certificates and the broker CA may
be group/world readable but must be process-owned and not group/world
writable. All paths are absolute and canonical. The broker is one canonical
HTTPS origin with exact explicit DNS SNI and CA trust; system roots, redirects,
environment proxies, plaintext fallback, and credential helpers are not used.

Authentication timeout is positive and at most the frozen five-second
handshake deadline. Revalidation is positive and at most 30 seconds. The
control timeout is positive and at most ten seconds. Guest and control listen
addresses and serving identities are distinct. The purpose credential is
canonical `nvt_rc1_` material loaded only from its mode `0600` file and is
compared in constant time.

The operator-side publisher contract requires explicit TLS 1.2+ CA and exact
server-name trust, forbids redirects and ambient proxies, and uses only:

- `POST /v1/native-egress-targets/snapshot` for a complete canonical snapshot;
- `POST /v1/native-egress-targets/status` for bounded non-topological state.

An applied empty snapshot is published deny-all. It differs from process-start
unpublished deny-all through the authenticated `published` status bit and
positive generation/digest. Status never lists bindings or listeners.

Each target URL is canonical `http://host:port`. The adapter sends the
validated Destination as HTTP/1.1 CONNECT authority and `Host`, and sends the
optional bounded capability selector only as `X-NVT-Capability`. It uses
structured bounded response parsing and returns a byte-stream connection only
after egressd accepts CONNECT. It never requests or receives broker/provider
credentials, sends no proxy authorization, and does not expose egressd response
details in relay errors. Credential resolution, destination policy, private-
address denial, audit, quota, TLS mediation, and injection remain exclusively
inside the exact per-run egressd path.

The listener requires TLS 1.2 or newer. At most 32 pre-authentication TLS/
broker handshakes run concurrently, while the frozen registry bounds 128 exact
bindings with one active and one authenticated equal/newer standby each. Each
broker-derived local trust interval is capped at 30 seconds. Registry readiness
is withdrawn before transport teardown on expiry, connection loss, denial,
replacement, or shutdown. Each admitted transport is additionally bounded to
64 active flows, eight pending opens, a 256 KiB stream window, and the frozen
flow/open/activity/shutdown deadlines.

## Development

```sh
cd nativeegressrelay
go vet ./...
go test -race -count=1 ./...
```

The coordinated `nvt-native-egress-relay` image is a static binary in a
distroless non-root runtime with no shell, package manager, Git, Go toolchain,
or cloud SDK. The opt-in chart deployment and operator exact-snapshot
publication are implemented, including withdrawal-before-cleanup ordering.
The operator also supplies the exact selected driver a bounded public
attachment plan and waits for its matching infrastructure-confinement
observation before publication readiness. Provider-owned guest redirect
installation, infrastructure confinement, cloud/provider integration, and the
final provider E2E remain separate future gates; this integration alone does
not make production VM mediation complete.
