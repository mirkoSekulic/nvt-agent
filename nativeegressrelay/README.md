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

The command optionally constructs a production `EgressdTargetRegistry` from a
strict process-owned `egressd_targets` snapshot. Each entry maps one complete
five-field Binding to exactly one canonical per-run egressd CONNECT listener.
Each canonical listener may appear for only one Binding in the complete
snapshot; sharing it would cross the per-run grant and credential boundary.
Target lookup is exact-only; guest destination input can never choose an
endpoint, run, or driver. If the snapshot is omitted, the command retains its
safe `DenyAllTargetResolver` behavior and acknowledges no sessions.

The snapshot is trusted control-plane input loaded once at process start.
Changing it currently requires a coordinated relay restart. The registry's
atomic level-triggered `Reconcile` method is an in-process seam for later
authenticated operator publication; this phase adds no watcher or target-
registration HTTP API. Removed or replaced mappings stop new flow opens and
withdraw their exact sessions without moving established flows to another
target.

## Configuration

The command reads one strict process-owned JSON file. It does not read
credentials from flags or environment variables:

```json
{
  "version": 1,
  "listen_address": "0.0.0.0:7445",
  "tls_certificate_file": "/run/nvt-native-egress-relay/tls.crt",
  "tls_key_file": "/run/nvt-native-egress-relay/tls.key",
  "broker_url": "https://nvt-broker.nvt.svc.cluster.local:8443",
  "broker_server_name": "nvt-broker.nvt.svc.cluster.local",
  "broker_ca_file": "/run/nvt-native-egress-relay/broker-ca.crt",
  "authentication_timeout_seconds": 5,
  "revalidation_interval_seconds": 30,
  "egressd_targets": [
    {
      "binding": {
        "agent_run_uid": "00000000-0000-4000-8000-000000000001",
        "execution_id": "execution-id",
        "driver_registration": "external-vm-driver",
        "desired_generation": 1,
        "guest_instance_id": "provider-owned-instance-id"
      },
      "connect_url": "http://run-egressd.example:8470"
    }
  ]
}
```

The default path is `/etc/nvt-agent/native-egress-relay.json`; `--config` may
select another absolute file. The configuration and private key must be
owner-only, regular, non-symlink, single-link files owned by the process
effective UID. The serving certificate and broker CA may be group/world
readable but must be process-owned and not group/world writable. All paths are
absolute and canonical. The broker is one canonical HTTPS origin with exact
explicit DNS SNI and CA trust; system roots, redirects, environment proxies,
plaintext fallback, and credential helpers are not used.

Authentication timeout is positive and at most the frozen five-second
handshake deadline. Revalidation is positive and at most 30 seconds.

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

No OCI image or coordinated release artifact is published by this phase.
The opt-in host-bundle capture boundary can now feed this relay, but dynamic
operator publication, provider-owned guest redirect installation,
mediated-VM readiness, provider confinement, and cloud/provider integration
remain separate future gates; this adapter alone does not make production VM
mediation complete.
