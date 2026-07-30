# Native egress relay core

`nvt-native-egress-relay` is the provider-neutral cluster-side authenticated
session boundary for [`nvt.native-egress/v1`](../protocol/native-egress.md).
It accepts the guest-initiated TLS connection, authenticates the
`nvt_eg1_` bearer through the broker, resolves only the complete five-field
guest binding through an in-process `TargetResolver`, and admits the shared
active/standby `SessionRegistry`.

Authentication is staged: the relay reads and authenticates the bounded hello,
resolves the exact target, and reserves the active/standby slot before sending
`hello_ack`. Capacity rejection and older replay therefore close without an
acknowledgement and cannot cause the guest to publish readiness. An ACK write
failure removes its reservation.

This phase intentionally has no flow transport or target adapter. The command
uses `DenyAllTargetResolver`, so it starts safely but cannot acknowledge a
session or report an exact binding active until a later operator-owned adapter
is wired in process. Any byte received after an authenticated hello is a
protocol failure and closes the session. There is no target-registration HTTP
API, binding enumeration, partial lookup, provider endpoint, CONNECT proxy,
yamux transport, egressd adapter, or Helm deployment here.

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
  "revalidation_interval_seconds": 30
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

The listener requires TLS 1.2 or newer. At most 32 pre-authentication TLS/
broker handshakes run concurrently, while the frozen registry bounds 128 exact
bindings with one active and one authenticated equal/newer standby each. Each
broker-derived local trust interval is capped at 30 seconds. Registry readiness
is withdrawn before transport teardown on expiry, connection loss, denial,
replacement, or shutdown.

## Development

```sh
cd nativeegressrelay
go vet ./...
go test -race -count=1 ./...
```

No OCI image or coordinated release artifact is published by this phase.
