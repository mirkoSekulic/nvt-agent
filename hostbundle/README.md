# Native NVT host bundle

This module builds and installs the provider-neutral native Linux guest slice
documented in [`protocol/host-bundle.md`](../protocol/host-bundle.md).

Build a deterministic Linux/amd64 bundle and architecture-aware OCI layout:

```sh
bash hostbundle/build.sh 0.8.33-test 0123456789abcdef0123456789abcdef01234567 dist/host-bundle
```

The layout tag resolves to an OCI index. `digest.txt` is its immutable digest.
The archive contains only the static bootstrap, root-owned runtime-identity
daemon, root-owned native control/optional workspace session client, the
separate optional native-egress flow client, credential-less capture daemon,
non-root supervisor/session fixture, the real repository `agentd`/`agentdctl`,
five systemd units, and
non-secret example path/endpoint configurations.
It does not copy the runtime container rootfs.

The initial native target is Linux amd64. The manifest, builder, OCI index, and
bootstrap platform selection also support arm64; coordinated publication can
add that descriptor without changing the bundle or execution-driver contract.

The guest OS supplies Python 3, tmux, systemd (when the units are used), the
`nvt-agent` user, and writable `/workspace`, `/run/nvt-agent`, and
`/var/lib/nvt-agent` paths. The included session executable is deliberately a
bounded lifecycle fixture, not a production AI runtime. Provider provisioning,
the optional fixed loopback workspace service, plugins, dynamic native-egress
target publication, provider redirect installation and confinement, and
mediated-VM readiness remain later phases.

The separate provider-neutral enrollment and runtime-identity boundaries are
documented in [`protocol/guest-enrollment.md`](../protocol/guest-enrollment.md)
and [`protocol/guest-runtime-identity.md`](../protocol/guest-runtime-identity.md).
The broker-side session credential boundary is documented in
[`protocol/guest-session-identity.md`](../protocol/guest-session-identity.md),
and the outbound transport in
[`protocol/native-session.md`](../protocol/native-session.md). The session
client requests a short-lived credential over a root-only Unix socket and
holds it only in bounded trusted memory; it never reads the runtime bearer.
The sensitive envelope is never embedded in this bundle, its OCI metadata, or
guest config. The daemon accepts it only from the root-owned mode `0600`
enrollment path, stores current/successor bearer state below root-owned mode
`0700` `/var/lib/nvt-agent-identity`, and authenticates with explicit CA trust.
No bearer is accepted through argv, environment, or agent-visible
configuration.

The native supervisor explicitly starts agentd with a group-scoped `0660`
socket owned by `nvt-agent:nvt-agent`; this is the only access granted to the
capability-free root session service. Agentd's default remains `0600` for the
existing container and Compose paths. The version-1 `session_readiness_path`
member is additive: older guest configurations that omit it retain their
original agentd/tmux readiness behavior, while newly provisioned native-session
guests enable the outbound-session readiness gate.
The optional version-1 `egress_readiness_socket_path` similarly gates tmux
startup and ongoing guest readiness on a live root-owned
capture-plus-transport lease. A reusable file cannot assert readiness: process
loss or transport withdrawal closes the lease before the supervisor removes
`guest-ready` and stops tmux. Omission preserves existing behavior.

`share/examples/session.json` remains the control-only example. Providers may
instead resolve the non-secret `share/examples/session-workspace.json` example
into the root-owned `/etc/nvt-agent/session.json`. Its optional `workspace`
block contains only a canonical TLS gateway endpoint and one literal loopback
destination. The same short-lived credential and explicit CA trust are used
for separate control and workspace TLS connections; neither the gateway nor a
stream can choose the local target. Readiness requires both legs, and renewal
switches only after both replacements authenticate.

`share/examples/native-egress.json` is a separate opt-in root-owned
configuration for `nvt-guest-egressd`. It contains only private runtime/socket
paths, one canonical TLS relay endpoint, and an explicit CA path. The process
requests a fixed-purpose egress credential from
`nvt-guest-identityd`; no
runtime identity, binding, audience, target endpoint, destination, or provider
credential is caller-configurable. The credential is never persisted and
reconnects reuse it; renewal retains at most a current and pending credential
in trusted memory.
After authentication the client proves the bounded yamux data plane is live
and exposes only a root-owned destination/byte-stream Unix socket. It retains
the short-lived bearer and exact binding, while the separate
`nvt-guest-captured` process owns agent-controlled HTTP/TLS parsing and cannot
represent either authority value on its IPC. Transparent flows carry no
capability hint. Proxy-aware clients use the bounded explicit CONNECT listener
and select the existing non-secret provider capability per flow via
`X-NVT-Capability` or the proxy username; CONNECT and proxy-auth framing is
consumed locally and never reaches the upstream byte stream.

After the bootstrap has installed and activated a release, guest provisioning
may install the repository-owned unit and its separately supplied non-secret
configuration using the stable `current` path:

```sh
install -o root -g root -m 0644 \
  /opt/nvt/current/share/systemd/nvt-agent-guest.service \
  /etc/systemd/system/nvt-agent-guest.service
install -o root -g root -m 0644 \
  /opt/nvt/current/share/systemd/nvt-guest-identity.service \
  /etc/systemd/system/nvt-guest-identity.service
install -o root -g root -m 0644 \
  /opt/nvt/current/share/systemd/nvt-guest-session.service \
  /etc/systemd/system/nvt-guest-session.service
install -d -o root -g root -m 0755 /etc/nvt-agent
# Write guest.json plus root-owned identity.json/session.json, explicit CA
# trust, and enrollment inputs. The
# bundled JSON files are examples and contain no bearer.
systemctl daemon-reload
systemctl enable --now nvt-guest-identity.service nvt-agent-guest.service nvt-guest-session.service
```

A provider implementing the later mediated-VM enforcement gates may also copy
`nvt-guest-egress.service` and `nvt-guest-captured.service`, write the two
root-owned example configurations plus explicit relay CA, install its redirect
into the configured transparent listener, configure proxy-aware clients for
the explicit listener, add `egress_readiness_socket_path` to `guest.json`, and
enable both units. The bundle does not enable or require them. Guest-local
capture forwards traffic but does not prevent hostile guest root from
bypassing it and does not claim production mediated-egress readiness.

The bundle never writes `/etc` or enables a service implicitly. That remains a
provider-owned provisioning step so activation cannot execute archive hooks.

Run the trusted-core and guest-side E2E tests:

```sh
cd hostbundle
go vet ./...
go test -race -count=1 ./...
```
