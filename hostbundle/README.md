# Native NVT host bundle

This module builds and installs the provider-neutral native Linux guest slice
documented in [`protocol/host-bundle.md`](../protocol/host-bundle.md).

Build a deterministic Linux/amd64 bundle and architecture-aware OCI layout:

```sh
bash hostbundle/build.sh 0.8.33-test 0123456789abcdef0123456789abcdef01234567 dist/host-bundle
```

The layout tag resolves to an OCI index. `digest.txt` is its immutable digest.
The archive contains only the static bootstrap/supervisor/session fixture, the
real repository `agentd`/`agentdctl`, the systemd unit, and an example
non-secret guest configuration. It does not copy the runtime container rootfs.

The initial native target is Linux amd64. The manifest, builder, OCI index, and
bootstrap platform selection also support arm64; coordinated publication can
add that descriptor without changing the bundle or execution-driver contract.

The guest OS supplies Python 3, tmux, systemd (when the unit is used), the
`nvt-agent` user, and writable `/workspace`, `/run/nvt-agent`, and
`/var/lib/nvt-agent` paths. The included session executable is deliberately a
bounded lifecycle fixture, not a production AI runtime. Provider bootstrap,
short-lived enrollment, code-server, plugins, gateway routing, broker identity,
and mediated VM egress remain later phases.

After the bootstrap has installed and activated a release, guest provisioning
may install the repository-owned unit and its separately supplied non-secret
configuration using the stable `current` path:

```sh
install -o root -g root -m 0644 \
  /opt/nvt/current/share/systemd/nvt-agent-guest.service \
  /etc/systemd/system/nvt-agent-guest.service
install -d -o root -g root -m 0755 /etc/nvt-agent
# Write an administrator-resolved guest.json; the bundled file is an example.
systemctl daemon-reload
systemctl enable --now nvt-agent-guest.service
```

The bundle never writes `/etc` or enables a service implicitly. That remains a
provider-owned provisioning step so activation cannot execute archive hooks.

Run the trusted-core and guest-side E2E tests:

```sh
cd hostbundle
go vet ./...
go test -race -count=1 ./...
```
