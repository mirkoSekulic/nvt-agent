# Native NVT host bundle

This module builds and installs the provider-neutral native Linux guest slice
documented in [`protocol/host-bundle.md`](../protocol/host-bundle.md).

Build a deterministic Linux/amd64 bundle and architecture-aware OCI layout:

```sh
bash hostbundle/build.sh 0.8.33-test 0123456789abcdef0123456789abcdef01234567 dist/host-bundle
```

The layout tag resolves to an OCI index. `digest.txt` is its immutable digest.
The archive contains only the static bootstrap, root-owned runtime-identity
daemon, non-root supervisor/session fixture, the real repository
`agentd`/`agentdctl`, two systemd units, and example path-only configurations.
It does not copy the runtime container rootfs.

The initial native target is Linux amd64. The manifest, builder, OCI index, and
bootstrap platform selection also support arm64; coordinated publication can
add that descriptor without changing the bundle or execution-driver contract.

The guest OS supplies Python 3, tmux, systemd (when the units are used), the
`nvt-agent` user, and writable `/workspace`, `/run/nvt-agent`, and
`/var/lib/nvt-agent` paths. The included session executable is deliberately a
bounded lifecycle fixture, not a production AI runtime. Provider provisioning,
code-server, plugins, gateway routing, downstream runtime-identity use, and
mediated VM egress remain later phases.

The separate provider-neutral enrollment and runtime-identity boundaries are
documented in [`protocol/guest-enrollment.md`](../protocol/guest-enrollment.md)
and [`protocol/guest-runtime-identity.md`](../protocol/guest-runtime-identity.md).
The broker-side future session credential boundary is documented separately in
[`protocol/guest-session-identity.md`](../protocol/guest-session-identity.md);
the current bundle does not request, store, or expose that credential.
The sensitive envelope is never embedded in this bundle, its OCI metadata, or
guest config. The daemon accepts it only from the root-owned mode `0600`
enrollment path, stores current/successor bearer state below root-owned mode
`0700` `/var/lib/nvt-agent-identity`, and authenticates with explicit CA trust.
No bearer is accepted through argv, environment, or agent-visible
configuration.

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
install -d -o root -g root -m 0755 /etc/nvt-agent
# Write guest.json plus root-owned identity.json/CA/enrollment inputs. The
# bundled JSON files are examples and contain no bearer.
systemctl daemon-reload
systemctl enable --now nvt-guest-identity.service nvt-agent-guest.service
```

The bundle never writes `/etc` or enables a service implicitly. That remains a
provider-owned provisioning step so activation cannot execute archive hooks.

Run the trusted-core and guest-side E2E tests:

```sh
cd hostbundle
go vet ./...
go test -race -count=1 ./...
```
