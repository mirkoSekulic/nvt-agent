# QEMU test/reference execution driver

This directory is a complete test OCI execution-driver implementation for the
generic `nvt.execution-driver/v1` and sensitive guest-enrollment handoff
contracts. QEMU is isolated here; the operator, broker, portable protocol,
agentd, runtime plugins, and built-in Kubernetes backend contain no QEMU
branches. It is built locally by CI to prove the generic native-VM lifecycle;
NVT does not publish it in the coordinated product image set or support it as a
production execution provider.

The reference image includes a pinned amd64 Alpine kernel, initramfs, and
minimal native disk template. The execution class must repeat the exact
aggregate `sha256` checksum baked into that image and identify a native NVT
host-bundle OCI index by repository plus digest:

```json
{
  "contract_version": "nvt.qemu-driver/v1",
  "guest_image": {"digest": "sha256:<64 lowercase hex>"},
  "host_bundle": {
    "repository": "https://ghcr.io/mirkosekulic/nvt-host-bundle",
    "digest": "sha256:<64 lowercase hex>"
  },
  "enrollment_ca_pem": "<issuer CA certificate PEM>",
  "native_session_endpoint": "tls://test-gateway.example:7443",
  "native_session_ca_pem": "<test gateway CA certificate PEM>",
  "native_egress_probe": {
    "host": "echo.example",
    "port": 443,
    "capability": "test-provider"
  },
  "cpus": 1,
  "memory_mib": 512,
  "acceleration": "auto",
  "boot_timeout_seconds": 110
}
```

The test workflows build the complete image locally and pin its OCI manifest
digest before registration. The matching guest checksum can be read without
starting the driver protocol:

```sh
docker build -f executiondrivers/qemu/Dockerfile \
  -t nvt-qemu-execution-driver:test .
docker run --rm --entrypoint cat \
  nvt-qemu-execution-driver:test \
  /opt/nvt-qemu/guest/digest
```

The checksum is a second binding between the administrator-owned class and the
kernel, initramfs, and disk template inside that exact driver image; it is not
a mutable discovery tag.

`registry_ca_pem` is optional for registries trusted by the guest OS.
`native_egress_probe` is an optional QEMU-reference-only non-secret acceptance
fixture and is rejected unless the operator also supplies the portable native
egress attachment. It cannot select relay identity, trust, bootstrap access,
or provider confinement. The
configuration is administrator-owned, bounded, strict JSON and contains no
token, runtime identity, provider credential, or egress identity. The guest
image checksum, host-bundle digest, exact execution binding, and private
virtio-serial channel are all validated before sensitive delivery.
`boot_timeout_seconds` is bounded to 10–110 seconds so a guest boot remains
inside the generic host's authoritative two-minute operation deadline.

The registration requires provider-neutral persistent storage. The driver
stores one execution-ID-hashed directory containing its non-secret convergence
record and qcow2 disk. Short-lived AF_UNIX control sockets live under `/tmp`
instead of the persistent path and are derived from a short collision-resistant
execution hash. Storage-backed registrations use one `Recreate` Deployment and
must not share an existing claim with another registration, so two driver
processes never intentionally operate the same disks. Enrollment envelopes are
streamed once over the private virtio channel and are never written to ordinary
driver state or seed media. The guest passes the envelope to the generic
host-bundle identity package, which commits the exact binding and current
runtime identity in root-only atomic state. The installed daemon authenticates
and rotates it independently of the agent session. The QEMU-only bundle
fixture uses the compile-time `hostbundleidentitytest` schedule to prove a
rotation promptly; that tag and accelerated schedule are absent from every
coordinated production bundle. Deletion confirms
QEMU has been reaped before removing the disk, socket, state, and temporary
resources or reporting `deleted`.

`acceleration: auto` uses `/dev/kvm` only when the registration workload has
been explicitly granted a usable KVM device; otherwise it uses bounded TCG.
The chart does not grant host devices or additional privilege. The hermetic CI
gate therefore uses TCG. Current guest artifacts target linux/amd64; the
driver image itself is built for the host architecture.

For mediated test runs, QEMU user networking is the infrastructure owner:
`restrict=on` denies ordinary guest-to-host and guest-to-network traffic, and
the driver emits only deterministic `guestfwd` entries for the attachment's
relay plus bounded bootstrap/control destinations. Reconcile and observe read
the live QEMU process arguments from `/proc/<pid>/cmdline` and report the exact
current attachment generation/digest only while that host-owned configuration
matches byte-for-byte. Mediated QEMU runs use the image's `tini` subreaper so
per-flow `guestfwd` helpers and QEMU itself are reaped across retry, restart,
and deletion; legacy runs retain the direct QEMU process shape. Guest iptables
redirects ordinary TCP traffic into the credential-less capture process while
excluding the protected loopback and bounded bootstrap/control networks, but
that redirect is routing plumbing and is never accepted as the confinement
assertion. The QEMU fixture receives no
runtime identity, egress bearer, broker token, relay-control token, or provider
credential.

The real TCG gate proves provisioning, outside-guest confinement before
enrollment, native bundle installation, broker-backed identity rotation,
control and egress sessions, exact relay target publication, transparent and
explicit captured flows through the run's per-run egressd, credential
injection, revocation, restart recovery, and complete cleanup. This remains an
unpublished test/reference provider, not a production provider. Public VM
ingress and production cloud-provider network enforcement remain out of scope.
