# QEMU reference execution driver

This directory is a complete OCI execution-driver implementation for the
generic `nvt.execution-driver/v1` and sensitive guest-enrollment handoff
contracts. QEMU is isolated here; the operator, broker, portable protocol,
agentd, runtime plugins, and built-in Kubernetes backend contain no QEMU
branches.

The production image includes a pinned amd64 Alpine kernel, initramfs, and
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
  "cpus": 1,
  "memory_mib": 512,
  "acceleration": "auto",
  "boot_timeout_seconds": 110
}
```

For a digest-pinned driver image, an administrator can read the matching guest
checksum without starting the driver protocol:

```sh
docker run --rm --entrypoint cat \
  ghcr.io/mirkosekulic/nvt-qemu-execution-driver@sha256:<driver-manifest-digest> \
  /opt/nvt-qemu/guest/digest
```

The checksum is a second binding between the administrator-owned class and the
kernel, initramfs, and disk template inside that exact driver image; it is not
a mutable discovery tag.

`registry_ca_pem` is optional for registries trusted by the guest OS. The
configuration is administrator-owned, bounded, strict JSON and contains no
token, runtime identity, provider credential, or egress identity. The guest
image checksum, host-bundle digest, exact execution binding, and private
virtio-serial channel are all validated before sensitive delivery.
`boot_timeout_seconds` is bounded to 10–110 seconds so a guest boot remains
inside the generic host's authoritative two-minute operation deadline.

The registration requires provider-neutral persistent storage. The driver
stores one execution-ID-hashed directory containing its non-secret convergence
record and qcow2 disk. Enrollment envelopes are streamed once over the private
virtio channel and are never written to ordinary driver state or seed media.
The guest stores the exchanged runtime identity only in its root-only sensitive
state. Deletion stops QEMU and removes the disk, socket, state, and temporary
resources before reporting `deleted`.

`acceleration: auto` uses `/dev/kvm` only when the registration workload has
been explicitly granted a usable KVM device; otherwise it uses bounded TCG.
The chart does not grant host devices or additional privilege. The hermetic CI
gate therefore uses TCG. Current guest artifacts target linux/amd64; the
driver image itself is built for the host architecture.

This reference proves provisioning, one-time enrollment, native bundle
installation, supervisor/agentd/session readiness, restart recovery, and
cleanup. Gateway publication, public VM ingress, production runtime identity
use, and mediated VM egress are intentionally not implemented here.
