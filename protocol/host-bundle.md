# Native host-bundle contract

`nvt.host-bundle/v1` is the provider-neutral distribution contract for the NVT
runtime installed directly on a Linux guest. A host bundle is a deterministic
tar+gzip layer carried by an OCI artifact; it is not a runnable container image.

The immutable input is an exact HTTPS repository plus a complete
`sha256:<64-hex>` OCI manifest-list digest. Tags are discovery metadata only and
must never be accepted as execution identity. The top-level OCI object is an
architecture-aware index. Each platform descriptor selects one artifact
manifest with:

- artifact type `application/vnd.nvt.host-bundle.v1`;
- one layer of type `application/vnd.nvt.host-bundle.layer.v1.tar+gzip`; and
- a platform matching the requested Linux OS and architecture.

The v1 archive contains `manifest.json` and only the files named by that
manifest. Its schema is:

```json
{
  "contract_version": "nvt.host-bundle/v1",
  "os": "linux",
  "architecture": "amd64",
  "bundle_version": "0.8.33-abcdef0",
  "build_id": "0123456789abcdef0123456789abcdef01234567",
  "native_entrypoint": "bin/nvt-guest-supervisor",
  "service_identity": "nvt-agent-guest.service",
  "compatibility": {"agentd_protocol": "nvt.agentd/v1"},
  "files": [
    {
      "path": "bin/agentd",
      "sha256": "sha256:<64-hex>",
      "size": 1234,
      "mode": 493
    }
  ]
}
```

`bundle_version` is the coordinated release identity. `build_id` is the full
source revision. Files are sorted by path and have deterministic content,
ownership, timestamp, and mode. Every file digest, size, and mode is validated
before activation. Unknown or duplicate JSON fields are invalid.

## Native installation and activation

Root runs `nvt-host-bootstrap`; the installer pulls anonymously over HTTPS
without Docker. It validates
the index, selected manifest, media types, platform, descriptor sizes and every
content digest before safe extraction. The archive may contain ordinary
directories and regular files only. Absolute/traversing/duplicate paths,
links, devices, FIFOs, sockets, non-root archive ownership, special permission
bits, unexpected files, and configured size/count overflows fail closed.
Archive content is data only; no install hook is executed.

Complete releases are published under:

```text
/opt/nvt/releases/<bundle-version>/<index-digest>/
```

The installer writes into a private temporary sibling, validates the complete
tree, atomically renames it into place, and atomically switches
`/opt/nvt/current`. A repeat install of the same complete digest is idempotent.
Incomplete final paths are not repaired or destroyed implicitly. An activation
failure leaves the previous `current` target untouched.
Published release directories are root-owned and `0755`: the non-root service
can read/execute them but cannot replace trusted code or activation links.

Before publication, the installer synchronizes every extracted regular file,
the manifest, completion metadata, and the completed temporary directory tree.
After the release rename it synchronizes the version and `releases`
directories; after replacing `current` it synchronizes `/opt/nvt`. A successful
installation also synchronizes the parent of the install root so a newly
created `/opt/nvt` entry is durable. A successful return therefore makes the
selected complete release and activation durable on
Linux filesystems that honor `fsync`. Any synchronization failure before the
`current` rename leaves the old activation unchanged. If the final install-root
sync fails after the atomic rename, the installer reports failure; after a
crash either old or new `current` may be recovered, but both targets refer only
to a previously synchronized complete release. Tests inject each boundary;
they do not simulate power loss or claim guarantees from a filesystem that
does not honor `fsync`.

The bootstrap binary itself is an input delivered by a future execution driver
or trusted guest image. It carries no enrollment material. The OCI bundle,
class configuration, completion metadata, and ordinary logs must not contain a
broker token, provider credential, or one-time enrollment secret.

## Guest service boundary

The bundle includes two independent native service boundaries:

- `nvt-guest-identity.service` runs the static root-owned
  `nvt-guest-identityd`. It consumes the separately delivered one-time
  envelope, keeps the current bearer and an unresolved successor only below
  root-owned `/var/lib/nvt-agent-identity`, authenticates to the configured
  broker, and rotates according to
  [`nvt.guest-runtime-identity/v1`](guest-runtime-identity.md).
- `nvt-agent-guest.service` runs the static non-root `nvt-guest-supervisor`.
  It owns the native session and `agentd` processes; `agentd` remains limited
  to session I/O, prompt queueing, and event logging.

The agent service requires the identity service. The identity unit uses
systemd `Type=notify` and becomes active only after durable state has been
validated and the exact current identity has authenticated successfully. A
later identity failure removes identity readiness. Transient broker failures
remain bounded inside the daemon and retry without claiming readiness; a
terminal revoked, expired, or unrecoverable identity exits non-zero so systemd
can stop/restart the dependent lifecycle without exposing bearer state to the
agent user.

The current bundle includes the real `agentd` and `agentdctl` sources plus a
bounded session fixture for the guest-side lifecycle gate. It does not yet
package code-server, an AI runtime, plugins, gateway publication, or mediated
VM egress.

Readiness is owned by the supervisor. It publishes `guest-ready` only after
agentd and the tmux session are stable, continuously monitors both processes,
and removes readiness before returning failure when either one disappears.
Systemd's `Restart=on-failure` can then start a fresh native lifecycle without
making agentd responsible for host supervision.

Guest prerequisites for v1 are Linux, Python 3, tmux, a dedicated `nvt-agent`
user, writable runtime/state/workspace directories, and systemd when the unit is
used. The containerized CI harness invokes the exact same supervisor and files
without pretending to be a provider VM or systemd proof.

The installer does not write `/etc`, deliver an enrollment envelope, or enable
services. Guest provisioning copies both fixed units from
`/opt/nvt/current/share/systemd/`, installs the non-secret broker CA at
`/etc/nvt-agent/runtime-identity-ca.pem`, writes the root-owned mode `0600`
identity path configuration at `/etc/nvt-agent/identity.json`, and delivers
the one-time mode `0600` envelope to
`/var/lib/nvt-agent-identity/enrollment.json`. It separately supplies the
resolved non-secret `/etc/nvt-agent/guest.json`, reloads systemd, and enables
the services. The identity state directory is root-owned mode `0700`; neither
the `nvt-agent` user nor its workspace can read it. These explicit steps are
provider-owned and are not archive hooks. No bearer is accepted through argv,
environment, systemd unit content, or ordinary guest configuration.

An administrator-owned VM execution class can already carry the opaque,
non-secret reference without a new core API field:

```yaml
configuration:
  hostBundle:
    repository: https://ghcr.io/example/nvt-host-bundle
    digest: sha256:<64-hex>
```

Producers cannot select or mutate execution-class configuration. Enrollment is
a separate short-lived input and must not be embedded here.

The provider-neutral [guest enrollment contract](guest-enrollment.md) defines
the separate one-time sensitive envelope, exact execution binding, atomic
exchange, and revocation semantics without placing any credential in this
bundle. The broker-backed issuer and dedicated operator-to-driver handoff are
implemented, and the bundle now contains the provider-neutral native identity
daemon. A test-only QEMU reference driver proves one-time exchange, bundle
installation, a real rotation, daemon/guest restart recovery, native readiness,
and cleanup in a real TCG guest. That driver is not published or supported as a
production provider. Gateway routing, downstream production authorization with
the runtime identity, broker session identity, and mediated VM networking
remain future production gates before VM execution is ready.
