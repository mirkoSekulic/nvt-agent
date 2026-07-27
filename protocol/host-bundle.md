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

The bootstrap binary itself is an input delivered by a future execution driver
or trusted guest image. It carries no enrollment material. The OCI bundle,
class configuration, completion metadata, and ordinary logs must not contain a
broker token, provider credential, or one-time enrollment secret.

## Guest service boundary

The bundle includes `nvt-agent-guest.service`, which runs the static
`nvt-guest-supervisor` from `/opt/nvt/current`. The supervisor owns the native
session and `agentd` processes; `agentd` remains limited to session I/O, prompt
queueing, and event logging. The current bundle includes the real `agentd` and
`agentdctl` sources plus a bounded session fixture for the guest-side lifecycle
gate. It does not yet package code-server, an AI runtime, plugins, enrollment,
broker integration, gateway publication, or mediated VM egress.

Guest prerequisites for v1 are Linux, Python 3, tmux, a dedicated `nvt-agent`
user, writable runtime/state/workspace directories, and systemd when the unit is
used. The containerized CI harness invokes the exact same supervisor and files
without pretending to be a provider VM or systemd proof.

The installer does not write `/etc` or enable services. Guest provisioning
copies the fixed unit from
`/opt/nvt/current/share/systemd/nvt-agent-guest.service`, supplies the resolved
non-secret `/etc/nvt-agent/guest.json`, then enables the unit. This explicit
step is provider-owned and is not an archive hook.

An administrator-owned VM execution class can already carry the opaque,
non-secret reference without a new core API field:

```yaml
configuration:
  hostBundle:
    repository: https://ghcr.io/example/nvt-host-bundle
    digest: sha256:<64-hex>
```

Producers cannot select or mutate execution-class configuration. Enrollment is
a separate future short-lived input and must not be embedded here.

The next provider phase must provision a real guest, deliver the bootstrap and
one-time enrollment independently, and implement gateway routing, broker
identity, revocation, and mediated egress before VM execution is production
ready.
