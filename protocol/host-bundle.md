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
  "compatibility": {
    "agentd_protocol": "nvt.agentd/v1",
    "native_session_protocol": "nvt.native-session/v1",
    "native_workspace_protocol": "nvt.native-workspace/v1",
    "native_egress_protocol": "nvt.native-egress/v1"
  },
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

`native_session_protocol` is an optional, additive v1 compatibility member.
Its absence identifies an immutable pre-native-session v1 bundle and remains
valid; such a bundle provides only the original agentd/supervisor lifecycle.
When present it must equal `nvt.native-session/v1`. Unknown values fail closed.
This preserves decoding of already published `nvt.host-bundle/v1` digests
without silently changing their requirements.

`native_workspace_protocol` is likewise optional and additive. Its absence is
valid for every bundle published before the trusted workspace forwarder was
packaged. When present it must equal `nvt.native-workspace/v1`; unknown values
fail closed. The separate marker does not change `nvt.native-session/v1` or
make workspace forwarding mandatory for a guest configuration.

`native_egress_protocol` is also optional and additive. Its absence preserves
every immutable bundle produced before the purpose-separated native-egress
client was packaged. When present it must equal `nvt.native-egress/v1`.
Presence describes compatible trusted session-establishment code; it does not
assert provider confinement, a production relay, traffic forwarding, or
mediated-VM readiness.

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

The bundle includes five independent native service boundaries:

- `nvt-guest-identity.service` runs the static root-owned
  `nvt-guest-identityd`. It consumes the separately delivered one-time
  envelope, keeps the current bearer and an unresolved successor only below
  root-owned `/var/lib/nvt-agent-identity`, authenticates to the configured
  broker, and rotates according to
  [`nvt.guest-runtime-identity/v1`](guest-runtime-identity.md).
- `nvt-agent-guest.service` runs the static non-root `nvt-guest-supervisor`.
  It owns the native session and `agentd` processes; `agentd` remains limited
  to session I/O, prompt queueing, and event logging. The supervisor requests
  agentd socket mode `0660` only for this native service: ownership remains
  `nvt-agent:nvt-agent`, allowing the capability-free root session service to
  connect through its explicit `nvt-agent` group. Other agentd deployments
  keep the existing `0600` default.
- `nvt-guest-session.service` runs the static root-owned
  `nvt-guest-sessiond`. It requests only a short-lived fixed-audience session
  credential over the identity daemon's root-only Unix socket, establishes
  the provider-neutral outbound [`nvt.native-session/v1`](native-session.md)
  transport, and relays bounded JSON to the unchanged agentd socket. When its
  optional root-owned workspace configuration is present, the same trusted
  process also establishes a separate
  [`nvt.native-workspace/v1`](native-workspace.md) TLS/yamux connection using
  the same current short-lived credential and forwards streams only to the
  configured literal loopback service. It never receives or persists the root
  runtime identity.
- `nvt-guest-egress.service` runs the separate static root-owned
  `nvt-guest-egressd` only when a trusted provider explicitly installs its
  non-secret configuration and enables the unit. It requests a short-lived
  purpose-separated `nvt_eg1_` credential through the same root-only identity
  socket, establishes [`nvt.native-egress/v1`](native-egress.md) over a
  separate explicitly trusted TLS connection, and retains current/pending
  credentials only in bounded process memory. After authentication it proves
  the pinned bounded yamux flow transport is live and exposes a mode `0600`
  root-only local flow socket. It does not receive the runtime identity,
  install provider redirect rules, or assert provider confinement/readiness.
- `nvt-guest-captured.service` runs a separate static credential-less process.
  It owns all agent-controlled HTTP/TLS/original-destination parsing and can
  send only canonical destination intent and raw bytes to the local flow
  socket; exact binding and bearer fields are absent from that IPC. Its
  transparent listener carries no capability hint. Its explicit CONNECT
  listener consumes the existing per-flow provider selector and never forwards
  CONNECT or proxy-auth framing upstream.

The agent service requires the identity service. The identity unit uses
systemd `Type=notify` and becomes active only after durable state has been
validated and the exact current identity has authenticated successfully. A
later identity failure removes identity readiness. `TimeoutStartSec=0` leaves
the initial activation pending while the daemon applies the enrollment
envelope's broker-owned expiry and its own bounded network operations; a
generic systemd startup timeout must not kill a recoverable enrollment and
strand the dependent agent start job. Transient broker failures remain bounded
inside the daemon and retry without claiming readiness. At local identity
expiry, or after a terminal revoked or unrecoverable result, the daemon
atomically erases bearer state, records replacement-required, and exits
non-zero so systemd stops/restarts the dependent lifecycle without exposing
bearer state to the agent user.

The current bundle includes the real `agentd` and `agentdctl` sources, the
trusted native control-session and optional workspace clients, the optional
native-egress session/flow client and separate credential-less Linux capture
process, plus a bounded
session fixture for the guest-side lifecycle gate. It does not package
code-server, an AI runtime, plugins, or the cluster-side egressd target
adapter.
The loopback workspace service remains an explicit provider-installed
prerequisite; the production gateway can route an already-authorized external
VM browser session to it through the exact native workspace binding.

Readiness is owned by the supervisor. It publishes `guest-ready` only after
agentd, the tmux session, and the native outbound session are stable,
continuously monitors all three boundaries, and removes readiness before
returning failure when any one disappears.
Systemd's `Restart=on-failure` can then start a fresh native lifecycle without
making agentd responsible for host supervision.

`session_readiness_path` is an additive optional member of the existing
version-1 guest configuration. An omitted member preserves the original v1
agentd/tmux readiness and monitoring behavior. New native-session guests set
the absolute path and thereby opt into the additional transport gate. A
present malformed path still fails closed.

`egress_readiness_socket_path` is a second additive optional version-1 member.
When present, the supervisor validates a non-symlink mode `0660` root-owned
socket below a mode `0750` root-owned runtime directory, authenticates the
server peer, and holds a live capture-plus-tunnel lease before starting tmux.
Capture death or transport withdrawal closes the lease; the supervisor removes
`guest-ready` before stopping the session. Omission preserves the pre-egress
behavior. A stale regular file or stale/unowned socket is never readiness.

Guest prerequisites for v1 are Linux, Python 3, tmux, a dedicated `nvt-agent`
user, writable runtime/state/workspace directories, and systemd when the unit is
used. The containerized CI harness invokes the exact same supervisor and files
without pretending to be a provider VM or systemd proof.

The installer does not write `/etc`, deliver an enrollment envelope, or enable
services. Guest provisioning copies the required fixed units from
`/opt/nvt/current/share/systemd/`, installs the non-secret broker CA at
`/etc/nvt-agent/runtime-identity-ca.pem`, writes the root-owned mode `0600`
identity path configuration at `/etc/nvt-agent/identity.json`, and delivers
the one-time mode `0600` envelope to
`/var/lib/nvt-agent-identity/enrollment.json`. It separately supplies the
resolved non-secret `/etc/nvt-agent/guest.json`, root-owned mode `0600`
`/etc/nvt-agent/session.json`, and explicit gateway CA trust, reloads systemd,
and enables the services. The identity state directory is root-owned mode
`0700`; neither the `nvt-agent` user nor its workspace can read it. These explicit steps are
provider-owned and are not archive hooks. No bearer is accepted through argv,
environment, systemd unit content, or ordinary guest configuration.

Mediated-VM providers may additionally copy both native-egress units, resolve
the non-secret `native-egress.json` and `native-capture.json` examples, install
the explicit relay CA, and enable both only after infrastructure confinement
prerequisites are met. The capture configuration contains two literal loopback
listeners and local socket paths only; it contains no binding, audience,
bearer, target endpoint, global capability, or provider credential. The
provider owns redirect installation and explicit-proxy client configuration,
and adds the root-owned `egress_readiness_socket_path` to `guest.json` when the
agent lifecycle must be gated. The bundle never enables these units itself.
The operator now gates its native-mediated condition on the exact published
relay target and exact desired attachment observation. The attachment gives a
provider the public relay trust, fixed capture ports, and bounded bootstrap
destinations needed to resolve these files; it never carries a credential.
Provider confinement and installed guest capture readiness remain
provider-owned prerequisites, and no production provider consumes the plan in
this phase.

The bundled `share/examples/session.json` remains the unchanged control-only
example. `share/examples/session-workspace.json` demonstrates the optional
non-secret additive block:

```json
"workspace": {
  "gateway_endpoint": "tls://workspace-gateway.example.invalid:444",
  "loopback_endpoint": "127.0.0.1:4090"
}
```

Only canonical TLS/DNS endpoints and literal loopback targets are accepted.
The target never comes from a gateway stream, browser request, AgentRun, or
driver response. The same configured CA bundle is used for exact server-name
validation of both outbound connections.

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
production provider. The broker implements the separate
[guest session identity contract](guest-session-identity.md), and this bundle
now requests a short-lived credential only through the root-only identity
authority and holds it only in trusted session-process memory. The production
gateway acceptor and test-only real QEMU/TCG guest prove authenticated control
establishment, relay, and restart. The separate
[`nvt.native-workspace/v1`](native-workspace.md) guest forwarder and production
gateway acceptor now establish the authenticated TLS/yamux transport and
expose the bounded active stream boundary consumed by authorized external-VM
browser routing. The provider-neutral native VM mediated-egress contract,
production broker identity endpoints, and trusted host-bundle
session/flow-transport client now exist. A production relay core serves the
corresponding bounded data plane and may use an explicit process-owned
exact-binding adapter into per-run egressd. Captured agent traffic integration,
including fixed-destination recovery and no-fallback flow opening, now exists
in the opt-in guest service. Dynamic operator target publication/readiness and
withdraw-before-cleanup ordering are now implemented. Provider-owned redirect
installation and external network confinement remain future gates before a
mediated external VM can be ready.
