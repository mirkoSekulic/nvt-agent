# Local manifest v1

Status: active for the local Docker backend.

`nvt.dev/local/v1` is the single human-authored, non-secret local-platform
manifest. The implementation lives in `localplatform/manifest`, with private
input and trusted-volume preparation in `localplatform/state`. It accepts one
bounded YAML document, rejects aliases, duplicate or unknown fields, unsupported
scalar tags, excessive depth/node/byte counts, invalid names and enums, unsafe
paths, unresolved references, mutable OCI image tags, and undeclared
secret-bearing fields.

The document defines logical secrets by file reference, provider accounts,
reusable profiles, named provider-neutral repositories, persistent
workstations, disposable or retained workflows, the built-in
`github-comments` producer, and external digest-pinned OCI producers. The
explicitly named `publicConfig` boundary described below is
administrator-asserted public data.

Profile, workflow, and producer names use the controller's 63-byte lower-case
run-ID grammar. A manifest declares at most 64 producers because each producer
owns one distinct local-controller schedule.

Every Codex or Claude profile explicitly selects one compatible runtime account
from its account list. Shell profiles select none. The controller projection
keeps that selection separate as the runtime/egress provider and emits its
required injection grant. Git credential mappings are derived only from
repository accounts. When multiple repository accounts are selected, the
profile must declare `defaultRepositoryAccount`; it is never inferred from the
runtime account. The projection duplicates preset identities and exact grants,
allowing local preset packaging to render the existing resolved-run profile
without consulting the broker-owned section.

Each repository supplies an HTTPS URL, exact checkout target, optional checkout
path and upstream, broker repository identity, and optional credential account.
`github: owner/repository` is shorthand expanded into those exact fields. A
workstation or workflow references repository names, so GitHub and Azure DevOps
checkouts use the same selection contract and account choice is unambiguous.

## Canonical compilation and ownership

Compilation produces deterministic JSON. Map entries and set-like lists are
sorted, and named sequences are sorted by name. Therefore YAML spelling, map
order, and set order do not affect the compiled bytes.

The compiled model is private local-platform intent, not a new runtime or
network protocol. Its sections establish these exclusive rendering boundaries:

| Section | Output owner | Existing contract eventually rendered |
| --- | --- | --- |
| `broker` | broker generator | account and exact per-profile repository-grant projections |
| `localController` | local-controller generator | execution profiles, repositories, workstations, and workflows |
| `gateway` | gateway generator | routes and typed Codex/Claude credential-portal slots |
| `producers[]` | the named producer generator | existing bounded schedule-admission client configuration |
| `privateInputs[]` | named trusted service | later file resolution/mount intent; never file contents |
| `generatedPrivateInputs[]` | local-platform state generator | generated admission credentials and their exact consumers |

Owner projections intentionally duplicate logical names where two renderers
need them. Each projection contains all non-secret fields needed by its renderer
and no renderer reads another owner's section. A built-in GitHub producer, for
example, receives resolved numeric App and installation IDs, repository
coordinates, and its own private-key input reference; the broker independently
owns its copy of that same logical key.

Broker rendering validates the final provider namespace before publishing any
managed state. This includes provider names derived for individual GitHub App
installations: a derived name may not collide with another derived provider or
with any user-authored account name.

The controller projection also contains one producer admission binding per
producer: stable producer identity, exactly one workflow, and a logical
generated credential name. Each binding contains a non-empty bounded principal
issuer allowlist: `github-comments` expands to `https://github.com`, while an
external OCI producer declares its issuers explicitly. The corresponding
generated-private-input entry is owned by local-platform state and lists only
the controller and that producer as consumers.

Generated configuration belongs in administrator-owned Docker volumes. It is
never written into `.broker`, the workspace, or another user-authored host
directory. Preset expansion belongs to local-platform packaging; core,
`agentd`, broker, gateway, controller, producer, Kubernetes, and Helm protocols
are unchanged by this contract.

## Private input resolution

Resolution starts only after the whole manifest has decoded, validated, and
compiled. Every path is relative to the directory containing
`nvt.local.yaml`; absolute paths, backslashes, empty components, and `..` are
rejected independently of the compiler's syntax checks.

Instruction files may be organized anywhere below that root. A confined
symlink is accepted, but `os.Root` prevents a link or concurrent rename from
escaping the manifest root. The final object must be a stable regular UTF-8
file no larger than 64 KiB, matching the unchanged resolved-run instruction
bound. The resolver reads and compares two snapshots so
an in-place write cannot produce a mixed generated instruction.

Secret files must be below `.nvt-local/secrets/`. Every path component and the
final file must be non-symlinks. The opened file must remain the same regular
file through two equal reads, be owned by the invoking effective user, expose
no group or other permission bits, contain at least one byte, and be no larger
than 64 KiB. A rename or content change during resolution fails closed. Errors
identify the unsafe input class without including its contents.

Resolved secret bytes remain in an opaque in-memory input set until they are
cleared. They are absent from the compiled document, redacted state plan,
generated JSON, environment values, helper arguments, Docker labels, and
command output. They reach persistent storage only as a bounded tar stream on
the trusted state helper's standard input.

Before any managed volume is created, the generated local-controller document
is validated against the unchanged resolved-run resolver plus the native limits
of 128 workstations, 128 profiles, 128 workflows, and 64 schedules. Every
rendered workstation and producer selection must resolve through that policy.
The generated controller service sets its active-run capacity to the same 128
workstation ceiling.

## Managed trusted-service state

The redacted state plan creates a distinct labeled Docker volume for generated
configuration, broker database/audit data, broker private and canonical
credential state, the shared broker agent registry, local-controller
database/audit data, and—when an OAuth account enables the portal—the portal
seed handoff. Portal seed storage is
writable only by the credential portal and read-only to the broker seed
supervisor; broker canonical credentials remain in the broker-private volume.
Before startup, the seed volume root is fixed to the packaged portal identity
`1000:1000` with mode `0700`, so the non-root portal can create its private
staging directory without broadening access.

Static inputs are snapshotted into exact per-consumer volumes. Generated inputs
use a persistent private source plus an exact journal-validated copy for each
consumer. Each service receives only `current/value` as a read-only subpath,
owned by its declared runtime UID with mode `0400`; generated-copy journals are
not mounted into the service. Shared
credentials, such as the controller route token or a producer admission token,
are copied into separate service volumes so granting one consumer never exposes
another consumer's directory. No agent service is a valid consumer.

Packaged producers have the packaged runtime identity `65532:65532`. An
external digest-pinned producer must declare `runtimeIdentity.uid` and
`runtimeIdentity.gid` as positive non-root IDs. That identity is carried into
the compiled producer contract and owns both its static secret snapshots and
generated admission-token copy; state planning fails if a producer consumer has
no exact compiled identity.

All volumes carry exactly these labels:

- `nvt.dev/local-platform-owner`: the bounded local project identity;
- `nvt.dev/local-platform-custodian`: the sole service or state generator that
  owns the volume;
- `nvt.dev/local-platform-role`: the fixed storage role;
- `nvt.dev/local-platform-volume`: the exact expected volume name; and
- `nvt.dev/local-platform-version`: `1`.

Existing same-name volumes are adopted only when the complete label map is
byte-for-byte equal. All existing volumes are checked before any state is
written. An empty, unmarked generated source left by an interrupted first
initialization can retry safely. A durable marker plus the exact source file is
required thereafter, so loss or corruption of an initialized value fails
closed rather than silently rotating it. Ordinary restarts preserve generated
material, a missing consumer copy is reconstructed from its source, and source
volume replacement rotates all consumer copies together before any later
service startup. The helper image itself must be pinned by SHA-256, runs
without networking or a writable root filesystem, and receives no private
value through Docker inspection surfaces.

The generated-config volume also stores a bounded, sorted historical inventory
of complete managed-volume label maps. Each successful reconciliation merges
the current plan into that inventory instead of dropping retired entries, so
`local-reset` can verify and remove exact-owned volumes left by manifest
shrinkage. Missing, incomplete, conflicting, or extra labels still fail closed.
If atomic configuration publication is interrupted after rotating `current`,
the next reconciliation validates and recovers the inventory from
`current.old` before publishing or cleaning that transaction snapshot.
Reconciliation and reset use the same read-only fallback helper and the same
finite inventory-sized Docker output bound; unrelated Docker commands retain
the smaller generic output limit. Reset uses that aligned bound for both the
historical inventory payload and exact-owned volume-name enumeration.
Reset snapshots and validates that inventory before deletion, removes every
other exact-owned volume first, and deletes generated-config as the final
volume so an interrupted retry retains its ownership anchor.

Credential-portal account projection is bounded to the portal contract's 128
slots before volume creation. Slot and local destination names use a
domain-separated full SHA-256 mapping of the logical account name; any duplicate
mapping is rejected before state is written.

Trusted-state preparation does not itself start a producer, workstation, or
workflow. The lifecycle renderer consumes its redacted plan and passes the
complete generated Compose document to Docker Compose on standard input.

## Local producer rendering

`localplatform/producer` renders one service and one read-only generated
configuration file for each compiled producer. The generated Compose fragment
is derived only from compiled intent and the exact managed-state plan. It
rejects a missing mount, an additional mount, a writable private input, an
unexpected subpath, a root runtime identity, and a mutable external image
before returning any YAML.

The packaged `github-comments` preset expands to the existing producer
contract with local profiled schedule admission. Its configured schedule name
is the producer name, and `pr-create`, `review`, and `run` all map to the one
manifest-selected workflow. The generated App configuration names only its
one repository and its exact private-key mount. Its SQLite state is the only
writable producer mount, preserving polling cursors, issue/comment
idempotency, reactions, and restart behavior without a user-authored producer
configuration or Compose service.

An external OCI producer receives exactly three environment variables:

- `NVT_SCHEDULE_ADMISSION_URL`, naming only its schedule endpoint;
- `NVT_SCHEDULE_ADMISSION_TOKEN_FILE`, naming its read-only generated token;
  and
- `NVT_PRODUCER_CONFIG_FILE`, naming its read-only
  `nvt.dev/local-producer/v1` configuration.

That configuration contains the producer name, its one workflow, the declared
`publicConfig`, and a logical-name to mounted-secret-file map. It contains no
profile, backend, image, repository, provider, broker grant, credential, agent,
or workstation selection. An external producer receives no state volume; only
the built-in preset has declared state semantics in v1.

Every producer runs as its compiled non-root identity with a read-only root
filesystem, all capabilities dropped, `no-new-privileges`, a bounded
non-executable tmpfs, PID/CPU/memory limits, and a bounded stop grace period.
Before rendering an external service, the digest-selected image must be
resolved in the local daemon and its image configuration must declare no OCI
volumes; the service is pinned to that inspected image ID. This prevents image
metadata from adding writable anonymous volumes behind the reviewed mount
plan.
The fragment includes no host bind, Docker socket, broker/agent credential,
service dependency, or another producer's volume. One producer therefore
cannot read another producer's inputs, and its crash/restart lifecycle does not
gate unrelated producers or workstations.

The fixture OCI image in `localplatform/producer/testfixture` exercises this
contract. It proves one exact-workflow submission succeeds while attempted
profile, workflow, backend, image, credential, and repository selections are
denied. Local-controller admission tests independently prove those unknown or
unauthorized selections create no durable run and never reach a backend.

## Example

See `localplatform/manifest/testdata/valid.yaml`. External producer
`publicConfig` is an explicit trust boundary: its bounded JSON-shaped content
is intentionally copied to generated configuration and must be public. The
compiler cannot infer whether an arbitrary string is sensitive. Secret access
is therefore declared only through the producer `secrets` map; ordinary
`config` and secret-shaped public keys are rejected. Built-in producers reject
both external-only fields and expose only their typed preset contract.
