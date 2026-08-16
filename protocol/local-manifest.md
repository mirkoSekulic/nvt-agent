# Local manifest v1

Status: design contract; behavior-inactive until the local-platform integration
series is complete.

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
file no larger than 256 KiB. The resolver reads and compares two snapshots so
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

## Managed trusted-service state

The redacted state plan creates a distinct labeled Docker volume for generated
configuration, broker database/audit data, broker private and canonical
credential state, local-controller database/audit data, and—when an OAuth
account enables the portal—the portal seed handoff. Portal seed storage is
writable only by the credential portal and read-only to the broker seed
supervisor; broker canonical credentials remain in the broker-private volume.

Static inputs are snapshotted into exact per-consumer volumes. Generated inputs
use a persistent private source plus an exact copy for each consumer. Every
consumer volume contains only `current/value`, owned by the packaged service
UID with mode `0400`; the service receives only that subpath read-only. Shared
credentials, such as the controller route token or a producer admission token,
are copied into separate service volumes so granting one consumer never exposes
another consumer's directory. No agent service is a valid consumer.

All volumes carry exactly these labels:

- `nvt.dev/local-platform-owner`: the bounded local project identity;
- `nvt.dev/local-platform-custodian`: the sole service or state generator that
  owns the volume;
- `nvt.dev/local-platform-role`: the fixed storage role;
- `nvt.dev/local-platform-volume`: the exact expected volume name; and
- `nvt.dev/local-platform-version`: `1`.

Existing same-name volumes are adopted only when the complete label map is
byte-for-byte equal. All existing volumes are checked before any state is
written. Missing generated source volumes receive fresh 256-bit material;
ordinary restarts preserve them, a missing consumer copy is reconstructed from
its source, and source replacement rotates all consumer copies together before
any later service startup. The helper image itself must be pinned by SHA-256,
runs without networking or a writable root filesystem, and receives no private
value through Docker inspection surfaces.

This slice prepares state and mount intent only. It does not render or start a
producer, workstation, workflow, or replacement Compose project; those remain
behavior-inactive until the later integration slices consume the plan.

## Example

See `localplatform/manifest/testdata/valid.yaml`. External producer
`publicConfig` is an explicit trust boundary: its bounded JSON-shaped content
is intentionally copied to generated configuration and must be public. The
compiler cannot infer whether an arbitrary string is sensitive. Secret access
is therefore declared only through the producer `secrets` map; ordinary
`config` and secret-shaped public keys are rejected. Built-in producers reject
both external-only fields and expose only their typed preset contract.
