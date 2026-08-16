# Local manifest v1

Status: design contract; behavior-inactive until the local-platform integration
series is complete.

`nvt.dev/local/v1` is the single human-authored, non-secret local-platform
manifest. The implementation lives in `localplatform/manifest`. It accepts one
bounded YAML document, rejects aliases, duplicate or unknown fields, unsupported
scalar tags, excessive depth/node/byte counts, invalid names and enums, unsafe
paths, unresolved references, mutable OCI image tags, and undeclared
secret-bearing fields.

The document defines logical secrets by file reference, provider accounts,
reusable profiles, named provider-neutral repositories, persistent
workstations, disposable or retained workflows, the built-in
`github-comments` producer, and external digest-pinned OCI producers. File
references are syntax-checked only in this slice. No file is opened and no
referenced private value is accepted or emitted. The explicitly named
`publicConfig` boundary described below is administrator-asserted public data.

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

## Example

See `localplatform/manifest/testdata/valid.yaml`. External producer
`publicConfig` is an explicit trust boundary: its bounded JSON-shaped content
is intentionally copied to generated configuration and must be public. The
compiler cannot infer whether an arbitrary string is sensitive. Secret access
is therefore declared only through the producer `secrets` map; ordinary
`config` and secret-shaped public keys are rejected. Built-in producers reject
both external-only fields and expose only their typed preset contract.
