# Local manifest v1

Status: design contract; behavior-inactive until the local-platform integration
series is complete.

`nvt.dev/local/v1` is the single human-authored, non-secret local-platform
manifest. The implementation lives in `localplatform/manifest`. It accepts one
bounded YAML document, rejects aliases, duplicate or unknown fields, unsupported
scalar tags, excessive depth/node/byte counts, invalid names and enums, unsafe
paths, unresolved references, mutable OCI image tags, and fields that could
embed credentials.

The document defines logical secrets by file reference, provider accounts,
reusable profiles, named provider-neutral repositories, persistent
workstations, disposable or retained workflows, the built-in
`github-comments` producer, and external digest-pinned OCI producers. File
references are syntax-checked only in this slice. No file is opened and no
secret value is accepted or emitted.

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
| `broker` | broker generator | account, grant, and broker-repository projections |
| `localController` | local-controller generator | execution profiles, repositories, workstations, and workflows |
| `gateway` | gateway generator | existing local route and credential-portal configuration |
| `producers[]` | the named producer generator | existing bounded schedule-admission client configuration |
| `privateInputs[]` | named trusted service | later file resolution/mount intent; never file contents |

Owner projections intentionally duplicate logical names where two renderers
need them. Each projection contains all non-secret fields needed by its renderer
and no renderer reads another owner's section. A built-in GitHub producer, for
example, receives resolved numeric App and installation IDs, repository
coordinates, and its own private-key input reference; the broker independently
owns its copy of that same logical key.

Generated configuration belongs in administrator-owned Docker volumes. It is
never written into `.broker`, the workspace, or another user-authored host
directory. Preset expansion belongs to local-platform packaging; core,
`agentd`, broker, gateway, controller, producer, Kubernetes, and Helm protocols
are unchanged by this contract.

## Example

See `localplatform/manifest/testdata/valid.yaml`. External producer `config`
is non-secret JSON-shaped data. Keys suggesting tokens, passwords, private
keys, credentials, or secrets are rejected; secret access is declared only as
logical names in the producer `secrets` map.
