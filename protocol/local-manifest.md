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
reusable profiles, persistent workstations, disposable or retained workflows,
the built-in `github-comments` producer, and external digest-pinned OCI
producers. File references are syntax-checked only in this slice. No file is
opened and no secret value is accepted or emitted.

## Canonical compilation and ownership

Compilation produces deterministic JSON. Map entries and set-like lists are
sorted, and named sequences are sorted by name. Therefore YAML spelling, map
order, and set order do not affect the compiled bytes.

The compiled model is private local-platform intent, not a new runtime or
network protocol. Its sections establish these exclusive rendering boundaries:

| Section | Output owner | Existing contract eventually rendered |
| --- | --- | --- |
| `broker` | broker generator | broker configuration, grants, and account references |
| `localController` | local-controller generator | existing local platform/workstation schedule configuration |
| `gateway` | gateway generator | existing local route and credential-portal configuration |
| `producers[]` | the named producer generator | existing bounded schedule-admission client configuration |
| `privateInputs[]` | named trusted service | later file resolution/mount intent; never file contents |

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
