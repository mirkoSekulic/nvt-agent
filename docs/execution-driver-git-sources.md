# Immutable execution-driver Git artifacts

`operator/executiondriver/gitresolver` is a topology-neutral acquisition layer
for trusted execution-driver artifacts. It does not register or start a driver,
does not participate in AgentRun reconciliation, and does not depend on the
local-executable host. A future operator process or dedicated driver-host
workload can use the same `Source`, `Artifact`, and `Resolver` boundary, then
explicitly pass the returned executable path and arguments to its chosen
process transport.

The source is complete and administrator-owned:

```go
gitresolver.Source{
    Git: gitresolver.GitSource{
        URL:          "https://github.com/example/nvt-execution-drivers.git",
        Revision:     "0123456789abcdef0123456789abcdef01234567",
        Subdir:   "drivers/example-vm",
    },
    Command: []string{"nvt-example-vm-driver", "--fixed-mode"},
}
```

There is deliberately no YAML, CRD, execution-profile, producer, controller,
or Helm surface for this type in this phase.

## Trust and acquisition boundary

The resolver accepts unauthenticated HTTPS URLs only. The trusted caller must
configure a non-empty exact DNS-host allowlist. Port 443 is the default; any
other HTTPS port must also be approved explicitly. IP literals, userinfo,
alternate protocols, redirects, query strings, fragments, escaped or
non-canonical paths, and implicit credentials are rejected.

Each source names one full lowercase SHA-1 or SHA-256 object ID, a non-empty
contained subdirectory, and one explicit relative executable command. The
temporary client repository is initialized explicitly with the matching Git
object format. The fetched object must be exactly the requested object and must
be a commit.
Branches, tags, abbreviated or symbolic revisions, repository scanning, and
fallback artifacts are not supported. Command arguments are fixed operator
configuration and must not contain credentials; provider credentials belong in
the later process host's explicit environment contract.

Git runs directly without a shell and with a fixed minimal environment. System
and user configuration, credential helpers, prompts, redirects, hooks,
submodules, Git LFS processing, external filters, and file/ext protocols are
disabled. The resolver performs no build, install, or driver process step. A
selected Git LFS pointer, gitlink, missing path, non-executable file, special
file, or escaping symlink fails closed.

Acquisition has one caller/configured deadline, a shallow immutable fetch, a
bounded stdout/stderr path, and explicit checkout entry/byte limits, including
the completion metadata that makes a cache entry publishable. The cache
directory must be owned by the resolver process identity with exact mode
`0700`, and should be placed on an administrator-owned filesystem with an
ordinary storage quota because a Git transport can consume space before a
completed checkout is measured.

## Atomic cache contract

The cache key covers canonical URL, revision, subdirectory, the executable
path, and every fixed argument. A process-safe per-key lock converges concurrent
callers. Fetch and validation occur only in a private temporary directory.
Completion metadata is written and synced before the final resource-bound
validation, then the complete directory is renamed atomically into place.
Interrupted temporary state is removed and is never returned.

Every cache hit revalidates exact completion metadata, commit identity and
type, Git object integrity, worktree/index cleanliness (including untracked
files), absence of gitlinks, resource bounds, path containment, and executable
type/mode. Invalid cached state is removed and reacquired from the same exact
source; another source or executable is never selected.

Errors expose only bounded categories. Remote stdout/stderr, repository
contents, URLs, environment values, and credential-like material are never
returned or logged by the resolver.
