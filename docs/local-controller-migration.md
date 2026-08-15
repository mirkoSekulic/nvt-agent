# Migrating local agents to nvt-local-controller

The migration path is additive. Existing `.agents/<name>/agent.yaml`, static
Compose projects, broker providers, and `.broker/agents.yaml` entries remain
unchanged and are the rollback path.

## Install and configure

Build the trusted control-plane images as usual, then copy and edit the small
manifest:

```sh
cp templates/local-controller-migration.yaml .agents/local-controller-migration.yaml
make local-agent-migrate
make infra-up
```

The manifest supplies only trusted metadata that cannot be inferred safely:
the immutable local principal, runtime type/autonomy/user, image, backend,
retention, and an explicit allowlist of reviewed non-secret runtime commands,
arguments, resume arguments, environment entries, and credential usernames. A source value is copied
only when it exactly matches that administrator-owned allowlist. Each named run selects a generated profile and workflow. Profile and
workflow names may be shared only when their complete generated values are
identical; conflicting reuse fails closed.

`nvt-local-migrate` reads each selected `agent.yaml`, the matching non-egress
entry in `.broker/agents.yaml`, and the provider names in `.broker/broker.yaml`.
It writes `.broker/local-controller.json` mode 0600. `infra-up` selects that
file as `NVT_LOCAL_CONTROLLER_NAMED_RUNS_CONFIG` when present. An existing
`NVT_LOCAL_CONTROLLER_SCHEDULING_CONFIG` remains a separate producer schedule
document, so persistent named workstations and authenticated disposable work
with its own TTL/retention policy operate together. Neither document contains
the other's bearer value. Omission preserves the current static-only behavior.

The converter supports credential-free direct agents and the current managed,
enforced transparent-mediation shape. A direct agent with broker grants remains
on the static rollback path because the local Docker backend has no zero-secret
direct materialization. The converter extracts the built-in
`git-host-credentials`, `git-credentials`, and `checkout-repos` declarations
into typed profile/workflow fields. Repository matches use the runtime helper's
canonical repository identity, so a credential rule without `.git` matches the
same checkout with `.git`; the non-secret credential username and identity are
preserved. A multi-repository broker grant is selected automatically only when
the checkout's provider-native owner/repository is an exact unique entry.
Otherwise an explicit `broker_repositories` mapping is required
in the manifest from the host-qualified checkout target to the provider-native
broker repository identifier:

```yaml
broker_repositories:
  github.example/organization/repository: organization/repository
```

The immutable base is deliberately narrower than arbitrary local `agent.yaml`.
It accepts the validated runtime allowlist, non-executing tool declarations,
empty editor settings, bounded HTTP exposures, the two exact `agent-init`
preseed shapes, and reference-only built-in plugins with empty configuration
(apart from the bounded GitHub watcher polling cadence).
Shell hooks, arbitrary editor values, custom/Git plugin configuration,
unapproved runtime arguments or environment values, and any other value-bearing
escape hatch are rejected and remain on static Compose. Unsupported transports,
duplicate managed plugins, unknown providers, unmatched checkout rules,
aliases, duplicate YAML keys, and ambiguous grants are also rejected.

The output includes only approved deployment values, provider names,
grants/capabilities, repository identifiers, and policy. Broker plugin
configuration, token hashes, credential paths, arbitrary source plugin values,
and credential bytes are never copied. This is structural allowlisting, not
arbitrary value redaction. Treat the generated document as reviewed deployment
configuration and never put real secrets in its runtime allowlist.

## Verify and operate

The three representative named workstations (`nvt-dev`, `studio`, and `infra`)
exercise the same controller path. Open the stable session routes at
`/agents/<run-id>/` or `<run-id>.agent.localhost`; named `expose.http` services
use `<exposure>.<run-id>.agent.localhost` without base-path rewriting. The
gateway remains the authorization and WebSocket proxy boundary.

Persistent policies retain workspace, runtime home/session marker, and Docker
data. Controller or host restart reconciles the immutable snapshot, stable
routes, volumes, and generic `runtime.resume.command`; there are no Codex or
Claude branches in the controller. Disposable producer-created runs use the
same scheduling/status/cancel/TTL APIs and become terminal only after exact-
owned containers, networks, identities, generated state, and disposable
volumes are cleaned.

Automated tests use synthetic GitHub-App-shaped, PAT-shaped, Codex-file-shaped,
and Claude-file-shaped providers. The migration tests prove current structural
shapes (`.git` normalization, credential usernames, and multi-repository
grants), reference-only output, atomic named-run restart, and simultaneous
disposable producer admission/status/cancel/cleanup. The cumulative hermetic
local-controller suites prove mediated injection, restart/resume,
path/host/application routes, WebSocket proxying, audience separation, and
secret-needle absence across generated Compose, Docker inspect/environment,
logs, controller state, and agent files. They do not claim that this container
ran the developer's current private configuration or completed a live
third-party login. A real local credential check, when needed, must be run manually against
the operator's existing broker state, must not modify or print credential
files, and must record only pass/fail and redacted diagnostics.

## Troubleshooting

- `migration failed`: keep static Compose running and fix the unsupported or
  ambiguous source. The command does not modify source files.
- `local-run-configuration-unavailable`: the generated selection conflicts
  with durable state or no longer resolves. Restore the previous document; do
  not delete state merely to bypass provenance checks.
- route is present but unready: check the bounded controller reason and the
  broker/egress dependencies. Do not copy credentials into the run.
- reconnect after restart starts fresh: verify the original agent config has a
  generic `runtime.resume` command and that the retention preserves runtime
  state.

## Roll back

Stop or explicitly delete the controller-owned run so bounded cleanup
converges. Move `.broker/local-controller.json` aside (or explicitly set
`NVT_LOCAL_CONTROLLER_NAMED_RUNS_CONFIG=`) and run `make infra-up`; then use the
unchanged `make agent-up NAME=<name>` static Compose workflow. Existing source
agent files and broker provider configuration were never rewritten. Do not run
both static and controller-owned copies of the same agent identity at once.
