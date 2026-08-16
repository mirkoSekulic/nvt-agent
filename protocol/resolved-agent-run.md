# Resolved agent-run contract

`nvt.resolved-agent-run/v1` is the provider-neutral, non-secret desired value
consumed by trusted local execution backends. It is independent of Kubernetes
CRDs, Compose YAML, process supervision, route publication, and durable
lifecycle storage. Those responsibilities belong to later local-controller
layers and backend adapters.

The Go contract and deterministic resolver live in `protocol/resolvedrun`.
The separate [local-controller protocol](local-controller.md) durably stores a
complete resolved snapshot and owns local lifecycle metadata; resolution itself
remains independent of that process. Neither contract changes Kubernetes
`AgentSchedule`/`AgentRun` behavior.

## Authority and precedence

Resolution receives two different inputs:

1. a trusted authorization context containing the authenticated canonical
   issuer plus immutable subject and the exact profile/workflow pairs that the
   caller may select; and
2. a strictly decoded caller request containing only run ID, one authorized
   profile/workflow selection, retention name, optional backend name, an
   optional initial prompt, and an optional bounded HTTPS source URL used only
   for display/navigation provenance.

Identity is deliberately absent from the caller request. The resolver freezes
the principal from the trusted context and rejects a profile/workflow pair not
listed in that context before looking it up in the global catalogs. A display
name is presentation data and never participates in authorization.

Trusted platform defaults own image, runtime controls, the complete agent
configuration, resources, and lifecycle events. A trusted profile may replace
those complete blocks and exclusively owns credential-provider mappings,
broker grants, egress policy, profile instructions, and the allowed
backend/retention selections. The selected trusted workflow exclusively owns
repositories and workflow instructions. Partial security-policy merging is not
performed.

Unknown and duplicate JSON fields are rejected. In particular, the caller
cannot submit a principal, repository, checkout path, credential alias, broker
provider/grant, capability, runtime configuration, plugin, exposure, resource,
egress policy, execution configuration, persistence policy, or TTL.

## Complete desired behavior

A resolved value contains:

- contract version, run ID, trusted principal, and authorized profile/workflow;
- an optional exact HTTPS source URL that is never fetched or rendered into
  executable agent configuration;
- image plus typed runtime identity, autonomy, user, container capabilities,
  Docker kernel-log-device policy, and required Docker networks;
- a bounded immutable base `agent_config` JSON object carrying the existing
  provider-neutral profile configuration, including fresh/resume commands,
  process environment, preseed, tools, code-server, non-managed plugins and
  their config, and HTTP exposures;
- the caller's bounded UTF-8 initial prompt;
- lifecycle completion and failure event names;
- administrator-owned repository checkouts and approved public credential
  aliases, including an optional non-secret credential username;
- broker provider names and non-secret grant/capability metadata;
- direct or mediated egress policy;
- separately ordered profile/workflow instructions;
- portable resources, persistence intent, retention, TTLs, and trusted
  execution-backend name/kind.

`agent_config` is limited to 256 KiB, must be a duplicate-free JSON object, and
must contain a valid direct runtime command. The prompt is limited to 64 KiB,
must be valid UTF-8, and cannot contain NUL. Agent configuration is trusted
administrator input: it must not contain real credentials. Existing runtime
configuration that declares non-managed plugins, exposures, tools, preseed, or
code-server behavior is carried unchanged instead of being re-expressed
through a lossy second schema.

The optional source URL is limited to 2048 bytes, must use HTTPS without
userinfo or control characters, and preserves valid query strings and
fragments exactly. It is presentation metadata only: it does not participate
in authorization, selection, routing, lifecycle, credentials, or execution.

### One runtime-rendering rule

The base block is not itself executable. `RenderAgentConfig` is the single
adapter transformation from a resolved value to the generic runtime bootstrap
document. Typed fields are authoritative, so the base block must not contain:

- `runtime.initial-prompt` (owned by `Prompt`);
- `runtime.proxy` or top-level `egress` (owned by `Egress` and `Broker`); or
- the `git-host-credentials`, `git-credentials`, or `checkout-repos` plugins
  (owned by `CredentialProviders` and `Workflow.Repositories`).

Any presence is a configuration conflict and fails before resolution. The
renderer clones the base, injects the typed initial prompt, injects the selected
runtime proxy for tunnel transports, renders broker/egress metadata, emits the
three managed repository plugins in stable dependency order before other
plugins. Enforced egress, including redirect transport, is marked
`operator-prepared: true`; bootstrap therefore uses the already bounded route
hosts/Git flags and never attempts an in-agent broker lookup. Backends must
execute the rendered result, never the base block, and must not independently
repeat these transformations.

`Lifecycle` remains portable desired intent, not runtime plugin configuration.
Each backend/controller observes the named agentd events and applies its own
completion, failure, process, and retention behavior. The portable renderer
does not inject the Kubernetes `lifecycle-termination` plugin or its
`/dev/termination-log` path.

Backend provisioning supplies only non-secret `AgentConfigBindings`: one
forward-proxy URL for forward-proxy/transparent, or an exact provider-to-base-
URL map for redirect header-injection grants. Missing, extra, malformed, or
wrong-transport bindings fail closed. Endpoint allocation remains outside the
portable desired value.

The execution backend has only a stable name and provider-neutral kind in this
portable value. Backend implementation/configuration remains trusted
controller configuration. A backend must reject resources or policy it cannot
honor rather than silently weakening the resolved value.

## Repository and credential boundary

Repository checkout and broker authorization use two explicit namespaces:

- `checkout_target` is the host-qualified match key derived exactly from the
  canonical HTTPS checkout URL, such as
  `github.com/Altinn/altinn-studio`; and
- `broker_repository` is the administrator-declared provider-native repository
  identifier passed unchanged to broker grant matching, such as
  `Altinn/altinn-studio`.

Generic code does not strip hosts or otherwise translate between these
namespaces. The selected credential mapping must allow the checkout target and
its referenced broker grant must independently allow the broker repository.
Both support exact values and one bounded trailing `/*` form. Checkout URLs
cannot contain userinfo, query parameters, fragments, encoded paths, or
traversal. A public checkout has no credential provider and therefore must omit
`broker_repository`; it is rendered only into the checkout plugin.

Credential mappings retain the bounded generic broker credential kind
(`token`, `headers`, or `mediated`). A mediated Git grant must use
`credential_kind: mediated`, so runtime plugins cannot silently fall back to
asking the agent-side broker client for a token. The profile may retain an
optional `default_credential_provider`, which must name one approved mapping
and is rendered as the generic host-credential default for tools that do not
select an alias explicitly. Repository entries also retain
an optional HTTPS `upstream` remote and optional commit identity policy.
Identity mode is either `provider`, with no inline fields, or `explicit`, with
bounded administrator-authored name and email. Enforced provider identity
requires the corresponding grant's non-secret `identity` preparation. None of
these fields contains credential material.

The contract has no credential-value field. It may carry provider names,
capability/grant metadata, and routing policy only. It never carries an access
token, refresh token, password, private key, authorization code, credential
file, injected header, broker agent token, or paired-egress token. Runtime
environment names that indicate credential values are rejected. Broker custody
and the trusted egress path remain the sensitive-data boundary.

Mediated resolution requires a paired-egress identity and a known transport.
Redirect does not use a runtime proxy selector and may use the established
unenforced compatibility mode. Forward-proxy and transparent require mediated
egress, enforcement, and an approved proxy provider present in the broker
grants; the renderer places that provider under `runtime.proxy.provider` for
the runtime command. Mediated policy rejects file-bundle grants. Direct policy
rejects mediated materializations and paired/proxy policy. The resolver
contains no provider-specific branches.

## Configuration and request example

This abbreviated trusted configuration uses example names only:

```json
{
  "defaults": {
    "image": "registry.example/agent-runtime@sha256:...",
    "runtime": {"type":"generic-agent","autonomy":"trusted-local","user":"root"},
    "agent_config": {
      "runtime": {
        "command":"agent-cli",
        "args":["run"],
        "resume":{"command":"agent-cli","args":["resume"]}
      },
      "plugins":[],
      "expose":{"http":[]}
    },
    "resources":{"cpu_limit":"2","memory_limit":"8Gi"},
    "lifecycle":{"complete_on":["plugin.work.completed"],"fail_on":["plugin.work.failed"]}
  },
  "profiles":[{
    "name":"engineering",
    "credential_providers":[{
      "name":"source",
      "broker_provider":"source-app",
      "credential_kind":"mediated",
      "match_targets":["git.example/approved/*"]
    }],
    "broker":{"grants":[{
      "provider":"source-app",
      "repositories":["approved/*"],
      "capabilities":["injection.headers"],
      "preparations":["identity"],
      "materialization":"header-inject",
      "egress_hosts":["git.example:443"],
      "git":true
    },{
      "provider":"runtime-main",
      "capabilities":["injection.headers"],
      "materialization":"header-inject",
      "egress_hosts":["runtime.example:443"]
    }]},
    "egress":{"mode":"mediated","transport":"forward-proxy","enforced":true,"proxy_provider":"runtime-main","paired_egress_required":true},
    "allowed_backends":["container"],
    "default_backend":"container",
    "allowed_retentions":["persistent"]
  }],
  "workflows":[{
    "name":"development",
    "repositories":[{
      "checkout_target":"git.example/approved/project",
      "broker_repository":"approved/project",
      "url":"https://git.example/approved/project.git",
      "path":"project",
      "upstream":"https://git.example/upstream/project.git",
      "credential_provider":"source",
      "identity":{"mode":"provider"}
    }]
  }],
  "execution_backends":[{"name":"container","kind":"container"}],
  "retention_policies":[{"name":"persistent","persistence":{"workspace":true,"runtime_state":true}}]
}
```

The authentication/policy layer supplies the trusted principal and an exact
authorization such as `engineering` plus `development`. The caller-owned JSON
request is only:

```json
{
  "run_id":"infra",
  "profile":"engineering",
  "workflow":"development",
  "retention":"persistent",
  "backend":"container",
  "prompt":"Implement the requested change."
}
```

Omitting `backend` selects the authorized profile's trusted default. A
caller-supplied `principal` field, an unauthorized profile/workflow pair,
unknown selections, malformed trusted identity, repository-policy mismatch,
or unsupported field fails closed.

## Kubernetes compatibility boundary

Kubernetes continues to resolve `AgentSchedule` directly into immutable
`AgentRun` resources through the existing operator implementation. It does not
serialize CRD YAML into this contract and does not route reconciliation through
the local resolver.

The operator compatibility gate constructs an existing profiled `AgentRun`
through the real schedule/profile/workflow builders, including its prompt,
full runtime configuration, plugins, exposure, lifecycle, container and Docker
controls, resources, instructions, and a real mediated provider with provider
identity, optional upstream, host-qualified checkout, and provider-native broker
repository. It removes only the fields that become the typed local overlay,
renders them through `RenderAgentConfig`, and compares the result with the
existing operator's final runtime rendering after removing only the asserted
Kubernetes lifecycle adapter from the comparison. The test separately pins
that the Kubernetes renderer still emits that adapter and that the portable
renderer does not. It also verifies that local resolution does not mutate the
Kubernetes object. The full operator and execution-driver image suites remain
regression gates for existing Pod/VM behavior.
