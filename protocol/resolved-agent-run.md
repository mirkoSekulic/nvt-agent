# Resolved agent-run contract

`nvt.resolved-agent-run/v1` is the provider-neutral, non-secret desired value
consumed by trusted local execution backends. It is deliberately independent of
Kubernetes CRDs, Docker Compose YAML, process supervision, route publication,
and lifecycle storage. Those responsibilities belong to later local-controller
layers and backend adapters.

The Go contract and deterministic resolver live in `protocol/resolvedrun`.
This first version defines data and resolution only; it does not introduce a
controller process or change Kubernetes `AgentSchedule`/`AgentRun` behavior.

## Ownership and precedence

Resolution has four explicit layers:

1. trusted platform defaults provide the runtime image, runtime process,
   tools, code-server settings, and resource defaults;
2. the selected trusted profile may replace each of those complete blocks and
   exclusively owns credential-provider mappings, broker grants, egress policy,
   profile instructions, and the allowed backend/retention selections;
3. the selected trusted workflow exclusively owns repositories and workflow
   instructions;
4. the local-run request supplies only a run ID, the authenticated immutable
   principal, profile name, workflow name, retention-policy name, and an
   optional backend name.

Profile overrides replace complete blocks. The resolver does not merge partial
security policy. A request can select only a backend and retention policy
explicitly allowed by the selected profile. Their effective configuration is
looked up from the administrator-owned catalogs.

The request decoder is strict and bounded. Unknown and duplicate fields are
rejected. In particular, a producer cannot submit repositories, checkout
paths, credential-provider aliases, broker providers or grants, capabilities,
runtime commands, preseed, tools, code-server settings, resources, egress
policy, execution configuration, persistence, or TTL values.

## Principal identity

The owner is the exact canonical HTTPS issuer plus immutable subject. The
optional display name is presentation data and never participates in profile,
workflow, repository, provider, retention, or backend selection.

## Contract shape

A resolved value contains:

- the contract version, run ID, exact principal, and selected profile/workflow;
- image, direct runtime command/arguments, optional direct resume command,
  autonomy, user, process-scoped non-secret environment, and non-secret
  preseed;
- administrator-owned repository checkouts and their approved public
  credential-provider aliases;
- tools and code-server configuration;
- broker provider names, repository bounds, capability names, preparation
  names, materialization mode, egress hosts, permission ceilings, and bounded
  request quotas;
- direct or mediated egress policy, the approved proxy provider, and whether a
  distinct paired-egress identity is required;
- profile and workflow workspace instructions in separate ordered fields;
- portable CPU/memory quantities, persistence intent, retention name, TTLs,
  and the selected trusted execution-backend name/kind.

The execution backend has only a stable name and provider-neutral kind in this
portable value. Backend implementation/configuration remains trusted controller
configuration. A backend must reject resources or policy it cannot honor; it
must not silently weaken the resolved value.

## Repository and credential boundary

Workflows own exact repository IDs, HTTPS checkout URLs, and destinations. The
repository ID must equal the canonical URL host and path (with an optional
terminal `.git` removed), so policy for one repository cannot be applied to a
different checkout host. URLs cannot contain userinfo, query parameters,
fragments, encoded paths, or traversal. A workflow can reference only a
credential alias declared by the selected profile. Both that mapping and its
matching broker grant must allow the exact repository ID. Repository bounds
support exact identifiers and one bounded trailing `/*` form.

The contract has no credential-value field. It can carry provider names,
capability/grant metadata, and routing policy only. It never carries an access
token, refresh token, password, private key, authorization code, provider
configuration, credential file, injected header, broker agent token, or paired
egress token. Runtime environment rejects credential-bearing variable-name
forms such as token, secret, password, credential, private-key, API-key, and
authorization variables. Runtime environment and preseed remain trusted
deployment configuration and must not be used for real credentials; broker
custody and the trusted egress path remain the sensitive-data boundary.

Mediated resolution requires a paired-egress identity, an approved proxy
provider present in the broker grants, and a known transport. It rejects
file-bundle grants. Direct resolution rejects mediated materializations and
paired/proxy policy. The resolver contains no provider-name, provider-host, or
provider-specific branches.

## Input example

The following abbreviated JSON illustrates administrator-owned configuration.
Names and values are examples, not built-in providers or policies:

```json
{
  "defaults": {
    "image": "registry.example/agent-runtime@sha256:...",
    "runtime": {
      "command": "agent-cli",
      "args": ["run"],
      "resume": {"command": "agent-cli", "args": ["resume"]},
      "autonomy": "trusted-local",
      "user": "root"
    },
    "tools": {},
    "code_server": {},
    "resources": {"cpu_limit": "2", "memory_limit": "8Gi"}
  },
  "profiles": [{
    "name": "engineering",
    "credential_providers": [{
      "name": "source",
      "broker_provider": "source-app",
      "repositories": ["git.example/approved/*"]
    }],
    "broker": {"grants": [{
      "provider": "source-app",
      "repositories": ["git.example/approved/*"],
      "capabilities": ["injection.headers"],
      "materialization": "header-inject",
      "egress_hosts": ["git.example:443"]
    }, {
      "provider": "runtime-main",
      "capabilities": ["injection.headers"],
      "materialization": "header-inject",
      "egress_hosts": ["runtime.example:443"]
    }]},
    "egress": {
      "mode": "mediated",
      "transport": "forward-proxy",
      "proxy_provider": "runtime-main",
      "paired_egress_required": true
    },
    "allowed_backends": ["container"],
    "default_backend": "container",
    "allowed_retentions": ["persistent"]
  }],
  "workflows": [{
    "name": "development",
    "repositories": [{
      "id": "git.example/approved/project",
      "url": "https://git.example/approved/project.git",
      "path": "project",
      "credential_provider": "source"
    }]
  }],
  "execution_backends": [{"name": "container", "kind": "container"}],
  "retention_policies": [{
    "name": "persistent",
    "persistence": {"workspace": true, "runtime_state": true}
  }]
}
```

The corresponding caller-owned request is only:

```json
{
  "run_id": "infra",
  "principal": {
    "issuer": "https://issuer.example",
    "subject": "immutable-subject",
    "display_name": "Display only"
  },
  "profile": "engineering",
  "workflow": "development",
  "retention": "persistent",
  "backend": "container"
}
```

Omitting `backend` selects the profile's trusted default. Unknown profiles,
workflows, backends, retention policies, malformed principals, conflicts,
repository-policy mismatches, and unsupported extra request fields fail closed.

## Kubernetes compatibility boundary

Kubernetes continues to resolve `AgentSchedule` directly into immutable
`AgentRun` resources through the existing operator implementation. It does not
serialize a CRD into this contract and does not route reconciliation through
the local resolver. Operator compatibility coverage compares the shared fields
produced by existing profile/workflow resolution with an equivalent local
resolution and asserts that the Kubernetes `AgentRun` is unchanged. The full
operator suite remains the regression gate for existing Pod/VM behavior.
