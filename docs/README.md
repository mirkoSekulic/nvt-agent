# Documentation

Start with the repository [README](../README.md). Use this page to find the
maintained guide or contract for a specific task.

## Get started

- [Local development](local-development-agent.md): configure and operate local
  workstations and producers.
- [Local credentials](local-credential-portal.md): enroll Codex or Claude
  accounts through the local gateway.
- [Kubernetes installation](../charts/nvt/README.md): install and configure the
  Helm chart.
- [Local kind environment](local-kind-github-producer.md): run the Kubernetes
  stack and GitHub producer in kind.

## Credentials and access

- [Credential portal](credential-portal.md): self-service credential custody
  and enrollment.
- [Codex authentication](codex-auth.md): direct and mediated Codex modes.
- [Claude authentication](claude-auth.md): API key and subscription OAuth
  modes, including refresh behavior.
- [OAuth2/OIDC eligibility](oauth-eligibility.md): login claim enrichment and
  admission policy.
- [Transparent mediated egress](transparent-egress-architecture.md): trust
  boundaries, capture, injection, and enforcement.

## Kubernetes APIs

- [AgentRun](../operator/docs/agentrun.md): workload, runtime, workspace,
  credentials, lifecycle, and status.
- [AgentSchedule](../operator/docs/agentschedule.md): producer admission,
  profiles, parallelism, and duplicate work.

## Runtime and extension

- [Runtime](../runtime/README.md): session startup, continuation, and prompt
  recovery.
- [Runtime plugins](../runtime/plugins/README.md): executable plugins, exported
  tools, events, and lifecycle hooks.
- [Gateway](../gateway/README.md): browser routing, login, and owner access.
- [GitHub comments producer](../producers/github-comments/README.md): commands,
  scheduling, and reactions.

## Protocols

Files under [`protocol/`](../protocol/) are normative contracts:

- [`agentd`](../protocol/agentd.md)
- [Events](../protocol/events.md)
- [Local manifest](../protocol/local-manifest.md)
- [Resolved agent runs](../protocol/resolved-agent-run.md)
- [Local controller](../protocol/local-controller.md)
- [Local routes](../protocol/local-routes.md)
- [Broker](../protocol/broker.md)
- [Broker providers](../protocol/broker-provider.md)
- [Prepared provider metadata](../protocol/prepared-provider-metadata.md)
- [Credential injection](../protocol/injection.md)
- [Transparent egress](../protocol/transparent-egress.md)

## Testing

- [CI coverage](ci-coverage.md)
- [Kubernetes smoke tests](../tests/operator/kind/README.md)
- [Kata smoke tests](../tests/operator/kata/README.md)

Protocol and API references take precedence over component READMEs. Git history
and merged pull requests preserve completed design work; active documentation
describes the current system.
