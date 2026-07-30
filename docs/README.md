# Documentation

Start with the repository [README](../README.md) for the system overview and
local quick start. The documents below are the maintained sources of truth.

## Guides

- [Local development agent](local-development-agent.md): configure a local
  Compose agent, broker grants, repositories, and plugins.
- [Local Kubernetes GitHub producer](local-kind-github-producer.md): run
  the operator, broker, producer, and real AgentRun Pods in kind.
- [Claude authentication](claude-auth.md): direct and mediated Claude Code
  authentication through the broker.
- [Codex authentication](codex-auth.md): broker-managed Codex authentication
  and the real mediated proof.

## Architecture

- [Transparent mediated egress](transparent-egress-architecture.md): current
  trust boundaries, traffic paths, enforcement, and limitations.
- [AgentRun API](../operator/docs/agentrun.md): workload specification and
  lifecycle.
- [AgentSchedule API](../operator/docs/agentschedule.md): admission,
  parallelism, and duplicate-work behavior.
- [Runtime plugins](../runtime/plugins/README.md): plugin contracts, tools,
  events, and lifecycle hooks.

## Protocols

Files under [`protocol/`](../protocol/) are normative contracts:

- [`agentd`](../protocol/agentd.md): session I/O and prompt queueing.
- [Events](../protocol/events.md): JSONL event format.
- [Broker](../protocol/broker.md): identities, grants, and provider material.
- [Injection](../protocol/injection.md): mediated credential injection.
- [Transparent egress](../protocol/transparent-egress.md): capture-to-egressd
  transport.
- [Execution drivers](../protocol/execution-driver.md): portable trusted-driver
  lifecycle, status, and cleanup contract.
- [Native host bundle](../protocol/host-bundle.md): digest-pinned OCI artifact,
  native guest installation, activation, and service boundary.
- [Native guest control session](../protocol/native-session.md): authenticated
  guest-initiated control transport and bounded agentd relay.
- [Native workspace tunnel](../protocol/native-workspace.md): separate bounded
  yamux data-plane contract and conformance proof for fixed loopback workspace
  services, including authorized production external-VM browser routing.
- [Native VM mediated egress](../protocol/native-egress.md): provider-neutral
  infrastructure-confinement, exact identity, flow-routing, readiness, and
  cleanup contract with a hermetic conformance proof and production broker
  identity authority, trusted guest flow client, and a standalone exact-binding
  relay with bounded flow transport; target adaptation, captured traffic,
  operator readiness, and provider enforcement are not implemented.

## Operations And Testing

- [CI coverage](ci-coverage.md): automated suites and manual proofs.
- [Kubernetes smoke tests](../tests/operator/kind/README.md): kind test cases.
- [Helm chart](../charts/nvt/README.md): installation and production values.
- [Gateway](../gateway/README.md): browser routing and OIDC authorization.

Component READMEs explain only how to build, configure, or operate that
component. If a component README conflicts with a protocol or API reference,
the protocol or API reference is authoritative.

Completed implementation plans are intentionally not retained in the active
documentation tree. Git history and merged pull requests preserve that design
history; maintained docs describe the system as it exists now.
