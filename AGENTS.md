# AGENTS.md

Repository-local guidance for nvt-agent work.

- Keep runtime contracts small, explicit, and implementation-swappable.
- `agentd` owns only session I/O, prompt queueing, and event logging. Do not add bootstrap, plugin supervision, host lifecycle, secrets, or egress policy to `agentd`.
- `agentd` is not a security boundary. Secrets belong to the broker and trusted egress path, not `agentd`.
- Treat in-container plugin secrets as local/dev mode only. In mediated production mode, real provider secrets stay in broker/egress services and never enter agent containers.
- Preserve the JSONL `agentd` protocol documented under `protocol/`.
- When changing `runtime/agentd`, `protocol/`, or `runtime/core/prompt-agent.sh`, run the conformance suite from `tests/agentd`. When changing `broker/` or `protocol/broker.md`, run `tests/broker`. When changing runtime plugins or core plugin tooling, run `tests/runtime`.
- When creating a pull request, include a non-empty description that summarizes the change and lists the tests or checks run. Do not rely on `--fill` if it would leave the PR body empty.
- Plugin events are advisory and must use `plugin.<domain>.*`; core/session event names are reserved. Use the `source` field for the producer identity.
- Prefer executable plugins with simple config contracts over core-specific integrations.
- Plugin `exports.tools` are the explicit public command API for a plugin. Exported tools are added to `PATH`; do not add plugin-specific helper logic to core.
- Exported tools run in the untrusted agent container. Do not put raw long-lived secrets in exported tool config; secret-bearing work should go through `brokerctl` or broker-backed providers where possible.
- Keep runtime and plugin contracts container-native and Kubernetes-friendly. Avoid making plugin behavior depend on Docker Compose, host paths, or Docker socket access unless the feature is explicitly local-only.
- Keep management Kubernetes-native: the operator reconciles Agent resources into Pods, storage, Services, routes, policy, and status. Local Docker Compose is a development backend.
- Keep isolation runtime-selectable through `RuntimeClass`, including Kata Containers and other microVM-backed pod runtimes.
- Keep runtime plugins and operator extensions conceptually separate. Runtime plugins implement agent behavior; operator extensions influence scheduling, placement, provisioning, routing, and policy.
- Keep generated agent workspace guidance in `runtime/core/write-agent-instructions.sh` aligned with runtime behavior.
