# AGENTS.md

Repository-local guidance for nvt-agent work.

- Keep runtime contracts small, explicit, and implementation-swappable.
- `agentd` owns only session I/O, prompt queueing, and event logging. Do not add bootstrap, plugin supervision, host lifecycle, secrets, or egress policy to `agentd`.
- `agentd` is not a security boundary. Secrets belong in future host/broker mechanisms, not in `agentd`.
- Preserve the JSONL `agentd` protocol documented under `protocol/`.
- When changing `runtime/agentd`, `protocol/`, or `runtime/core/prompt-agent.sh`, run the conformance suite from `tests/agentd`.
- Plugin events are advisory and must use `plugin.<name>.*`; core/session event names are reserved.
- Prefer executable plugins with simple config contracts over core-specific integrations.
- Keep runtime and plugin contracts container-native and Kubernetes-friendly. Avoid making plugin behavior depend on Docker Compose, host paths, or Docker socket access unless the feature is explicitly local-only.
- Treat the long-term manager direction as Kubernetes-native: a future operator should reconcile Agent custom resources into Pods/PVCs/Services/routes/status. Local Docker Compose is a development backend.
- Keep isolation runtime-selectable. Future Kubernetes support should allow hardened pod runtimes through `RuntimeClass`, such as Kata Containers or other microVM-backed pod runtimes.
- Keep runtime plugins and future operator extensions conceptually separate. Runtime plugins implement agent behavior; operator extensions influence scheduling, placement, provisioning, routing, and policy.
- Keep generated agent workspace guidance in `runtime/core/write-agent-instructions.sh` aligned with runtime behavior.
