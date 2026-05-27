# agentd Events

`agentd` owns authoritative core events about the agent session. Plugins publish
advisory plugin events.

Reserved core prefixes:

```text
agentd.
health.
prompt.
session.
```

Plugins should publish namespaced events:

```text
plugin.<domain>.<event-name>
```

The domain is a stable event namespace, not necessarily the executable plugin
name. The event `source` field carries the producer identity.

Examples:

```text
plugin.github.pr.comment
plugin.github.pr.review
plugin.github.pr.checks
plugin.test-runner.failed
plugin.checkout-repos.completed
plugin.agent.signal.done
```

`agentd` validates the event envelope and logs the event. It does not validate
plugin-specific payload meaning.

`agentdctl subscribe` provides v1 subscription behavior by tailing
`events.jsonl`. Filters are prefix matches, and subscriber processes are isolated
from `agentd`; a slow or dead subscriber cannot block the daemon.

## Deferred Work

Current `agentd` v1 intentionally does not implement:

- session turn/readiness awareness; prompts are injected as the queue drains
- server-side live event subscription; v1 subscription is client-side log tailing
- agentd process supervision beyond container health checks
- a bounded queue or queue overflow policy
