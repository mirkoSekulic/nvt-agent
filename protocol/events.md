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
plugin.<plugin-name>.<event-name>
```

Examples:

```text
plugin.github-pr-watcher.comment-added
plugin.test-runner.failed
plugin.checkout-repos.completed
```

`agentd` validates the event envelope and logs the event. Future versions will
add subscribers. It does not validate plugin-specific payload meaning.

## Deferred Work

Current `agentd` v1 intentionally does not implement:

- session turn/readiness awareness; prompts are injected as the queue drains
- live event subscription; plugin events are logged only
- agentd process supervision beyond container health checks
- a bounded queue or queue overflow policy
