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

`agentd` validates the event envelope, logs the event, and relays it to future
subscribers. It does not validate plugin-specific payload meaning.

