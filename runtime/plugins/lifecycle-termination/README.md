# lifecycle-termination

`lifecycle-termination` is the credential-less lifecycle reporter used by
operator-managed, enforced AgentRuns. It subscribes to ordinary `agentd`
events through `agentdctl`, writes a bounded JSON event name to the container's
Kubernetes termination-message file, and terminates the agent container.

The operator injects this plugin and observes the message from the owned Pod's
status. The plugin carries no Kubernetes identity, callback token, broker
token, or provider credential. Event names are still checked against the
owning AgentRun's `spec.lifecycle` before status changes.

```yaml
plugins:
  - name: lifecycle-termination
    source: builtin
    when: after-agent
    restart: always
    config:
      completeOn: [plugin.agent.signal.done]
      failOn: [plugin.agent.failed]
      terminationMessagePath: /dev/termination-log
```

This plugin is operator-reserved in literal zero-secret mode. Users should
declare `spec.lifecycle`; they should not add the plugin directly.
