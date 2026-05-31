# initial-prompt

`initial-prompt` delivers one configured prompt to the running agent through
`agentdctl prompt`.

```yaml
plugins:
  - name: initial-prompt
    source: builtin
    when: after-agent
    restart: never
    config:
      text: |
        Implement the requested change.
```

The plugin reads `config.text`. Empty text exits successfully without delivery.
For non-empty text, it stores the SHA-256 digest in:

```text
$NVT_STATE_DIR/initial-prompt/last.sha256
```

If the same prompt hash was already delivered, it exits without enqueueing a
duplicate prompt. The hash file is written only after `agentdctl prompt`
succeeds.

Delivery failures from `agentdctl prompt` are retried for a short bounded
period to tolerate agent startup races. Config validation failures and a missing
`agentdctl` executable fail immediately.

AgentRun-generated configs can inject this plugin from `spec.prompt.text`.
Normal local agents are unaffected unless they explicitly configure this plugin.
