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

`agentd` accepts a prompt only after the configured tmux session has existed
continuously for a bounded startup grace (five seconds by default). This is a
runtime-agnostic readiness gate: it avoids treating early tmux session creation
as proof that the interactive target can already receive input, but it cannot
observe a CLI-specific acknowledgement. The grace can be bounded between zero
and 30 seconds with `NVT_AGENT_SESSION_STARTUP_GRACE_SECONDS`. No queued or
injected event is emitted before the gate passes, and this plugin records its
digest only after the queue request succeeds.

AgentRun-generated configs can inject this plugin from `spec.prompt.text`.
Normal local agents are unaffected unless they explicitly configure this plugin.
