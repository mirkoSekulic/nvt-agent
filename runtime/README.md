# Runtime session launch and continuation

Runtime bootstrap accepts a provider-neutral command contract:

```yaml
runtime:
  command: generic-fresh-command
  args: [--fresh-option]
  initial-prompt:
    delivery: argument
    text: Perform the initial task.
  resume:
    command: generic-resume-command
    args: [--resume-option]
```

`runtime.resume` is optional. When it is absent, launch and restart behavior is
unchanged: the runtime uses `runtime.command` and `runtime.args`, including the
configured initial-prompt argument, on every process start. No continuation
marker is read or written.

When `runtime.resume` is present, both its `command` and the fresh
`runtime.command` must be non-empty strings. Both argument fields are arrays of
strings and default to empty. The initial prompt is appended only to the fresh
arguments; it is never passed to the resume command. Commands and arguments are
deployment configuration, not secrets, and must not contain credentials.
Runtime core does not discover tool-owned sessions or add tool-specific flags.

## Durable resume marker

The launcher owns one explicit marker at
`$NVT_STATE_DIR/runtime-session.json`. Its only version 1 form is:

```json
{"state":"resumable","version":1}
```

No command, argument, prompt, session identifier, credential, or other
tool-specific data is stored in the marker. Unknown versions, fields, states,
or malformed JSON fail startup.

For a missing marker, the launcher uses the fresh command. A resume-enabled
fresh launch gets one attempt, preventing the existing fast-exit retry loop
from delivering the initial prompt more than once. Only after the tmux session
survives the existing fast-exit stability window does the launcher atomically
write `resumable`, sync the containing directory, and publish the launcher
readiness marker consumed by `agentd`. A failed initial launch therefore leaves
no marker, and the next container start still uses the fresh command.

On a later process start, `resumable` selects `runtime.resume.command` and its
arguments. A failed resume is retried only within the existing bounded launcher
policy and then fails the container; it never falls back to the fresh command.
The marker remains `resumable`, so another process start cannot fall back to the
fresh command or replay its initial-prompt argument.

Marker replacement uses a mode `0600` temporary file in the same directory,
file flush and `fsync`, `os.replace`, and a directory `fsync`. This matches the
runtime's single-launcher container model and ensures readers see either the
previous complete state or the next complete state. Persistent AgentRun home
storage preserves the marker across Pod recreation. With ephemeral storage,
loss of the marker is intentionally best-effort and the next startup is fresh.

This state is independent of plugin-owned files under `NVT_STATE_DIR`. Runtime
core does not inspect, remove, or reinterpret GitHub watcher registry or seen
state, and `agentd` remains responsible only for session I/O, prompt queueing,
and event logging.

## Pending prompt queue

When `runtime.resume` is configured, generic startup gives `agentd` a durable
queue directory under `$NVT_STATE_DIR/agentd/prompt-queue`. `agentd` persists a
prompt before acknowledging it as queued, restores pending entries in FIFO
order after restart, and removes each entry after its injection attempt. The
queue is released only after the resumed session passes the normal readiness
gate. A failed resume therefore leaves pending prompts for a later restart and
never redirects them into a new session.

Queue entries are mode `0600` inside a mode `0700` directory and contain the
full prompt payload needed for recovery. They are prompt-queue data, not resume
state; the resume marker itself remains non-secret and contains no prompt or
provider data. A crash between terminal injection and durable acknowledgement
can cause at-least-once redelivery. Without `runtime.resume`, `agentd` retains
its existing in-memory-only queue behavior and no durable queue directory is
configured.
