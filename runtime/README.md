# Runtime session launch and continuation

## Optional code-server agent terminal

Code-server can open one dedicated integrated terminal and attach it to the
managed agent session when the workspace folder opens:

```yaml
code-server:
  agentTerminal:
    openOnStartup: true
```

The feature is disabled when `agentTerminal` is omitted or when
`openOnStartup` is `false`. When enabled, bootstrap atomically writes one
non-secret, mode `0600` NVT-owned enable marker under `NVT_STATE_DIR`. The
bundled workspace-side extension activates after code-server startup, reads
only that exact marker, creates one focused integrated terminal whose
executable is exactly `nvt-session-attach`, and reuses a surviving terminal
with the same stable NVT identity across extension activation or browser
reload. It does not configure a default terminal profile, so manually created
terminals remain ordinary shells.

This mechanism does not create, parse, authorize, or execute user/workspace
tasks. In particular, bootstrap never sets `task.allowAutomaticTasks`, so a
repository-controlled `.vscode/tasks.json` entry with `runOn: folderOpen` does
not become authorized by this feature. Existing user `tasks.json` content,
including any task with the display label `NVT: Agent Session`, is untouched.

`nvt-session-attach` is the generic session attachment boundary. Its current
implementation waits up to 60 seconds for the managed session and then
attaches to it. It never creates or replaces a session. The implementation can
be replaced if the session backend changes without changing code-server
bootstrap or extension activation. `AGENT_SESSION` selects the managed session
name; the default is `agent`.

Disabling or omitting the feature removes only the NVT-owned enable marker.
Bootstrap and the extension do not read or modify any code-server setting or
task for this feature. Re-running bootstrap is idempotent. `agentTerminal` must
be an object and `openOnStartup` must be a boolean.

Runtime bootstrap accepts a provider-neutral command contract:

```yaml
runtime:
  command: generic-fresh-command
  args: [--fresh-option]
  env:
    RUNTIME_MODE: deployment-value
    SERVICE_ENDPOINT: https://service.example.test
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

`runtime.env` is an optional object whose names must be portable environment
variable names and whose values must be strings. Values are passed literally:
there is no shell parsing, variable interpolation, or path expansion. The same
map is inherited by the fresh and resume runtime children, and a configured
value overrides the corresponding inherited process value. It is not exported
to the container entrypoint, plugins, `agentd`, code-server, or plugin
supervisors. When `runtime.env` is absent, runtime launch behavior is unchanged.
This scoping applies to the `runtime.env` map itself; other bootstrap features
may independently install system trust or persist their own environment values
for components that source the generated container environment.

These values are deployment configuration stored inside the agent container
and in its generated runtime command document. They must not contain real,
long-lived secrets; use the repository's credential and mediation mechanisms
for sensitive material.

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
order after restart, and removes each entry only after successful terminal
injection. A failed injection remains durable for the next restart. The
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
