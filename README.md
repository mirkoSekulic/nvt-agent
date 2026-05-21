# nvt-agent

`nvt-agent` is a planned platform for running coding agents in isolated runtimes and coordinating them from higher-level task managers.

The first target is a container-based workflow where Claude Code, Codex, or another terminal agent runs inside a prepared environment. A manager can then create agents for issues or tasks, inject prompts, watch progress, and create pull requests or merge requests through provider plugins.

## Goals

- Run coding agents in disposable or persistent runtimes.
- Support multiple agent CLIs, such as Claude Code and Codex.
- Keep the runtime backend replaceable: Docker first, later Podman, Kata, VMs, Kubernetes, or remote workers.
- Keep SCM providers replaceable: GitHub, GitLab, Gitea, Azure DevOps, or others.
- Allow external plugins and watchers to prompt agents without changing core.
- Support manager-driven workflows such as one issue becoming one branch, one agent, and one PR/MR.

## Architecture

```text
manager
  -> plans work
  -> finds/claims issues or tasks
  -> starts agent runtimes
  -> sends initial prompts
  -> monitors lifecycle
  -> asks SCM plugins to create PRs/MRs

agent platform
  -> manages runtime lifecycle
  -> bootstraps tools
  -> creates persistent home/workspace
  -> starts agent session
  -> injects prompts
  -> exposes logs/exec/status

plugins
  -> manager plugins: issue sources, schedulers, long-running agent policies
  -> agent plugins: PR/MR updates, CI checks, comments, local context
  -> SCM providers: GitHub, GitLab, Gitea, Azure DevOps
```

## Core Commands

The core should stay small and expose stable primitives:

```sh
nvt-agent create <agent>
nvt-agent up <agent>
nvt-agent prompt <agent> --stdin
nvt-agent exec <agent> -- <command>
nvt-agent logs <agent>
nvt-agent down <agent>
nvt-agent rm <agent>
```

Once `prompt` exists, any watcher or plugin can feed work into an agent.

## Agent Runtime

Each agent runs in its own isolated runtime.

The initial implementation can use Docker with a runner-style base image, for example:

```text
ghcr.io/catthehacker/ubuntu:act-24.04
```

Each runtime should have:

- mounted workspace
- persistent home volume
- bootstrap script
- git credentials/config
- agent CLI installed
- persistent terminal session

The agent command should be configurable:

```yaml
agent:
  command: claude
```

or:

```yaml
agent:
  command: codex
  args:
    - --sandbox
    - danger-full-access
    - --ask-for-approval
    - never
```

## Prompt Injection

The platform should treat terminal agents as black boxes.

For the first version, use `tmux` as the persistent session and input surface:

```sh
tmux new-session -d -s agent -c /workspace "$AGENT_COMMAND"
```

Prompt injection:

```sh
tmux load-buffer -b agent-prompt /tmp/prompt.txt
tmux paste-buffer -b agent-prompt -t "$PANE_ID" -p -r
tmux send-keys -t "$PANE_ID" Enter
```

This lets the platform support Claude Code, Codex, or another terminal agent without implementing a model loop itself.

## Manager

The manager is responsible for higher-level work orchestration.

The manager should be configurable through plugins. It should not only know how
to poll issues. It should be able to run manager plugins that discover work,
start long-running agents, schedule autonomous task agents, and coordinate
provider-specific workflows.

There are two plugin scopes:

```text
manager plugins
  -> decide what work exists
  -> claim/schedule work
  -> spawn agents
  -> watch global queues/issues/events
  -> apply policy

agent plugins
  -> run inside or beside one agent
  -> watch PR/MR comments/checks
  -> inject prompts into that agent
  -> provide tools/context for that agent
```

Recommended first model:

```text
one issue = one branch = one agent runtime = one PR/MR
```

Example flow:

```text
1. Poll issues with label `agent-ready`.
2. Claim issue with label `agent-running`.
3. Create branch `agent/issue-123`.
4. Start runtime `repo-issue-123`.
5. Inject issue prompt.
6. Agent edits, tests, commits, and pushes.
7. Manager creates PR/MR.
8. Manager comments on issue.
9. Manager stops runtime or leaves it for inspection.
```

Example policy:

```yaml
manager:
  max_parallel_agents: 2
  max_runtime: 2h
  eligible_labels:
    - agent-ready
  claim_label: agent-running
  done_label: agent-pr-created
  branch_prefix: agent/
  cleanup: stopped

  plugins:
    - name: github-issues
      command: nvt-github-issue-source
      restart: always
      config:
        repo: org/repo
        label: agent-ready

    - name: default-scheduler
      command: nvt-default-scheduler
      restart: always
      config:
        max_parallel_agents: 2
```

The issue planner is one possible manager plugin, not a core assumption.

## Manager State

The manager needs durable state so it can survive restarts and avoid duplicating
work.

Use SQLite for manager state and the filesystem for logs, prompts, and
artifacts.

Example layout:

```text
~/.local/share/nvt-agent/
  manager.db
  agents/
    repo-issue-123/
      state.json
      prompts/
      logs/
  plugins/
    github-issues/
      state.json
      cache/
```

Useful manager tables:

```text
agents
  id
  name
  template
  status
  runtime_kind
  runtime_id
  workspace_path
  created_at
  updated_at

tasks
  id
  source
  source_id
  provider
  repo
  title
  status
  assigned_agent_id
  branch
  change_request_url
  created_at
  updated_at

plugins
  id
  name
  scope
  status
  command
  pid
  started_at
  updated_at

events
  id
  source
  type
  dedupe_key
  payload_json
  created_at

prompt_deliveries
  id
  agent_id
  source
  prompt_path
  status
  created_at

change_requests
  id
  provider
  repo
  url
  source_branch
  target_branch
  status
  task_id
```

Task state should be explicit:

```text
discovered
claimed
agent_starting
prompt_sent
running
branch_pushed
change_created
done
failed
timed_out
```

## Agent Lifecycle

The agent can signal completion, but the manager owns final lifecycle control.

Recommended completion contract:

```text
/workspace/.nvt-agent/result.json
```

Example:

```json
{
  "status": "completed",
  "summary": "Implemented the requested change.",
  "branch": "agent/issue-123",
  "commit": "abc1234",
  "checks": [
    {
      "name": "tests",
      "command": "npm test",
      "status": "passed"
    }
  ],
  "change_request_ready": true
}
```

The manager should also enforce lifecycle policy:

```yaml
lifecycle:
  max_runtime: 2h
  idle_timeout: 30m
  stop_on_completion: true
  keep_workspace: true
  cleanup_after: 7d
  failure_action: keep_for_inspection
```

The manager may stop or kill an agent at any time:

```sh
nvt-agent down repo-issue-123
```

or:

```sh
nvt-manager task stop issue-123
```

## Manager Runtime

The manager can also run in a container.

For Docker, the simplest approach is Docker-outside-of-Docker by mounting the host Docker socket:

```sh
docker run -d \
  --name nvt-agent-manager \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v nvt-agent-state:/var/lib/nvt-agent \
  -v "$PWD/workspaces:/workspaces" \
  nvt-agent-manager:latest
```

Inside the manager container, Docker CLI or Docker SDK can create sibling agent containers through the host Docker daemon.

Security note: mounting `/var/run/docker.sock` gives the manager powerful control over the host Docker daemon. This is suitable for trusted local automation, but not for untrusted users or plugins.

## Plugins

Plugins should start as external processes with a simple contract.

Avoid dynamic plugin loading at first. A plugin can be any executable supervised
by the manager or started for a specific agent.

Core provides environment variables:

```sh
NVT_AGENT_NAME=<agent>
NVT_AGENT_WORKSPACE=/workspace
NVT_AGENT_STATE_DIR=/home/agent/.local/state/nvt-agent/plugins/<plugin>
NVT_AGENT_BIN=/usr/local/bin/nvt-agent
```

Plugins send prompts through:

```sh
nvt-agent prompt "$NVT_AGENT_NAME" --stdin
```

Example watcher:

```sh
while true; do
  update="$(check_external_system)"
  if [ -n "$update" ]; then
    nvt-agent prompt "$NVT_AGENT_NAME" --stdin <<EOF
<external_update>
$update
</external_update>
EOF
  fi
  sleep 60
done
```

This allows independent plugins for:

- GitHub PR watcher
- GitLab MR watcher
- Azure DevOps PR watcher
- Gitea PR watcher
- issue planner
- Jira watcher
- Slack command watcher
- scheduled prompts

Manager plugins can use the same core commands to create agents:

```sh
nvt-agent create repo-issue-123 --template claude-dev
nvt-agent up repo-issue-123
nvt-agent prompt repo-issue-123 --stdin
```

## SCM Abstraction

Use generic terminology:

```text
change request = GitHub PR, GitLab MR, Gitea PR, Azure DevOps PR
issue = issue, work item, or task
```

Provider interface:

```go
type SCMProvider interface {
    CreateChangeRequest(ctx context.Context, input ChangeRequestInput) (ChangeRequest, error)
    Comment(ctx context.Context, id string, body string) error
    GetChangeRequest(ctx context.Context, id string) (ChangeRequest, error)
    ListChecks(ctx context.Context, id string) ([]Check, error)
}
```

Provider implementations:

```text
GitHubProvider
GitLabProvider
GiteaProvider
AzureDevOpsProvider
```

The core can handle basic Git operations:

```text
create branch
commit
push
status
diff
```

Provider plugins should handle:

```text
create PR/MR
comment on PR/MR
watch checks
watch reviews/comments
map provider events into prompts
```

## Identity

Identity should be configurable per provider.

Examples:

```yaml
scm:
  provider: github
  auth:
    type: app
```

```yaml
scm:
  provider: gitlab
  auth:
    type: token
    token_env: GITLAB_TOKEN
```

```yaml
scm:
  provider: github
  auth:
    type: cli
    command: gh
```

For GitHub:

- GitHub App actions show as `app-name[bot]`.
- Machine user actions show as that normal user.
- Personal token actions show as the human user.

The core should avoid hardcoding any provider-specific identity behavior.

## Issue Planner

The issue planner can be a manager component or plugin.

Example config:

```yaml
issue_planner:
  enabled: true
  labels:
    include:
      - agent-ready
    exclude:
      - blocked
      - security
      - needs-design
  max_open_prs: 1
  branch_prefix: agent/
  require_human_label: true
  dry_run: false
```

Example prompt:

```text
<issue_task>
Provider: github
Repository: org/repo
Issue: #123
Title: Fix parser crash on empty input
URL: https://github.com/org/repo/issues/123

Instructions:
- Create branch agent/issue-123-parser-crash.
- Investigate the issue.
- Implement the smallest correct fix.
- Add or update tests.
- Run the relevant test suite.
- Commit the changes.
- Push the branch.
- Report the final commit hash and test result.
</issue_task>
```

## Suggested Technology

Use Go for the manager and core CLI/daemon:

- single binary
- good Docker SDK
- good GitHub/GitLab clients
- good concurrency
- easy to package

Use shell scripts for early plugins where possible.

Use Docker for the first runtime, while keeping the backend interface open for Podman, Kata, VMs, Kubernetes, or remote workers.

## MVP

Build the agent runtime first, then the manager. The manager should consume the
same core API a human uses manually.

First useful `nvt-agent` version:

1. `nvt-agent create/up/prompt/logs/down/rm`
2. Docker-based agent runtime
3. persistent home volume and workspace mount
4. bootstrap script support
5. `tmux` session running `claude` or `codex`
6. manual prompt injection into one named agent
7. shell/exec/logs for inspection

Then add:

1. one SCM provider plugin
2. one watcher plugin that calls `nvt-agent prompt`
3. one manager loop that picks issues labeled `agent-ready`
4. one issue becomes one branch, one agent runtime, and one PR/MR

Separate binaries or scripts with a stable `nvt-agent prompt` contract are
enough for the first plugin model.
