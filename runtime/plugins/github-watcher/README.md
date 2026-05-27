# github-watcher

`github-watcher` watches GitHub pull requests and turns selected PR activity
into `agentd` events and optional prompts.

It is a long-running `after-agent` plugin. In broker mode it reads GitHub through
`brokerctl http request`, so the watcher does not receive a GitHub token for API
reads. Direct mode remains available as a local/dev fallback and gets tokens from
`git-host-credentials`:

```sh
git-host-credential token --provider <provider>
```

The watcher supports both static PRs from `agent.yaml` and dynamic registrations
through the exported `github-watch` command. Dynamic registrations are persisted
under:

```text
$NVT_STATE_DIR/plugins/github-watcher/registry.json
```

Because that directory is in the agent home volume, dynamically registered PRs
continue to be watched after container restart.

## Static Configuration

```yaml
plugins:
  - name: git-host-credentials
    source: builtin
    config:
      default-provider: fork-app
      providers:
        - name: fork-app
          type: github-app
          app-id-env: GITHUB_APP_ID
          installation-id-env: GITHUB_APP_INSTALLATION_ID
          private-key-base64-env: GITHUB_APP_PRIVATE_KEY_BASE64
          match:
            - github.com/my-user/*

  - name: github-watcher
    source: builtin
    when: after-agent
    restart: always
    config:
      default-provider: fork-app
      poll-seconds: 60
      broker:
        enabled: true
        provider: fork-app

      prs:
        - repo: my-user/my-repo
          number: 123
          provider: fork-app # optional, falls back to default-provider
          broker:
            enabled: true
            provider: fork-app # optional, falls back to top-level broker provider or watch provider
          labels:
            - frontend
            - high-priority

          publish:
            enabled: true

          comments:
            enabled: true
            author-associations:
              - OWNER
              - MEMBER
              - COLLABORATOR
            prompt:
              enabled: true
              # template optional

          reviews:
            enabled: true
            author-associations:
              - OWNER
              - MEMBER
              - COLLABORATOR
            prompt:
              enabled: true
              # template optional

          checks:
            enabled: true
            mode: aggregate # v1 only supports aggregate
            publish-failed-transition: true
            publish-passed-transition: false
            prompt:
              failed: true
              passed: false
              # template optional
```

Templates are optional. If omitted, the plugin uses built-in default prompts for
comments, reviews, and checks.

`labels` are metadata carried into published events and prompt text. They do not
filter GitHub labels in v1.

When `broker.enabled` is true, read-only GitHub API calls are executed through
`brokerctl http request`. The watcher does not receive the GitHub App private
key or installation token for those API reads. Direct mode remains available as
a local/dev fallback.

## Dynamic Registration

`github-watch` is exported by the plugin and is available on `PATH` after
`export-plugin-tools` runs.

Register a PR non-interactively:

```sh
github-watch register \
  --repo my-user/my-repo \
  --number 123 \
  --provider fork-app \
  --label frontend \
  --label high-priority
```

Register interactively:

```sh
github-watch register --interactive
```

List dynamic registrations:

```sh
github-watch list
```

Remove a dynamic registration:

```sh
github-watch remove --repo my-user/my-repo --number 123
```

Dynamic registrations use the same defaults as static config:

- `--provider` falls back to `default-provider`
- comments, reviews, and checks are enabled by default
- comments and reviews prompt by default for dynamic registrations
- failed check transitions prompt by default
- passed check transitions do not prompt by default

Useful flags:

```sh
github-watch register --repo my-user/my-repo --number 123 --no-comments
github-watch register --repo my-user/my-repo --number 123 --no-reviews
github-watch register --repo my-user/my-repo --number 123 --no-checks
github-watch register --repo my-user/my-repo --number 123 --no-prompt-comments
github-watch register --repo my-user/my-repo --number 123 --prompt-passed-checks
```

## Events

The plugin publishes:

```text
plugin.github.pr.comment
plugin.github.pr.review
plugin.github.pr.checks
```

Payloads include enough context for downstream plugins to react without calling
GitHub again:

```json
{
  "repo": "my-user/my-repo",
  "number": 123,
  "url": "https://github.com/my-user/my-repo/pull/123",
  "labels": ["frontend"],
  "event": "comment",
  "author": "octocat",
  "author_association": "COLLABORATOR",
  "body": "Please update the tests",
  "summary": "Please update the tests"
}
```

## Startup And Restart Behavior

On first sight of a PR, the watcher baselines existing comments, reviews, and
check status. It does not publish old activity as new events. This prevents
prompt storms when a watcher is first configured or when the container restarts.

After the baseline exists, only newer comments/reviews or aggregate check status
transitions are published.

Deleted comments are ignored. Edited comments use `updated_at`, so edits newer
than the current watermark can produce a comment event.

## Checks

Only aggregate check mode is supported in v1. The plugin reduces all check runs
for the PR head commit to one status:

- `failed`: at least one check has `failure`, `timed_out`, `cancelled`, or
  `action_required`
- `passed`: all completed checks are `success`, `skipped`, or `neutral`
- `pending`: any check is still running
- `none`: no check runs were found

By default the watcher publishes failed transitions and ignores passed
transitions, which keeps CI noise low.

## Author Associations

Comments and reviews can be filtered by GitHub `author_association`:

```yaml
author-associations:
  - OWNER
  - MEMBER
  - COLLABORATOR
```

This is cheaper and easier to maintain than listing every trusted username.

## Security

In direct mode, this plugin receives GitHub API access through in-container
provider tokens from `git-host-credentials`. That is local/dev behavior.

In broker mode, read-only GitHub API calls go through `brokerctl http request`.
That keeps the GitHub App private key and derived API token inside the broker
for those reads. Token mode may still be used by Git credential helpers for
operations that require a token, such as Git push.

The production operator direction is for GitHub credentials and egress to be
broker-mediated so the autonomous agent container does not hold raw GitHub App
private keys or long-lived tokens.
