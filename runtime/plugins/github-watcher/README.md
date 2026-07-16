# github-watcher

`github-watcher` watches GitHub pull requests and turns selected PR activity
into `agentd` events and optional prompts.

It is a long-running `after-agent` plugin. It always makes ordinary GitHub API
requests. A generic `plugin.egress.provider` declaration gives its process an
exact provider-scoped proxy in mediated deployments, where egressd injects the
real credential outside the agent. The watcher does not inspect egress mode,
construct proxy URLs, or invoke `gh-auth`/`brokerctl`. Direct mode remains a
local/dev fallback and gets a token only when a direct provider is explicitly
configured:

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
    egress:
      provider: github-main-app
    config:
      poll-seconds: 60

      prs:
        - repo: my-user/my-repo
          number: 123
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
              - CONTRIBUTOR
            prompt:
              enabled: true
              # template optional

          reviews:
            enabled: true
            author-associations:
              - OWNER
              - MEMBER
              - COLLABORATOR
              - CONTRIBUTOR
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

          closed:
            enabled: true
            remove: false # static watches are never removed from agent.yaml
            publish: true
            prompt: false
```

Templates are optional. If omitted, the plugin uses built-in default prompts for
comments, reviews, and checks.

`labels` are metadata carried into published events and prompt text. They do not
filter GitHub labels in v1.

For local direct use, omit `egress` and configure `default-provider` or a
per-watch `provider`; the watcher then asks `git-host-credential` for that
explicit credential. In mediated use, omit those direct credential fields and
set only the outer `egress.provider`. The removed `broker` request fields fail
with a migration message rather than selecting a second transport.

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

- `--provider` falls back to `default-provider`; both are optional for generic
  process-level mediation
- comments, reviews, and checks are enabled by default
- comments and reviews prompt by default for dynamic registrations
- failed check transitions prompt by default
- passed check transitions do not prompt by default
- close handling is enabled by default
- merged PRs publish `plugin.github.pr.merged` by default
- closed unmerged PRs publish `plugin.github.pr.closed` by default
- dynamic registrations remove themselves from `registry.json` after merge or close by default
- close prompts are disabled by default
- comment and review author associations default to `OWNER`, `MEMBER`, `COLLABORATOR`, and `CONTRIBUTOR`

Useful flags:

```sh
github-watch register --repo my-user/my-repo --number 123 --no-comments
github-watch register --repo my-user/my-repo --number 123 --no-reviews
github-watch register --repo my-user/my-repo --number 123 --no-checks
github-watch register --repo my-user/my-repo --number 123 --no-prompt-comments
github-watch register --repo my-user/my-repo --number 123 --prompt-passed-checks
github-watch register --repo my-user/my-repo --number 123 --no-remove-on-close
github-watch register --repo my-user/my-repo --number 123 --prompt-on-close
github-watch register --repo my-user/my-repo --number 123 --no-publish-on-close
github-watch register --repo my-user/my-repo --number 123 \
  --author-association OWNER \
  --author-association MEMBER \
  --author-association COLLABORATOR \
  --author-association CONTRIBUTOR
```

## Events

The plugin publishes:

```text
plugin.github.pr.comment
plugin.github.pr.review
plugin.github.pr.checks
plugin.github.pr.merged
plugin.github.pr.closed
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

Terminal PR state is tracked separately as `<repo>#<number>:closed`, with the
seen value set to `merged` or `closed`. This prevents repeated terminal events
when a closed static watch remains configured or a dynamic watch is explicitly
kept with `--no-remove-on-close`.

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
  - CONTRIBUTOR
```

`CONTRIBUTOR` is useful for fork, upstream, and organization PR workflows where
GitHub may report maintainers or admins with that association. This is cheaper
and easier to maintain than listing every trusted username.

## Security

In direct mode, this plugin receives GitHub API access through in-container
provider tokens from `git-host-credentials`. That is local/dev behavior.

In mediated mode, read-only GitHub API calls use the generic process proxy and
egressd. The watcher sends no token or placeholder. The GitHub App private key
and derived API token remain in the broker. The provider name is carried as a
non-secret proxy capability hint, so separate watcher plugin processes can use
different providers for the same host without guessing. Direct token mode is
retained for local development when an explicit direct provider is configured.

The production operator direction is for GitHub credentials and egress to be
broker-mediated so the autonomous agent container does not hold raw GitHub App
private keys or long-lived tokens.
