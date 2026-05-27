# git-host-credentials

`git-host-credentials` defines named credential providers for Git hosting
services. It is a tool-only plugin: it does not run a lifecycle process, but it
exports commands that other plugins, terminal users, and the agent can call.

## Configuration

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

        - name: personal-token
          type: token-env
          token-env: GIT_HOST_TOKEN
          match:
            - github.com/my-user/*

        - name: company-headers
          type: headers
          headers:
            - header-env: COMPANY_GIT_API_KEY_HEADER

        - name: brokered-fork-app
          type: broker
          broker-provider: fork-app
          match:
            - github.com/my-user/*

        - name: brokered-company-headers
          type: broker
          broker-provider: company-headers
          credential-kind: headers
          match:
            - altinn.studio/repos/digdir/oed
```

`match` entries are glob patterns matched against normalized repo targets such
as `github.com/my-user/project`. If more than one provider matches, pass
`--provider` explicitly.

## Exported Tools

```sh
git-host-credential resolve --target github.com/my-user/project
git-host-credential type --provider fork-app
git-host-credential token --provider fork-app
git-host-credential token --provider brokered-fork-app --target github.com/my-user/project
git-host-credential identity --provider brokered-fork-app --target github.com/my-user/project
git-host-credential headers --provider brokered-company-headers --target altinn.studio/repos/digdir/oed
git-host-credential doctor --provider fork-app
```

`type: broker` delegates token/header retrieval and provider commit identity
lookup to `brokerctl`. It is intended for broker mode, where raw provider
secrets live in the broker service instead of the agent container.

Broker providers default to token credentials. Use `credential-kind: headers`
when the broker provider exposes static headers:

```yaml
type: broker
broker-provider: company-headers
credential-kind: headers
```

Broker-backed header providers need a concrete repo target so the broker can
apply agent grants. Prefer repo-level `match` entries for them. For self-hosted
Git, configure the broker provider with `target-mode: literal` and match the
full host/path repository id, for example `altinn.studio/repos/digdir/oed`.

`gh-auth` runs GitHub CLI commands with a provider token through `GH_TOKEN`
without calling `gh auth login` or writing GitHub CLI auth state:

```sh
gh-auth --provider fork-app pr view 123 --repo my-user/project
gh-auth pr checks 123 --repo my-user/project
```

When `--provider` is omitted, `gh-auth` resolves from `--repo`, the current
`origin` remote, or `default-provider`.

## Security

Prefer `type: broker` for secret-bearing providers. Local `token-env` and
`headers` providers keep raw secrets in the agent container and should be
treated as local/dev fallback.

Production operator mode should move raw secrets into a broker sidecar/service.
In that model this plugin becomes a broker client and exported tools receive
only scoped, short-lived credentials or broker-mediated responses.

Broker-backed static PAT/header providers are still compatibility paths for
Git. Token mode returns a token to the agent, and header mode writes headers into
Git config. GitHub App providers are stronger because broker-minted Git tokens
are short-lived and repo-scoped.
