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
            - header-env: COMPANY_GIT_AUTH_HEADER
```

`match` entries are glob patterns matched against normalized repo targets such
as `github.com/my-user/project`. If more than one provider matches, pass
`--provider` explicitly.

## Exported Tools

```sh
git-host-credential resolve --target github.com/my-user/project
git-host-credential type --provider fork-app
git-host-credential token --provider fork-app
git-host-credential headers --provider company-headers
git-host-credential doctor --provider fork-app
```

`gh-auth` runs GitHub CLI commands with a provider token through `GH_TOKEN`
without calling `gh auth login` or writing GitHub CLI auth state:

```sh
gh-auth --provider fork-app pr view 123 --repo my-user/project
gh-auth pr checks 123 --repo my-user/project
```

When `--provider` is omitted, `gh-auth` resolves from `--repo`, the current
`origin` remote, or `default-provider`.

## Security

This plugin currently supports local/dev mode where raw secrets are available
inside the agent container. GitHub App private keys are especially sensitive:
they can mint installation tokens for every repository in the installation.

Production operator mode should move raw secrets into a broker sidecar/service.
In that model this plugin becomes a broker client and exported tools receive
only scoped, short-lived credentials or broker-mediated responses.
