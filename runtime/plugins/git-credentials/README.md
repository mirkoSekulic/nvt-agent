# git-credentials

`git-credentials` configures Git to use the `git-credential-nvt` helper. It is
the Git-specific adapter that lets ordinary `git clone`, `git fetch`, and
`git push` commands use providers from `git-host-credentials`.

This plugin does not mint tokens itself. It only maps Git URL prefixes to named
credential providers.

Token providers (`github-app` and `token-env`) are exposed through
`git-credential-nvt`. Header providers configure Git `http.<url>.extraHeader`
entries directly.

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

  - name: git-credentials
    source: builtin
    when: before-agent
    config:
      credentials:
        - match: https://github.com/my-user/
          provider: fork-app
          username: x-access-token
```

`match` values are URL prefixes. The most specific matching rule wins.

`username` is optional and defaults to `x-access-token`.

## Runtime Behavior

At startup this plugin writes:

```text
$HOME/.nvt-agent/git-credentials/config.yaml
```

Then it configures Git globally:

```sh
git config --global credential.helper nvt
git config --global credential.useHttpPath true
```

Git resolves helper name `nvt` to the exported `git-credential-nvt` command on
`PATH`.

## Relationship To checkout-repos

`checkout-repos` stays auth-agnostic. If this plugin is enabled before
`checkout-repos`, private clones use Git's normal credential helper flow:

```yaml
plugins:
  - name: git-host-credentials
    source: builtin
    config: {}

  - name: git-credentials
    source: builtin
    when: before-agent
    config: {}

  - name: checkout-repos
    source: builtin
    when: before-agent
    restart: never
    config:
      repos:
        - url: https://github.com/my-user/private-repo.git
```

## Doctor

The plugin doctor checks that Git, `git-credential-nvt`, and
`git-host-credential` are on `PATH`, validates credential rules, and asks
`git-host-credential doctor --provider <name>` to validate each referenced
provider.
