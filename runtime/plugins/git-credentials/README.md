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
          identity:
            mode: provider
```

`match` values are URL prefixes. The most specific matching rule wins.

`username` is optional and defaults to `x-access-token`. It is only the Git
credential username returned to Git's HTTPS credential flow; it is not commit
authorship.

Commit identity is configured separately:

```yaml
identity:
  mode: provider
```

`mode: provider` asks the credential provider for commit identity. Broker-backed
GitHub App providers return the App bot identity, using the bot user id in the
noreply email.

```yaml
identity:
  mode: explicit
  name: "Mirko Sekulic"
  email: "123456+mirkoSekulic@users.noreply.github.com"
```

`mode: explicit` works with every provider type. If `identity` is omitted, this
plugin does not configure commit identity.

For broker-backed PAT or header providers, use explicit identity:

```yaml
identity:
  mode: explicit
  name: "Automation Bot"
  email: "automation@example.com"
```

`identity.mode: provider` is intended for providers that can report a real
commit identity, currently broker-backed GitHub App providers.

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

When identity is configured, the plugin writes repo-local Git config only:

```sh
git -C <repo> config user.name ...
git -C <repo> config user.email ...
```

It does not set global `user.name` or `user.email`.

Broker-backed header providers configure `http.<url>.extraHeader` the same way
local header providers do. The header secret is therefore present in Git config;
this is a compatibility path, not a zero-trust path.

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

After cloning, `checkout-repos` calls:

```sh
git-credentials configure-repo <repo>
```

This command reads the repo's `origin` URL, matches it against
`credentials[].match`, and applies repo-local commit identity when configured.
When called by `checkout-repos`, failures are logged as warnings and checkout
continues. For repos cloned manually later, run `git-credentials configure-repo
.` yourself.

## Doctor

The plugin doctor checks that Git, `git-credential-nvt`, and
`git-host-credential` are on `PATH`, validates credential rules, and asks
`git-host-credential doctor --provider <name>` to validate each referenced
provider. `identity.mode=provider` is accepted only for providers that support
commit identity; token/header providers should use `identity.mode=explicit`.
