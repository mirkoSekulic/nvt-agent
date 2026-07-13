# github-app broker provider

Trusted broker provider for GitHub App credentials.

The provider runs only inside the broker image/service. It must not be copied
into the agent image. It holds the GitHub App private key, signs App JWTs,
mints repo-scoped installation tokens, and injects authorization for
broker-executed GitHub API requests. It also exposes the GitHub App bot commit
identity. The noreply email uses the bot user's numeric id from
`GET /users/<slug>[bot]`, not the App id or installation id.

## Header injection (mediated git-over-HTTPS)

With `config.injection-hosts` (e.g. `[github.com]`) the provider serves
`/v1/injection/headers` for the paired egress identity, becoming the mediated
git credential source (`protocol/injection.md`). Injection accepts
exactly these path shapes:

- `/{owner}/{repo}[.git]/info/refs` (GET) — smart-HTTP ref advertisement
- `/{owner}/{repo}[.git]/git-upload-pack` (POST) — fetch/clone
- `/{owner}/{repo}[.git]/git-receive-pack` (POST) — push
- `/repos/{owner}/{repo}/...` — REST API paths (methods per `allow.methods`)
- `/graphql` (POST) — GraphQL API paths, only when the agent grant contains
  exactly one concrete repository. Multi-repo and wildcard grants are rejected
  because GraphQL has no repository in the URL for the broker to scope.

git paths are answered with `authorization: Basic base64(x-access-token:<token>)`;
API and GraphQL paths with `Bearer`. Every shape runs the same two-layer repo check
(provider `allow.repositories` ∩ the agent grant's `repositories`) and mints a
single-repo installation token.

Read/write mapping: `git-upload-pack` mints `contents: read`;
`git-receive-pack` requires the effective contents permission to be `write`
and mints `contents: write`; `info/refs` mints the effective permission (the
`?service=` query never reaches the broker). The effective permission is the
narrower of the grant-level `permissions.contents` (default `read`) and the
provider-level `allow.permissions.contents` ceiling. Push and `info/refs`
tokens also retain explicitly granted non-content permissions, such as
`workflows: write`, only when the provider allowlist permits the same level.
Fetch-only `git-upload-pack` tokens remain scoped to `contents: read`.

Routing (`/v1/injection/routing`) reports `git: true` for this provider so
runtime bootstrap installs the git redirect wiring.
