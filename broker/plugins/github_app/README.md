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
`/v1/injection/headers` for the paired egress identity, becoming the Phase 4
git credential source (`docs/phase4-git-mediation-plan.md`). Injection accepts
exactly these path shapes:

- `/{owner}/{repo}[.git]/info/refs` (GET) — smart-HTTP ref advertisement
- `/{owner}/{repo}[.git]/git-upload-pack` (POST) — fetch/clone
- `/{owner}/{repo}[.git]/git-receive-pack` (POST) — push
- `/repos/{owner}/{repo}/...` — REST API paths (methods per `allow.methods`)

git paths are answered with `authorization: Basic base64(x-access-token:<token>)`;
API paths with `Bearer`. Every shape runs the same two-layer repo check
(provider `allow.repositories` ∩ the agent grant's `repositories`) and mints a
single-repo installation token.

Read/write mapping: `git-upload-pack` mints `contents: read`;
`git-receive-pack` requires the effective contents permission to be `write`
and mints `contents: write`; `info/refs` mints the effective permission (the
`?service=` query never reaches the broker). The effective permission is the
narrower of the grant-level `permissions.contents` (default `read`) and the
provider-level `allow.permissions.contents` ceiling.

Routing (`/v1/injection/routing`) reports `git: true` for this provider so
runtime bootstrap installs the git redirect wiring.
