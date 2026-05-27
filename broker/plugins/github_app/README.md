# github-app broker provider

Trusted broker provider for GitHub App credentials.

The provider runs only inside the broker image/service. It must not be copied
into the agent image. It holds the GitHub App private key, signs App JWTs,
mints repo-scoped installation tokens, and injects authorization for
broker-executed GitHub API requests. It also exposes the GitHub App bot commit
identity. The noreply email uses the bot user's numeric id from
`GET /users/<slug>[bot]`, not the App id or installation id.
