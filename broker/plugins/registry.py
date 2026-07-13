from broker.plugins.claude_oauth.provider import ClaudeOAuthProvider
from broker.plugins.codex_oauth.provider import CodexOAuthProvider
from broker.plugins.github_app.provider import GithubAppProvider
from broker.plugins.placeholder.provider import PlaceholderProvider
from broker.plugins.static_headers.provider import StaticHeadersProvider
from broker.plugins.static_token.provider import StaticTokenProvider


BUILTIN_PROVIDERS = {
    "claude-oauth": ClaudeOAuthProvider,
    "codex-oauth": CodexOAuthProvider,
    "github-app": GithubAppProvider,
    "headers": StaticHeadersProvider,
    "placeholder": PlaceholderProvider,
    "token": StaticTokenProvider,
}
