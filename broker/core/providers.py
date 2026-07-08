from broker.plugins.github_app.provider import GithubAppProvider
from broker.plugins.claude_oauth.provider import ClaudeOAuthProvider
from broker.plugins.codex_oauth.provider import CodexOAuthProvider
from broker.core.config import provider_entries
from broker.plugins.placeholder.provider import PlaceholderProvider
from broker.plugins.static_headers.provider import StaticHeadersProvider
from broker.plugins.static_token.provider import StaticTokenProvider


PROVIDERS = {
    "claude-oauth": ClaudeOAuthProvider,
    "codex-oauth": CodexOAuthProvider,
    "github-app": GithubAppProvider,
    "headers": StaticHeadersProvider,
    "placeholder": PlaceholderProvider,
    "token": StaticTokenProvider,
}


def load_providers(config):
    output = {}
    for entry in provider_entries(config, PROVIDERS):
        provider = PROVIDERS[entry["plugin"]](entry)
        output[provider.name] = provider
    return output
