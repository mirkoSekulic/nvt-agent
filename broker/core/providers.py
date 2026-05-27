from broker.plugins.github_app.provider import GithubAppProvider
from broker.core.config import provider_entries
from broker.plugins.static_headers.provider import StaticHeadersProvider
from broker.plugins.static_token.provider import StaticTokenProvider


PROVIDERS = {
    "github-app": GithubAppProvider,
    "headers": StaticHeadersProvider,
    "token": StaticTokenProvider,
}


def load_providers(config):
    output = {}
    for entry in provider_entries(config):
        provider = PROVIDERS[entry["plugin"]](entry)
        output[provider.name] = provider
    return output
