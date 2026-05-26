from broker.plugins.github_app.provider import GithubAppProvider
from broker.core.config import provider_entries


def load_providers(config):
    output = {}
    for entry in provider_entries(config):
        provider = GithubAppProvider(entry)
        output[provider.name] = provider
    return output
