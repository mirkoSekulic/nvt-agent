from broker.core.config import provider_entries, provider_plugin_entries
from broker.core.errors import ProviderError
from broker.core.executable_provider import ExecutableProviderAdapter
from broker.core.provider_adapter import ProviderAdapter
from broker.plugins.registry import BUILTIN_PROVIDERS


class InProcessProviderAdapter(ProviderAdapter):
    """Adapter for the existing in-process Python provider implementations."""

    def __init__(self, provider):
        self._provider = provider
        self._name = provider.name

    @property
    def ready(self):
        return True

    @property
    def external(self):
        return False

    def close(self):
        return None

    def validate_state(self):
        validate = getattr(self._provider, "validate_state", None)
        if callable(validate):
            validate()
        return True

    @property
    def name(self):
        return self._name

    @property
    def injection_hosts(self):
        return getattr(self._provider, "injection_hosts", None) or []

    @property
    def injection_git(self):
        return getattr(self._provider, "injection_git", False)

    @property
    def bundle_ttl_seconds(self):
        return getattr(self._provider, "bundle_ttl_seconds", None)

    def supports(self, capability):
        if capability == "files":
            return hasattr(self._provider, "files")
        if capability == "placeholder-files":
            return hasattr(self._provider, "placeholder_files")
        if capability == "injection":
            return bool(self.injection_hosts) and callable(getattr(self._provider, "injection_headers", None))
        return False

    def http_request(self, method, url, headers, paginate, effective_repositories):
        return self._provider.http_request(method, url, headers, paginate, effective_repositories)

    def normalize_target(self, target):
        return self._provider.normalize_target(target)

    def target_from_repo(self, repo):
        return self._provider.target_from_repo(repo)

    def token_for_repo(self, repo, effective_repositories):
        return self._provider.token_for_repo(repo, effective_repositories)

    def identity_for_repo(self, repo, effective_repositories):
        return self._provider.identity_for_repo(repo, effective_repositories)

    def identity_for_grant(self, effective_repositories):
        operation = getattr(self._provider, "identity_for_grant", None)
        if not callable(operation):
            raise ProviderError("identity-not-supported")
        return operation(effective_repositories)

    def headers_for_repo(self, repo, effective_repositories):
        return self._provider.headers_for_repo(repo, effective_repositories)

    def files(self, agent_id, audit, request_id):
        return self._provider.files(agent_id, audit, request_id)

    def placeholder_files(self, agent_id, audit, request_id, grant):
        return self._provider.placeholder_files(agent_id, audit, request_id, grant)

    def injection_headers(self, host, method, path, agent_id, audit, request_id, grant):
        result = self._provider.injection_headers(host, method, path, agent_id, audit, request_id, grant)
        if len(result) == 3:
            headers, expires_at, strip = result
            return headers, expires_at, strip, {}
        return result


def load_providers(config) -> dict[str, ProviderAdapter]:
    output: dict[str, ProviderAdapter] = {}
    external_plugins = provider_plugin_entries(config, BUILTIN_PROVIDERS)
    supported = set(BUILTIN_PROVIDERS) | set(external_plugins)
    try:
        for entry in provider_entries(config, supported):
            plugin_name = entry["plugin"]
            if plugin_name in BUILTIN_PROVIDERS:
                provider = BUILTIN_PROVIDERS[plugin_name](entry)
                adapter = InProcessProviderAdapter(provider)
            else:
                adapter = ExecutableProviderAdapter(entry, external_plugins[plugin_name])
            output[adapter.name] = adapter
    except Exception:
        for adapter in output.values():
            adapter.close()
        raise
    return output
