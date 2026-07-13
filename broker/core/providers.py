from abc import ABC, abstractmethod

from broker.core.config import provider_entries
from broker.plugins import BUILTIN_PROVIDERS


class ProviderAdapter(ABC):
    """Core-owned boundary consumed by Broker."""

    @property
    @abstractmethod
    def name(self):
        raise NotImplementedError

    @abstractmethod
    def supports(self, capability):
        raise NotImplementedError

    @property
    @abstractmethod
    def injection_hosts(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def injection_git(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def bundle_ttl_seconds(self):
        raise NotImplementedError

    @abstractmethod
    def http_request(self, method, url, headers, paginate, effective_repositories):
        raise NotImplementedError

    @abstractmethod
    def normalize_target(self, target):
        raise NotImplementedError

    @abstractmethod
    def target_from_repo(self, repo):
        raise NotImplementedError

    @abstractmethod
    def token_for_repo(self, repo, effective_repositories):
        raise NotImplementedError

    @abstractmethod
    def identity_for_repo(self, repo, effective_repositories):
        raise NotImplementedError

    @abstractmethod
    def headers_for_repo(self, repo, effective_repositories):
        raise NotImplementedError

    @abstractmethod
    def files(self, agent_id, audit, request_id):
        raise NotImplementedError

    @abstractmethod
    def placeholder_files(self, agent_id, audit, request_id, grant):
        raise NotImplementedError

    @abstractmethod
    def injection_headers(self, host, method, path, agent_id, audit, request_id, grant):
        raise NotImplementedError


class InProcessProviderAdapter(ProviderAdapter):
    """Adapter for the existing in-process Python provider implementations."""

    def __init__(self, provider):
        self._provider = provider
        self._name = provider.name
        self._injection_hosts = getattr(provider, "injection_hosts", None) or []
        self._injection_git = bool(getattr(provider, "injection_git", False))
        self._bundle_ttl_seconds = getattr(provider, "bundle_ttl_seconds", None)
        self._capabilities = {
            "files": callable(getattr(provider, "files", None)),
            "placeholder-files": callable(getattr(provider, "placeholder_files", None)),
            "injection": bool(self._injection_hosts) and callable(getattr(provider, "injection_headers", None)),
        }

    @property
    def name(self):
        return self._name

    @property
    def injection_hosts(self):
        return self._injection_hosts

    @property
    def injection_git(self):
        return self._injection_git

    @property
    def bundle_ttl_seconds(self):
        return self._bundle_ttl_seconds

    def supports(self, capability):
        return self._capabilities.get(capability, False)

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

    def headers_for_repo(self, repo, effective_repositories):
        return self._provider.headers_for_repo(repo, effective_repositories)

    def files(self, agent_id, audit, request_id):
        return self._provider.files(agent_id, audit, request_id)

    def placeholder_files(self, agent_id, audit, request_id, grant):
        return self._provider.placeholder_files(agent_id, audit, request_id, grant)

    def injection_headers(self, host, method, path, agent_id, audit, request_id, grant):
        return self._provider.injection_headers(host, method, path, agent_id, audit, request_id, grant)


def load_providers(config):
    output = {}
    for entry in provider_entries(config, BUILTIN_PROVIDERS):
        provider = BUILTIN_PROVIDERS[entry["plugin"]](entry)
        adapter = InProcessProviderAdapter(provider)
        output[adapter.name] = adapter
    return output
