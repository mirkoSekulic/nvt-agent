from abc import ABC, abstractmethod


class ProviderAdapter(ABC):
    """Complete core-owned provider lifecycle and operation boundary."""

    @property
    @abstractmethod
    def name(self): ...

    @property
    @abstractmethod
    def ready(self): ...

    @property
    @abstractmethod
    def external(self): ...

    @abstractmethod
    def close(self): ...

    @abstractmethod
    def validate_state(self): ...

    @abstractmethod
    def supports(self, capability): ...

    @property
    @abstractmethod
    def injection_hosts(self): ...

    @property
    @abstractmethod
    def injection_git(self): ...

    @property
    @abstractmethod
    def bundle_ttl_seconds(self): ...

    @abstractmethod
    def http_request(self, method, url, headers, paginate, effective_repositories): ...

    @abstractmethod
    def normalize_target(self, target): ...

    @abstractmethod
    def target_from_repo(self, repo): ...

    @abstractmethod
    def token_for_repo(self, repo, effective_repositories): ...

    @abstractmethod
    def identity_for_repo(self, repo, effective_repositories): ...

    @abstractmethod
    def headers_for_repo(self, repo, effective_repositories): ...

    @abstractmethod
    def files(self, agent_id, audit, request_id): ...

    @abstractmethod
    def placeholder_files(self, agent_id, audit, request_id, grant): ...

    @abstractmethod
    def injection_headers(self, host, method, path, agent_id, audit, request_id, grant): ...
