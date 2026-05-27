import fnmatch

from broker.core.config import env_value, fail, list_value, string_value
from broker.plugins.github_app.provider import ProviderError


class StaticTokenProvider:
    def __init__(self, entry):
        self.entry = entry
        self.name = string_value(entry.get("name"), "provider.name", required=True)
        self.config = entry.get("config") or {}
        if not isinstance(self.config, dict):
            fail(f"provider {self.name} config must be a YAML object")
        self.allow = entry.get("allow") or {}
        if not isinstance(self.allow, dict):
            fail(f"provider {self.name} allow must be a YAML object")
        self.allowed_repositories = self._allowed_strings("repositories")
        self.token = self._token()

    def _allowed_strings(self, key):
        values = list_value(self.allow.get(key), f"provider {self.name} allow.{key}")
        output = []
        for index, value in enumerate(values):
            if not isinstance(value, str) or not value:
                fail(f"provider {self.name} allow.{key}[{index}] must be a non-empty string")
            output.append(value)
        return output

    def _token(self):
        token_env = string_value(self.config.get("token-env"), f"provider {self.name} config.token-env", required=True)
        value = env_value(token_env)
        if not value:
            fail(f"environment variable {token_env} must not be empty")
        return value

    def _ensure_repo_allowed(self, repo, effective_repositories):
        if not self.allowed_repositories:
            raise ProviderError("repo-not-allowed", "provider has no allowed repositories")
        if not any(fnmatch.fnmatchcase(repo, pattern) for pattern in self.allowed_repositories):
            raise ProviderError("repo-not-allowed")
        if effective_repositories is None:
            raise ProviderError("repo-not-allowed", "agent grant scope is required")
        if not effective_repositories:
            raise ProviderError("repo-not-allowed")
        for pattern in effective_repositories:
            if fnmatch.fnmatchcase(repo, pattern):
                return
        raise ProviderError("repo-not-allowed")

    def token_for_repo(self, repo, effective_repositories):
        self._ensure_repo_allowed(repo, effective_repositories)
        return self.token, None

    def headers_for_repo(self, repo, effective_repositories):
        raise ProviderError("headers-not-supported", f"provider {self.name} does not support headers")

    def identity_for_repo(self, repo, effective_repositories):
        raise ProviderError("identity-not-supported", f"provider {self.name} does not support commit identity; use identity.mode=explicit")
