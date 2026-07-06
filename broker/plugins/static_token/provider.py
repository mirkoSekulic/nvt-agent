import fnmatch

from broker.core.config import env_value, fail, injection_hosts, list_value, string_value
from broker.plugins.github_app.provider import ProviderError
from broker.plugins.static_target import normalize_target, target_mode


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
        self.target_mode = target_mode(self.config, self.name)
        self.allowed_repositories = self._allowed_strings("repositories")
        self.token = self._token()
        self.injection_hosts = injection_hosts(self.config, self.name)

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

    def normalize_target(self, target):
        return normalize_target(target, self.target_mode)

    def target_from_repo(self, repo):
        if self.target_mode == "github":
            return f"github.com/{repo}"
        return repo

    def headers_for_repo(self, repo, effective_repositories):
        raise ProviderError("headers-not-supported", f"provider {self.name} does not support headers")

    def identity_for_repo(self, repo, effective_repositories):
        raise ProviderError("identity-not-supported", f"provider {self.name} does not support commit identity; use identity.mode=explicit")

    def injection_headers(self, host, method, path, agent_id, audit, request_id, grant=None):
        return {"authorization": f"Bearer {self.token}"}, None, ["authorization"]
