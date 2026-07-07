import fnmatch
import re

from broker.core.config import env_value, fail, injection_hosts, list_value, string_value
from broker.plugins.github_app.provider import ProviderError
from broker.plugins.static_target import normalize_target, target_mode


# The zero-entropy placeholder from protocol/injection.md. No injected header
# value may collide with it (that would defeat the whole non-possession point).
INJECTION_PLACEHOLDER = "NVT-PLACEHOLDER-NOT-A-KEY"

# RFC 7230 header field-name token, lowercased.
_HEADER_NAME_RE = re.compile(r"^[a-z0-9!#$%&'*+.^_`|~-]+$")


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
        # Generalized injection so this one provider covers Bearer APIs and
        # key-header APIs (e.g. Anthropic's x-api-key) with no egressd change
        # (docs/phase5-6b-observability-pr-plan.md decision 4).
        self.injection_header = self._injection_header()
        self.injection_scheme = self._injection_scheme()
        self.injection_extra_headers = self._injection_extra_headers()

    def _injection_header(self):
        raw = self.config.get("injection-header")
        if raw is None:
            return "authorization"
        header = string_value(raw, f"provider {self.name} config.injection-header")
        return self._normalize_header_name(header, "injection-header")

    def _injection_scheme(self):
        raw = self.config.get("injection-scheme")
        if raw is None:
            return "Bearer"
        # An explicit empty string means "inject the raw token" (x-api-key).
        if not isinstance(raw, str):
            fail(f"provider {self.name} config.injection-scheme must be a string")
        return raw

    def _injection_extra_headers(self):
        raw = self.config.get("injection-extra-headers")
        if raw is None:
            return {}
        if not isinstance(raw, dict):
            fail(f"provider {self.name} config.injection-extra-headers must be a YAML object")
        headers = {}
        for key, value in raw.items():
            name = self._normalize_header_name(
                string_value(key, f"provider {self.name} config.injection-extra-headers key"),
                "injection-extra-headers",
            )
            if name == self.injection_header:
                fail(f"provider {self.name} config.injection-extra-headers duplicates {name}")
            if not isinstance(value, str) or not value:
                fail(f"provider {self.name} config.injection-extra-headers[{name}] must be a non-empty string")
            if INJECTION_PLACEHOLDER in value:
                fail(f"provider {self.name} config.injection-extra-headers[{name}] must not contain the injection placeholder")
            headers[name] = value
        return headers

    def _normalize_header_name(self, value, field):
        name = value.strip().lower()
        if not _HEADER_NAME_RE.match(name):
            fail(f"provider {self.name} config.{field} {value!r} is not a valid header name")
        return name

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
        value = f"{self.injection_scheme} {self.token}" if self.injection_scheme else self.token
        headers = {self.injection_header: value}
        headers.update(self.injection_extra_headers)
        # Every injected name is stripped from the incoming request so the
        # agent's placeholder version is removed before injection.
        strip = list(headers.keys())
        return headers, None, strip
