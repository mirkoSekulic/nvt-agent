from urllib.parse import urlparse

from broker.core.config import fail, string_value
from broker.plugins.github_app.provider import ProviderError, github_repo_from_target


def target_mode(config, provider_name):
    mode = string_value(config.get("target-mode"), f"provider {provider_name} config.target-mode") or "github"
    if mode not in {"github", "literal"}:
        fail(f"provider {provider_name} config.target-mode must be github or literal")
    return mode


def normalize_target(target, mode):
    if mode == "github":
        return github_repo_from_target(target)
    return literal_target(target)


def literal_target(target):
    value = target.strip().removesuffix(".git").strip("/")
    if not value:
        raise ProviderError("target-invalid")
    if value.startswith(("https://", "http://")):
        parsed = urlparse(value)
        value = f"{parsed.hostname or ''}{parsed.path}".strip("/").removesuffix(".git")
    elif "@" in value and ":" in value and "://" not in value:
        user_host, path = value.split(":", 1)
        host = user_host.rsplit("@", 1)[-1]
        value = f"{host}/{path}".strip("/").removesuffix(".git")
    if not value or "/" not in value:
        raise ProviderError("target-invalid")
    if any(part in {".", ".."} or not part for part in value.split("/")):
        raise ProviderError("target-invalid")
    return value
