import json
import os
import re
import shlex
from pathlib import Path
from urllib.parse import unquote, urlsplit


class PluginEgressError(ValueError):
    pass


_PROVIDER_RE = re.compile(r"^[!-~]{1,128}$")
_HTTPS_PROXY_NAMES = ("HTTPS_PROXY", "https_proxy")
_PLAIN_PROXY_NAMES = ("HTTP_PROXY", "ALL_PROXY", "http_proxy", "all_proxy")
_LOCAL_NO_PROXY = "localhost,127.0.0.1,::1"


def _runtime_value(name, env, home):
    value = env.get(name)
    if value is not None:
        return value
    path = Path(home) / ".nvt-agent" / "env"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    prefix = f"{name}="
    for line in lines:
        candidate = line.strip()
        if candidate.startswith("export "):
            candidate = candidate[7:]
        if not candidate.startswith(prefix):
            continue
        try:
            fields = shlex.split(candidate, posix=True)
        except ValueError:
            raise PluginEgressError("runtime egress environment is malformed")
        if len(fields) != 1:
            raise PluginEgressError("runtime egress environment is malformed")
        key, separator, parsed = fields[0].partition("=")
        if key == name and separator:
            return parsed
    return None


def _provider_suffix(provider):
    suffix = re.sub(r"[^A-Za-z0-9]+", "_", provider).strip("_").upper()
    if not suffix:
        raise PluginEgressError("plugin.egress.provider cannot be mapped to a provider-scoped proxy")
    return suffix


def provider(plugin):
    raw = plugin.get("egress")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise PluginEgressError("plugin.egress must be a YAML object")
    unknown = sorted(set(raw) - {"provider"})
    if unknown:
        raise PluginEgressError(f"plugin.egress contains unsupported field: {unknown[0]}")
    value = raw.get("provider")
    if not isinstance(value, str) or not _PROVIDER_RE.fullmatch(value):
        raise PluginEgressError("plugin.egress.provider must be a bounded printable provider name")
    return value


def _metadata(state_dir):
    path = Path(state_dir) / "egress.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise PluginEgressError("mediated plugin egress metadata is unavailable")
    if not isinstance(value, dict) or value.get("mode") != "mediated":
        raise PluginEgressError("mediated plugin egress metadata is invalid")
    transport = value.get("transport")
    if transport not in {"forward-proxy", "transparent"}:
        raise PluginEgressError("plugin.egress.provider requires mediated proxy transport")
    grants = value.get("grants")
    if not isinstance(grants, list):
        raise PluginEgressError("mediated plugin egress grants are invalid")
    return transport, grants


def environment(plugin, base_env=None):
    selected = provider(plugin)
    env = dict(os.environ if base_env is None else base_env)
    if selected is None:
        return env
    if env.get("NVT_EGRESS_MODE", "").strip().lower() != "mediated":
        return env

    home = env.get("HOME", str(Path.home()))
    state_dir = env.get("NVT_STATE_DIR", str(Path(home) / ".nvt-agent"))
    transport, grants = _metadata(state_dir)
    matches = [
        grant for grant in grants
        if isinstance(grant, dict)
        and grant.get("provider") == selected
        and grant.get("materialization") in {"header-inject", "placeholder-file"}
    ]
    if len(matches) != 1:
        raise PluginEgressError("plugin.egress.provider is not an exact injection-eligible mediated grant")

    # This identity belongs only to trusted egress infrastructure. It is not
    # expected in an agent environment, but never propagate it across a plugin
    # launch boundary if an embedding accidentally supplied it.
    env.pop("NVT_EGRESS_BROKER_TOKEN", None)

    name = "NVT_EGRESS_FORWARD_PROXY_URL_" + _provider_suffix(selected)
    proxy_url = _runtime_value(name, env, home)
    if not proxy_url:
        raise PluginEgressError("provider-scoped mediated proxy is unavailable")
    parts = urlsplit(proxy_url)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.query or parts.fragment:
        raise PluginEgressError("provider-scoped mediated proxy is invalid")
    if unquote(parts.username or "") != selected:
        raise PluginEgressError("provider-scoped mediated proxy does not match plugin.egress.provider")
    if parts.password not in {None, "", "x"}:
        raise PluginEgressError("provider-scoped mediated proxy contains unexpected userinfo")

    # The provider-scoped listener supports HTTPS CONNECT only. Keep plain HTTP
    # out of that listener rather than implying an authentication policy for
    # cleartext requests.
    for name in _PLAIN_PROXY_NAMES:
        env.pop(name, None)
    for name in _HTTPS_PROXY_NAMES:
        env[name] = proxy_url
    env["NVT_PLUGIN_EGRESS_PROVIDER"] = selected
    env["NO_PROXY"] = _LOCAL_NO_PROXY
    env["no_proxy"] = _LOCAL_NO_PROXY
    return env
