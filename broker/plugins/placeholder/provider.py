"""Generic placeholder-file provider.

Materializes a syntactically valid auth/config file containing only inert
placeholders. Real secret values are read from the environment (broker/provider
custody) and held broker-side; they are never emitted into the file the agent
receives. This is the provider-agnostic mechanism behind the `placeholder-file`
materialization mode; provider-specific presets (e.g. Codex) build the same
shapes with their own field layout.
"""

import json

from broker.core.config import env_value, fail, list_value, string_value
from broker.plugins.github_app.provider import ProviderError
from broker.plugins.placeholder_file import (
    far_future_exp,
    render_jwt,
    render_plain,
    validate_mode,
    validate_relative_path,
)


class PlaceholderProvider:
    def __init__(self, entry):
        self.entry = entry
        self.name = string_value(entry.get("name"), "provider.name", required=True)
        self.config = entry.get("config") or {}
        if not isinstance(self.config, dict):
            fail(f"provider {self.name} config must be a YAML object")
        file_config = self.config.get("file")
        if not isinstance(file_config, dict):
            fail(f"provider {self.name} config.file must be a YAML object")
        self.file_path = validate_relative_path(
            file_config.get("path"), f"provider {self.name} config.file.path"
        )
        self.file_mode = self._file_mode(file_config.get("mode"))
        self.hosts = self._hosts()
        self.fields = self._fields()

    def _file_mode(self, mode):
        if mode is None:
            return "0600"
        return validate_mode(mode, f"provider {self.name} config.file.mode")

    def _hosts(self):
        hosts = []
        for index, host in enumerate(list_value(self.config.get("hosts"), f"provider {self.name} config.hosts")):
            if not isinstance(host, str) or not host:
                fail(f"provider {self.name} config.hosts[{index}] must be a non-empty string")
            hosts.append(host)
        return hosts

    def _fields(self):
        raw = self.config.get("fields")
        if not isinstance(raw, dict) or not raw:
            fail(f"provider {self.name} config.fields must be a non-empty YAML object")
        fields = {}
        for key, spec in raw.items():
            if not isinstance(key, str) or not key:
                fail(f"provider {self.name} config.fields keys must be non-empty strings")
            # Fail closed on ambiguity: any object field MUST be a well-formed
            # secret spec (naming a secret-env). A mis-keyed secret field must
            # never silently degrade into a literal object emitted verbatim.
            # Only scalar values are literals (emitted as-is; non-secret).
            if isinstance(spec, dict):
                fields[key] = self._secret_field(key, spec)
            elif isinstance(spec, (list,)):
                fail(f"provider {self.name} config.fields.{key} must be a scalar literal or a secret spec object")
            else:
                fields[key] = {"kind": "literal", "value": spec}
        return fields

    def _secret_field(self, key, spec):
        shape = spec.get("shape", "plain")
        if shape not in ("plain", "jwt"):
            fail(f"provider {self.name} config.fields.{key}.shape must be plain or jwt")
        secret_env = string_value(spec.get("secret-env"), f"provider {self.name} config.fields.{key}.secret-env", required=True)
        # Read the real value so it is proven to be held broker-side, and fail
        # loudly if it is missing — but it is NEVER emitted into the file.
        real = env_value(secret_env)
        if not real:
            fail(f"environment variable {secret_env} must not be empty")
        claims = spec.get("claims")
        if claims is None:
            claims = {}
        if not isinstance(claims, dict):
            fail(f"provider {self.name} config.fields.{key}.claims must be a YAML object")
        if shape != "jwt" and spec.get("claims") is not None:
            fail(f"provider {self.name} config.fields.{key}.claims is only valid for shape jwt")
        return {"kind": "secret", "shape": shape, "claims": claims}

    def placeholder_files(self, agent_id, audit, request_id, grant=None):
        content_object = {}
        for key, field in self.fields.items():
            if field["kind"] == "literal":
                content_object[key] = field["value"]
            elif field["shape"] == "jwt":
                content_object[key] = render_jwt(field["claims"], far_future_exp())
            else:
                content_object[key] = render_plain()
        files = [{
            "path": self.file_path,
            "content": json.dumps(content_object, indent=2) + "\n",
            "mode": self.file_mode,
        }]
        # Placeholders do not expire; the real credential is refreshed
        # broker-side and injected at the edge.
        return files, list(self.hosts), None

    # The generic placeholder provider materializes files only; it does not
    # serve secret-bearing endpoints. Guard against accidental use.
    def token_for_repo(self, repo, effective_repositories):
        raise ProviderError("token-not-supported", f"provider {self.name} is placeholder-file only")

    def headers_for_repo(self, repo, effective_repositories):
        raise ProviderError("headers-not-supported", f"provider {self.name} is placeholder-file only")

    def files(self, agent_id, audit, request_id):
        raise ProviderError("files-not-supported", f"provider {self.name} does not vend real file bundles; use placeholder-file")
