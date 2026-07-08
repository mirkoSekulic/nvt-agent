"""Claude Code OAuth provider.

Broker-owned custody of the Claude Code subscription OAuth credential
(`~/.claude/.credentials.json`, a `{"claudeAiOauth": {...}}` object). It is the
Claude analogue of the Codex OAuth provider and supports the same three
materialization surfaces, so Claude Code can be driven the same way Codex is:

- ``files`` (``/v1/files``) — direct/file-bundle mode. Vends a usable
  ``.credentials.json`` into the agent. This is the insecure dev/fallback path
  where the agent holds the real credential (the ``file-bundle`` contract).
- ``placeholder_files`` (``/v1/placeholder-files``) — mediated mode. Vends a
  syntactically valid ``.credentials.json`` whose ``accessToken``/``refreshToken``
  are inert placeholders and whose ``expiresAt`` is far-future, so Claude Code
  starts without ever holding real credential bytes. Non-secret subscription
  metadata (``scopes``/``subscriptionType``/``rateLimitTier``) is copied through,
  guarded so a token-shaped value is refused rather than smuggled out.
- ``injection_headers`` (``/v1/injection/headers``) — edge injection. Returns
  ``authorization: Bearer <access token>`` (plus any configured static extra
  headers) for the paired egress identity only. The real token never reaches
  the agent.

The Claude-specific file shape lives entirely inside this provider. Runtime
bootstrap, agentd, and egressd stay generic: bootstrap materializes the
placeholder file by its returned ``path``, and egressd injects the returned
headers with no Claude-specific logic.

This provider does not refresh the broker-side OAuth token over the network in
this revision (see ``protocol/broker.md`` "Claude OAuth Provider Rules" for the
documented proof gap). It reads current credential state and surfaces the real
``expiresAt`` as the injection/bundle expiry ceiling; keeping the broker-side
credential fresh is out of scope here.
"""

import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from broker.core.config import fail, injection_hosts, list_value, string_value
from broker.plugins.github_app.provider import ProviderError
from broker.plugins.placeholder_file import (
    far_future_exp,
    render_plain,
    validate_relative_path,
)


DEFAULT_FILE_NAME = ".credentials.json"
DEFAULT_BUNDLE_TTL_SECONDS = 1200

# Non-secret subscription metadata copied into the placeholder file is
# operator-trusted identity, but as defense in depth a copied value that looks
# credential-shaped (too long, or a JWT-like dotted blob) is refused rather than
# smuggled into the placeholder. Mirrors the Codex placeholder claim guard.
MAX_NONSECRET_LEN = 128

# The non-secret fields of claudeAiOauth. Everything else in the object
# (accessToken, refreshToken, and any future secret field) is treated as secret
# and never copied into the placeholder file.
NONSECRET_FIELDS = ("scopes", "subscriptionType", "rateLimitTier")

# RFC 7230 header field-name token, lowercased.
_HEADER_NAME_RE = re.compile(r"^[a-z0-9!#$%&'*+.^_`|~-]+$")

# The zero-entropy placeholder from protocol/injection.md. No injected header
# value may collide with it (that would defeat the non-possession point).
INJECTION_PLACEHOLDER = "NVT-PLACEHOLDER-NOT-A-KEY"


class ClaudeOAuthProvider:
    def __init__(self, entry):
        self.entry = entry
        self.name = string_value(entry.get("name"), "provider.name", required=True)
        self.config = entry.get("config") or {}
        if not isinstance(self.config, dict):
            fail(f"provider {self.name} config must be a YAML object")
        self.credentials_file, self.credentials_env = self._source()
        self.file_name = self._file_name()
        self.bundle_ttl_seconds = self._int_config("bundle-ttl-seconds", DEFAULT_BUNDLE_TTL_SECONDS)
        self.injection_hosts = injection_hosts(self.config, self.name)
        self.injection_extra_headers = self._injection_extra_headers()
        self.placeholder = self._placeholder_config()
        self.lock = threading.Lock()

    def _source(self):
        # Exactly one broker-side source of the Claude credentials. A host path
        # is one option, not a requirement of the contract: an env/secret is
        # equally valid so the runtime contract never mandates host paths.
        file_value = self.config.get("credentials-file")
        env_value_name = self.config.get("credentials-env")
        if (file_value is None) == (env_value_name is None):
            fail(f"provider {self.name} config must set exactly one of credentials-file or credentials-env")
        if file_value is not None:
            path = Path(string_value(file_value, f"provider {self.name} config.credentials-file", required=True))
            if not path.is_absolute():
                fail(f"provider {self.name} config.credentials-file must be an absolute path")
            return path, None
        env_name = string_value(env_value_name, f"provider {self.name} config.credentials-env", required=True)
        return None, env_name

    def _file_name(self):
        raw = self.config.get("file-name")
        if raw is None:
            return DEFAULT_FILE_NAME
        name = string_value(raw, f"provider {self.name} config.file-name", required=True)
        if "/" in name or "\\" in name or name == "." or ".." in name:
            fail(f"provider {self.name} config.file-name must be a plain relative filename")
        return name

    def _int_config(self, key, default):
        value = self.config.get(key, default)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            fail(f"provider {self.name} config.{key} must be a positive integer")
        return value

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
            if name == "authorization":
                fail(f"provider {self.name} config.injection-extra-headers must not override authorization")
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

    def _placeholder_config(self):
        raw = self.config.get("placeholder-file")
        if raw is None:
            return None
        if not isinstance(raw, dict):
            fail(f"provider {self.name} config.placeholder-file must be a YAML object")
        path = validate_relative_path(raw.get("path"), f"provider {self.name} config.placeholder-file.path")
        hosts = []
        for index, host in enumerate(list_value(raw.get("hosts"), f"provider {self.name} config.placeholder-file.hosts")):
            if not isinstance(host, str) or not host:
                fail(f"provider {self.name} config.placeholder-file.hosts[{index}] must be a non-empty string")
            # The placeholder file's host bindings must be a subset of the
            # provider's injection-hosts: every host the placeholder credential
            # is bound to must be one the edge can actually inject for.
            if host not in self.injection_hosts:
                fail(f"provider {self.name} config.placeholder-file.hosts[{index}] {host} must also be listed in injection-hosts")
            hosts.append(host)
        return {"path": path, "hosts": hosts}

    # --- credential reading (broker-side custody) ---------------------------

    def _read_raw(self):
        if self.credentials_file is not None:
            try:
                return self.credentials_file.read_text(encoding="utf-8")
            except FileNotFoundError as error:
                raise ProviderError("credentials-not-found", "Claude credentials file not found", 502) from error
            except (OSError, UnicodeDecodeError) as error:
                raise ProviderError("credentials-read-failed", "Claude credentials file could not be read", 502) from error
        value = os.environ.get(self.credentials_env)
        if not value:
            raise ProviderError("credentials-not-found", "Claude credentials env is empty", 502)
        return value

    def _read_credentials(self):
        raw = self._read_raw()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ProviderError("credentials-invalid", "Claude credentials are not valid JSON", 502) from error
        if not isinstance(data, dict):
            raise ProviderError("credentials-invalid", "Claude credentials must be a JSON object", 502)
        oauth = data.get("claudeAiOauth")
        if not isinstance(oauth, dict):
            raise ProviderError("credentials-invalid", "Claude credentials missing claudeAiOauth object", 502)
        return data, oauth

    def _access_token(self, oauth):
        token = oauth.get("accessToken")
        if not isinstance(token, str) or not token:
            raise ProviderError("credentials-invalid", "Claude credentials missing claudeAiOauth.accessToken", 502)
        return token

    def _expiry_rfc3339(self, oauth):
        # claudeAiOauth.expiresAt is a millisecond epoch. Surface it as the
        # injection/bundle expiry ceiling; a missing/invalid value means no
        # provider-side expiry (the broker still caps file bundles by TTL).
        exp_ms = oauth.get("expiresAt")
        if not isinstance(exp_ms, (int, float)) or isinstance(exp_ms, bool):
            return None
        return rfc3339(int(exp_ms // 1000))

    # --- direct / file-bundle mode ------------------------------------------

    def files(self, agent_id, audit, request_id):
        # Insecure dev/fallback path: the agent receives the real credential
        # (access + refresh token). Mediated mode is the zero-possession path.
        with self.lock:
            data, oauth = self._read_credentials()
            self._access_token(oauth)
            expires_at = self._expiry_rfc3339(oauth)
        content = json.dumps(data, indent=2) + "\n"
        files = [{"name": self.file_name, "content": content, "mode": "0600"}]
        return files, expires_at, {"access_token_expires_at": expires_at}

    # --- mediated placeholder mode ------------------------------------------

    def placeholder_files(self, agent_id, audit, request_id, grant=None):
        if self.placeholder is None:
            raise ProviderError("placeholder-files-not-configured", f"provider {self.name} has no placeholder-file config", 403)
        with self.lock:
            # Read (and validate) the real credential so custody is proven and a
            # missing/broken broker credential fails loudly — but the real
            # accessToken/refreshToken are NEVER emitted into the file.
            _data, oauth = self._read_credentials()
            self._access_token(oauth)
        placeholder_oauth = {
            "accessToken": render_plain(),
            "refreshToken": render_plain(),
            "expiresAt": far_future_exp() * 1000,
        }
        for field in NONSECRET_FIELDS:
            if field in oauth:
                placeholder_oauth[field] = self._guard_nonsecret(field, oauth[field])
        content = {"claudeAiOauth": placeholder_oauth}
        files = [{
            "path": self.placeholder["path"],
            "content": json.dumps(content, indent=2) + "\n",
            "mode": "0600",
        }]
        return files, list(self.placeholder["hosts"]), None

    def _guard_nonsecret(self, field, value):
        # A copied non-secret field is a scalar or a flat list of scalars.
        # Nested lists/dicts are refused so the token-shape guard always runs on
        # the actual leaf value and arbitrary nested content can never be copied
        # into the placeholder file if the credential shape ever changes.
        if isinstance(value, list):
            return [self._guard_scalar(field, item) for item in value]
        return self._guard_scalar(field, value)

    def _guard_scalar(self, field, value):
        if isinstance(value, bool) or isinstance(value, (int, float)):
            return value
        if isinstance(value, str):
            if len(value) > MAX_NONSECRET_LEN:
                raise ProviderError("placeholder-claim-unsafe", f"Claude placeholder field {field} value is too long to be non-secret", 502)
            if value.count(".") >= 2 and len(value) > 40:
                raise ProviderError("placeholder-claim-unsafe", f"Claude placeholder field {field} value looks token-shaped, refusing", 502)
            return value
        # Anything else (nested list/dict, None) is not a flat non-secret scalar.
        raise ProviderError("placeholder-claim-unsafe", f"Claude placeholder field {field} must be a scalar or a flat list of scalars, refusing", 502)

    # --- mediated edge injection --------------------------------------------

    def injection_headers(self, host, method, path, agent_id, audit, request_id, grant=None):
        with self.lock:
            _data, oauth = self._read_credentials()
            access_token = self._access_token(oauth)
            expires_at = self._expiry_rfc3339(oauth)
        headers = {"authorization": f"Bearer {access_token}"}
        headers.update(self.injection_extra_headers)
        # Every injected name is stripped from the incoming request so the
        # agent's placeholder version is removed before injection.
        strip = list(headers.keys())
        return headers, expires_at, strip


def rfc3339(exp):
    return datetime.fromtimestamp(exp, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
