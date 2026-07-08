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

When ``claudeAiOauth.expiresAt`` is within the configured refresh margin, the
provider refreshes with the broker-owned refresh token and persists rotated
credential state before vending files or injection headers. Runtime bootstrap,
agentd, and egressd stay generic.
"""

import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from broker.core.config import env_value, fail, injection_hosts, list_value, string_value
from broker.plugins.github_app.provider import ProviderError
from broker.plugins.placeholder_file import (
    far_future_exp,
    render_plain,
    validate_relative_path,
)


DEFAULT_FILE_NAME = ".credentials.json"
DEFAULT_TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
DEFAULT_REFRESH_MARGIN_SECONDS = 600
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
        self.token_url = string_value(self.config.get("token-url") or DEFAULT_TOKEN_URL, f"provider {self.name} config.token-url", required=True)
        parsed = urlparse(self.token_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            fail(f"provider {self.name} config.token-url must be an http(s) URL")
        self.client_id = self._provider_value("client-id", required=False)
        self.refresh_margin_seconds = self._int_config("refresh-margin-seconds", DEFAULT_REFRESH_MARGIN_SECONDS)
        self.bundle_ttl_seconds = self._int_config("bundle-ttl-seconds", DEFAULT_BUNDLE_TTL_SECONDS)
        self.files_refresh_margin_seconds = max(self.refresh_margin_seconds, self.bundle_ttl_seconds)
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

    def _provider_value(self, key, default=None, required=True):
        value = self.config.get(key)
        env_key = f"{key}-env"
        env_name = self.config.get(env_key)
        if value is not None and env_name is not None:
            fail(f"provider {self.name} cannot set both {key} and {env_key}")
        if value is not None:
            if isinstance(value, int):
                return str(value)
            if isinstance(value, str) and value:
                return value
            fail(f"provider {self.name} {key} must be a non-empty string or integer")
        if isinstance(env_name, str):
            value = env_value(env_name)
            if not value:
                fail(f"environment variable {env_name} must not be empty")
            return value
        if default is not None:
            return default
        if required:
            fail(f"provider {self.name} requires {key} or {env_key}")
        return None

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

    def _refresh_token(self, oauth):
        token = oauth.get("refreshToken")
        if not isinstance(token, str) or not token:
            raise ProviderError("credentials-invalid", "Claude credentials missing claudeAiOauth.refreshToken", 502)
        return token

    def _expiry_seconds(self, oauth):
        exp_ms = oauth.get("expiresAt")
        if not isinstance(exp_ms, (int, float)) or isinstance(exp_ms, bool):
            return None
        return int(exp_ms // 1000)

    def _expiry_rfc3339(self, oauth):
        # claudeAiOauth.expiresAt is a millisecond epoch. Surface it as the
        # injection/bundle expiry ceiling; a missing/invalid value means no
        # provider-side expiry (the broker still caps file bundles by TTL).
        exp = self._expiry_seconds(oauth)
        if exp is None:
            return None
        return rfc3339(exp)

    def _fresh_credentials(self, agent_id, audit, request_id, operation_prefix, refresh_margin_seconds=None):
        data, oauth = self._read_credentials()
        access_token = self._access_token(oauth)
        self._refresh_token(oauth)
        exp = self._expiry_seconds(oauth)
        if exp is None:
            return data, oauth, access_token, None, False

        now = int(time.time())
        if refresh_margin_seconds is None:
            refresh_margin_seconds = self.refresh_margin_seconds
        if exp - now > refresh_margin_seconds:
            return data, oauth, access_token, exp, False

        try:
            refreshed_data = self._refresh(data, oauth)
            self._write_credentials(refreshed_data)
            refreshed_oauth = refreshed_data["claudeAiOauth"]
            refreshed_access_token = self._access_token(refreshed_oauth)
            refreshed_exp = self._expiry_seconds(refreshed_oauth)
            audit.write(
                request_id=request_id,
                agent=agent_id,
                provider=self.name,
                operation=f"{operation_prefix}.refresh",
                allowed=True,
                expires_at=rfc3339(refreshed_exp) if refreshed_exp is not None else None,
            )
            return refreshed_data, refreshed_oauth, refreshed_access_token, refreshed_exp, True
        except ProviderError as error:
            if error.reason in {"credentials-source-not-writable", "token-refresh-not-configured"}:
                raise
            if exp <= now:
                raise
            print(f"claude-oauth provider {self.name}: refresh failed; serving current valid access token", flush=True)
            return data, oauth, access_token, exp, False

    def _refresh(self, data, oauth):
        if not self.client_id:
            raise ProviderError(
                "token-refresh-not-configured",
                f"Claude provider {self.name} requires client-id or client-id-env before OAuth refresh",
                502,
            )
        if self.credentials_file is None:
            raise ProviderError(
                "credentials-source-not-writable",
                "Claude credentials-env cannot persist refreshed or rotated OAuth tokens",
                502,
            )
        refresh_token = self._refresh_token(oauth)
        body = urlencode({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
        }).encode("utf-8")
        request = Request(
            self.token_url,
            method="POST",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            error.read()
            raise ProviderError("token-refresh-failed", f"Claude token refresh failed: HTTP {error.code}", 502) from error
        except URLError as error:
            raise ProviderError("token-refresh-failed", "Claude token refresh failed: upstream unreachable", 502) from error
        except json.JSONDecodeError as error:
            raise ProviderError("token-refresh-failed", "Claude token refresh response was not valid JSON", 502) from error
        if not isinstance(payload, dict):
            raise ProviderError("token-refresh-failed", "Claude token refresh response was not an object", 502)
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ProviderError("token-refresh-failed", "Claude token refresh response missing access_token", 502)

        updated = json.loads(json.dumps(data))
        updated_oauth = updated["claudeAiOauth"]
        updated_oauth["accessToken"] = access_token
        refresh_token = payload.get("refresh_token")
        if isinstance(refresh_token, str) and refresh_token:
            updated_oauth["refreshToken"] = refresh_token

        expires_at_ms = self._payload_expires_at_ms(payload)
        if expires_at_ms is None:
            raise ProviderError("token-refresh-failed", "Claude token refresh response missing expires_in", 502)
        updated_oauth["expiresAt"] = expires_at_ms

        scope = payload.get("scope")
        if isinstance(scope, str) and scope:
            updated_oauth["scopes"] = scope.split()
        updated["last_refresh"] = datetime.now(timezone.utc).isoformat()
        return updated

    def _payload_expires_at_ms(self, payload):
        expires_in = payload.get("expires_in")
        if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool) and expires_in > 0:
            return int((time.time() + expires_in) * 1000)
        expires_at = payload.get("expires_at")
        if isinstance(expires_at, (int, float)) and not isinstance(expires_at, bool):
            if expires_at > 10_000_000_000:
                return int(expires_at)
            if expires_at > 0:
                return int(expires_at * 1000)
        return None

    def _write_credentials(self, data):
        if self.credentials_file is None:
            raise ProviderError(
                "credentials-source-not-writable",
                "Claude credentials-env cannot persist refreshed or rotated OAuth tokens",
                502,
            )
        self.credentials_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            mode = self.credentials_file.stat().st_mode & 0o777
        except FileNotFoundError:
            mode = 0o600
        temporary = self.credentials_file.with_name(f".{self.credentials_file.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            with temporary.open("w", encoding="utf-8") as file:
                json.dump(data, file, indent=2)
                file.write("\n")
            temporary.chmod(mode)
            os.replace(temporary, self.credentials_file)
        finally:
            temporary.unlink(missing_ok=True)

    # --- direct / file-bundle mode ------------------------------------------

    def files(self, agent_id, audit, request_id):
        # Insecure dev/fallback path: the agent receives the real credential
        # (access + refresh token). Mediated mode is the zero-possession path.
        with self.lock:
            data, oauth, _access_token, _exp, refreshed = self._fresh_credentials(
                agent_id,
                audit,
                request_id,
                "files",
                self.files_refresh_margin_seconds,
            )
            expires_at = self._expiry_rfc3339(oauth)
        content = json.dumps(data, indent=2) + "\n"
        files = [{"name": self.file_name, "content": content, "mode": "0600"}]
        return files, expires_at, {"access_token_expires_at": expires_at, "refreshed": refreshed}

    # --- mediated placeholder mode ------------------------------------------

    def placeholder_files(self, agent_id, audit, request_id, grant=None):
        if self.placeholder is None:
            raise ProviderError("placeholder-files-not-configured", f"provider {self.name} has no placeholder-file config", 403)
        with self.lock:
            # Read (and validate) the real credential so custody is proven and a
            # missing/broken broker credential fails loudly — but the real
            # accessToken/refreshToken are NEVER emitted into the file.
            _data, oauth, _access_token, _exp, _refreshed = self._fresh_credentials(
                agent_id,
                audit,
                request_id,
                "placeholder",
            )
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
            _data, oauth, access_token, _exp, _refreshed = self._fresh_credentials(
                agent_id,
                audit,
                request_id,
                "injection",
            )
            expires_at = self._expiry_rfc3339(oauth)
        headers = {"authorization": f"Bearer {access_token}"}
        headers.update(self.injection_extra_headers)
        # Every injected name is stripped from the incoming request so the
        # agent's placeholder version is removed before injection.
        strip = list(headers.keys())
        return headers, expires_at, strip


def rfc3339(exp):
    return datetime.fromtimestamp(exp, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
