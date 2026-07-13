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

Refresh: the broker keeps the broker-side access token fresh over the network
(an OAuth ``refresh_token`` exchange against ``token-url``, analogous to the
Codex flow). Claude credentials only expose ``expiresAt`` for the *access*
token. Newer Claude credentials may also carry ``refreshTokenExpiresAt``; the
broker preserves it and advances it when the token endpoint returns
``refresh_token_expires_in``. Access-token refresh remains proactive (before
``expiresAt`` minus a safety margin) rather than waiting for a 401. Refresh is
serialized: single-flight *within* the broker
process (a thread lock) and *across* processes (an advisory ``flock`` on a lock
file beside ``credentials-file``) so a second broker or the manual probe cannot
run a competing refresh-token exchange and invalidate the rotation. It is
rate-limit aware: on a transient upstream failure (HTTP 429/5xx) the sanitized
failure is cached for a cooldown so Claude Code retries cannot storm the OAuth
endpoint. A still-valid access token is served through a transient refresh
failure; on the mediated injection path an expired one fails closed, while the
direct ``/v1/files`` path still vends the (expired) real credential so Claude
Code — which possesses the refresh token in direct mode — can self-refresh.

Durability: network refresh requires a durable sink for the rotated credential,
so it is only performed for a ``credentials-file`` source. A ``credentials-env``
source cannot write a rotated credential back to an env var; refreshing it only
in memory would be lost on restart, after which the broker would reload the
now-stale (possibly already-rotated-away) env refresh token. So a
``credentials-env`` source never triggers a network refresh: a still-valid token
is served, an expired one fails closed on the mediated path. Token values never
appear in logs, errors, or audit — only the upstream HTTP status and a safe
OAuth error class are surfaced.
"""

import fcntl
import json
import os
import random
import re
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlparse

from broker.core.config import env_value, fail, injection_hosts, list_value, string_value
from broker.core.errors import ProviderError
from broker.plugins.placeholder_file import (
    far_future_exp,
    render_plain,
    validate_relative_path,
)


DEFAULT_FILE_NAME = ".credentials.json"
DEFAULT_BUNDLE_TTL_SECONDS = 1200
# Claude Code's public OAuth token endpoint and client id. Both are overridable
# in config (token-url/client-id) so a fake endpoint can be pinned in tests and
# a future endpoint change needs no code change.
DEFAULT_TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
DEFAULT_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
# The refresh request must match the shape observed from Claude Code's native
# client. These values are configurable because this is empirical compatibility,
# not a stable API contract documented by Anthropic.
DEFAULT_REFRESH_SCOPE = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
DEFAULT_USER_AGENT = "axios/1.15.2"
# Refresh is driven by access-token expiry. A refresh-token expiry, when known,
# is retained for operator visibility but cannot replace proactive access-token
# refresh: no token exchange can extend a refresh token after it has expired.
DEFAULT_REFRESH_MARGIN_SECONDS = 900
DEFAULT_REFRESH_EXPIRY_WARNING_SECONDS = 5 * 24 * 60 * 60
# After a transient refresh failure, cache the sanitized failure for a cooldown
# (with light jitter and exponential backoff up to the max) so concurrent Claude
# CLI retries do not hammer the OAuth endpoint. Fail fast (or serve a still-valid
# token) during the cooldown instead of re-calling upstream.
DEFAULT_REFRESH_COOLDOWN_SECONDS = 90
DEFAULT_REFRESH_COOLDOWN_MAX_SECONDS = 900

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

# A safe OAuth/API error code is a short enum-like token. Only such a value is
# ever surfaced in a ProviderError message — never an error_description free
# string or a raw response body, either of which could echo secret material.
_SAFE_ERROR_CODE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

# Upstream OAuth error codes that mean the refresh token itself is no longer
# usable: the operator must re-login. These are surfaced distinctly from the
# transient (retryable) failures so an operator/alert can tell them apart.
_LOGIN_REQUIRED_ERROR_CODES = frozenset(
    {"invalid_grant", "unauthorized_client", "invalid_client", "access_denied"}
)

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
        self.token_url = string_value(
            self.config.get("token-url") or DEFAULT_TOKEN_URL,
            f"provider {self.name} config.token-url",
            required=True,
        )
        parsed = urlparse(self.token_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            fail(f"provider {self.name} config.token-url must be an http(s) URL")
        # client-id / refresh-scope / user-agent each accept a literal
        # or an env indirection (`client-id-env`), mutually exclusive, falling
        # back to the public Claude Code default when neither is set. This keeps
        # existing documented `client-id-env` configuration working instead of
        # silently ignoring it.
        self.client_id = self._provider_value("client-id", DEFAULT_CLIENT_ID)
        self.refresh_scope = self._provider_value("refresh-scope", DEFAULT_REFRESH_SCOPE)
        self.user_agent = self._provider_value("user-agent", DEFAULT_USER_AGENT)
        self.refresh_margin_seconds = self._int_config("refresh-margin-seconds", DEFAULT_REFRESH_MARGIN_SECONDS)
        self.refresh_expiry_warning_seconds = self._int_config(
            "refresh-expiry-warning-seconds", DEFAULT_REFRESH_EXPIRY_WARNING_SECONDS
        )
        self.refresh_cooldown_seconds = self._int_config("refresh-cooldown-seconds", DEFAULT_REFRESH_COOLDOWN_SECONDS)
        self.refresh_cooldown_max_seconds = self._int_config(
            "refresh-cooldown-max-seconds", DEFAULT_REFRESH_COOLDOWN_MAX_SECONDS
        )
        if self.refresh_cooldown_max_seconds < self.refresh_cooldown_seconds:
            self.refresh_cooldown_max_seconds = self.refresh_cooldown_seconds
        # A file bundle must be usable for its whole TTL, so refresh far enough
        # ahead that the whole bundle window stays covered.
        self.files_refresh_margin_seconds = max(self.refresh_margin_seconds, self.bundle_ttl_seconds)
        self.injection_hosts = injection_hosts(self.config, self.name)
        self.injection_extra_headers = self._injection_extra_headers()
        self.placeholder = self._placeholder_config()
        # Single-flight refresh state. _refresh_lock serializes the upstream
        # refresh call (and the re-read that lets a queued caller observe a
        # just-refreshed credential without calling upstream itself); it does
        # NOT serialize the common read-only path.
        self._refresh_lock = threading.Lock()
        self._cooldown_until = 0.0
        self._cooldown_error = None
        self._backoff_seconds = self.refresh_cooldown_seconds
        self._refresh_expiry_warned = False

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
        # Resolve a config value that may be given literally (``key``) or via an
        # env indirection (``key-env``). The two are mutually exclusive; when
        # neither is set the caller's ``default`` is used (or a config error is
        # raised when required and no default exists). Restored so documented
        # override fields (notably ``client-id-env``) keep working rather than
        # being silently ignored.
        value = self.config.get(key)
        env_key = f"{key}-env"
        env_name = self.config.get(env_key)
        if value is not None and env_name is not None:
            fail(f"provider {self.name} cannot set both {key} and {env_key}")
        if value is not None:
            if isinstance(value, int) and not isinstance(value, bool):
                return str(value)
            if isinstance(value, str) and value:
                return value
            fail(f"provider {self.name} {key} must be a non-empty string or integer")
        if env_name is not None:
            env_ref = string_value(env_name, f"provider {self.name} config.{env_key}", required=True)
            resolved = env_value(env_ref)
            if not resolved:
                fail(f"environment variable {env_ref} must not be empty")
            return resolved
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
        # claudeAiOauth.expiresAt is a millisecond epoch for the ACCESS token
        # only. A missing/invalid value means no known provider-side expiry.
        exp_ms = oauth.get("expiresAt")
        if not isinstance(exp_ms, (int, float)) or isinstance(exp_ms, bool):
            return None
        return int(exp_ms // 1000)

    def _refresh_expiry_seconds(self, oauth):
        exp_ms = oauth.get("refreshTokenExpiresAt")
        if not isinstance(exp_ms, (int, float)) or isinstance(exp_ms, bool):
            return None
        return int(exp_ms // 1000)

    def _warn_refresh_expiry(self, oauth):
        exp = self._refresh_expiry_seconds(oauth)
        if exp is None:
            return
        if exp - int(time.time()) > self.refresh_expiry_warning_seconds:
            self._refresh_expiry_warned = False
            return
        if not self._refresh_expiry_warned:
            self._log(
                f"refresh authorization expires at {rfc3339(exp)}; "
                "replace the broker credential from a trusted login before then"
            )
            self._refresh_expiry_warned = True

    # --- proactive, single-flight refresh -----------------------------------

    def _can_refresh(self):
        # Network refresh needs a durable sink for the rotated credential. Only a
        # credentials-file source has one; a credentials-env source would lose the
        # rotation on restart (and reload a possibly-invalid env refresh token),
        # so it is never network-refreshed.
        return self.credentials_file is not None

    def _fresh_credentials(self, agent_id, audit, request_id, operation_prefix, margin=None, serve_expired=False):
        """Return (data, oauth, access_token, exp_seconds, refreshed).

        Reads current custody, refreshing proactively when the access token is
        within ``margin`` of expiry. Refresh is single-flight (one upstream call
        at a time, in-process and cross-process) and a transient failure is
        served from a cached cooldown rather than re-attempted.

        Expiry handling is the caller's contract: with ``serve_expired`` the
        (possibly expired) credential is always returned (the direct
        ``/v1/files`` path, where the agent holds the refresh token and can
        self-refresh); without it an expired-and-unrefreshable credential fails
        closed (the mediated injection path).
        """
        if margin is None:
            margin = self.refresh_margin_seconds
        data, oauth = self._read_credentials()
        self._warn_refresh_expiry(oauth)
        access_token = self._access_token(oauth)
        exp = self._expiry_seconds(oauth)
        now = int(time.time())
        # Common path: comfortably valid (or no known expiry) — no refresh, no
        # lock, no upstream call.
        if exp is None or exp - now > margin:
            return data, oauth, access_token, exp, False
        # Near/at expiry but this source cannot durably persist a rotation:
        # never call upstream. Serve a still-valid token; fail closed (or serve
        # the expired credential on the direct path) once actually expired. No
        # refresh was attempted, so no refresh audit event is emitted.
        if not self._can_refresh():
            if exp > now or serve_expired:
                return data, oauth, access_token, exp, False
            raise self._expired_failure()
        # Near/at expiry. Serialize so concurrent callers — threads in this
        # broker and other processes (a second broker, the manual probe) sharing
        # the credentials-file — collapse to at most one upstream refresh call.
        with self._refresh_guard():
            data, oauth = self._read_credentials()
            access_token = self._access_token(oauth)
            exp = self._expiry_seconds(oauth)
            now = int(time.time())
            # A concurrent caller may have already refreshed and persisted.
            if exp is not None and exp - now > margin:
                return data, oauth, access_token, exp, False
            if time.monotonic() < self._cooldown_until:
                # Cooling down after a recent failure: never call upstream (no
                # refresh attempt, so no refresh audit event — the cooldown must
                # not manufacture noisy duplicate upstream-refresh events). Serve
                # a still-valid token; fail closed only once actually expired.
                if exp is not None and exp > now:
                    self._log("refresh in cooldown; serving current valid access token")
                    return data, oauth, access_token, exp, False
                if serve_expired and not (
                    self._cooldown_error is not None
                    and self._cooldown_error.reason == "token-refresh-persist-failed"
                ):
                    return data, oauth, access_token, exp, False
                raise self._cooldown_failure()
            try:
                refreshed = self._refresh(data, oauth)
            except ProviderError as error:
                self._enter_cooldown(error)
                # Audit every genuine upstream-refresh attempt failure exactly
                # once, even when a still-valid token is then served, so an
                # operator sees the failure before the token actually expires.
                self._audit_refresh(audit, request_id, agent_id, operation_prefix, False, None, error.reason)
                if exp is not None and exp > now:
                    self._log(f"refresh failed ({error.reason}); serving current valid access token")
                    return data, oauth, access_token, exp, False
                if serve_expired:
                    self._log(f"refresh failed ({error.reason}); vending expired credential for self-refresh")
                    return data, oauth, access_token, exp, False
                # Expired and refresh failed on the mediated path: fail closed.
                raise
            try:
                self._persist(refreshed)
            except ProviderError as error:
                self._enter_cooldown(error)
                self._audit_refresh(audit, request_id, agent_id, operation_prefix, False, None, error.reason)
                if exp is not None and exp > now:
                    self._log(f"refresh persistence failed ({error.reason}); serving current valid access token")
                    return data, oauth, access_token, exp, False
                raise
            self._reset_cooldown()
            data = refreshed
            oauth = data["claudeAiOauth"]
            access_token = self._access_token(oauth)
            exp = self._expiry_seconds(oauth)
            self._audit_refresh(
                audit, request_id, agent_id, operation_prefix, True,
                rfc3339(exp) if exp is not None else None, None,
            )
            return data, oauth, access_token, exp, True

    def _enter_cooldown(self, error):
        backoff = self._backoff_seconds or self.refresh_cooldown_seconds
        jitter = backoff * 0.1 * random.random()
        self._cooldown_until = time.monotonic() + backoff + jitter
        self._cooldown_error = error
        self._backoff_seconds = min(backoff * 2, self.refresh_cooldown_max_seconds)

    def _reset_cooldown(self):
        self._cooldown_until = 0.0
        self._cooldown_error = None
        self._backoff_seconds = self.refresh_cooldown_seconds

    def _cooldown_failure(self):
        if self._cooldown_error is not None:
            return self._cooldown_error
        return ProviderError("token-refresh-failed", "Claude token refresh is in cooldown", 502)

    def _expired_failure(self):
        # Fail-closed sentinel for the mediated path when the access token is
        # expired and no network refresh is possible (a credentials-env source,
        # which cannot durably persist a rotation).
        return ProviderError(
            "credentials-expired",
            "Claude access token is expired and this credential source cannot refresh",
            502,
        )

    def _refresh_lock_path(self):
        # Advisory cross-process lock file beside the credentials-file. Only a
        # credentials-file source refreshes, so env sources have no lock file.
        if self.credentials_file is None:
            return None
        return self.credentials_file.with_name(f".{self.credentials_file.name}.refresh.lock")

    @contextmanager
    def _refresh_guard(self):
        # Serialize the refresh critical section against other threads in this
        # broker (the in-process lock) AND other processes that share the same
        # credentials-file — a second broker instance or the manual refresh probe
        # (an flock on a lock file). Without the cross-process lock, two rotating
        # refresh-token exchanges could interleave and invalidate each other's
        # rotation. Callers re-read the credential after acquiring the guard so a
        # rotation persisted by whoever held it first is observed.
        with self._refresh_lock:
            lock_path = self._refresh_lock_path()
            if lock_path is None:
                yield
                return
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def _audit_refresh(self, audit, request_id, agent_id, operation_prefix, allowed, expires_at, reason):
        if audit is None:
            return
        fields = {
            "request_id": request_id,
            "agent": agent_id,
            "provider": self.name,
            "operation": f"{operation_prefix}.refresh",
            "allowed": allowed,
            "expires_at": expires_at,
        }
        if reason:
            fields["reason"] = reason
        audit.write(**fields)

    def _refresh(self, data, oauth):
        """Exchange the refresh token for a new access token.

        On failure raises a ProviderError whose reason/message carry only the
        upstream HTTP status and a safe OAuth error class — never token bytes,
        Authorization headers, the request body, or a raw response body.
        """
        refresh_token = self._refresh_token(oauth)
        body = json.dumps({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
            "scope": self.refresh_scope,
        }).encode("utf-8")
        request = Request(
            self.token_url,
            method="POST",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*",
                "User-Agent": self.user_agent,
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read()
            payload = json.loads(raw.decode("utf-8"))
        except HTTPError as error:
            raise self._classify_http_error(error) from None
        except URLError:
            raise ProviderError("token-refresh-failed", "Claude token refresh failed: upstream unreachable", 502) from None
        except json.JSONDecodeError:
            raise ProviderError("token-refresh-failed", "Claude token refresh response was not valid JSON", 502) from None
        if not isinstance(payload, dict):
            raise ProviderError("token-refresh-failed", "Claude token refresh response was not an object", 502)
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ProviderError("token-refresh-failed", "Claude token refresh response missing access_token", 502)
        expires_in = payload.get("expires_in")
        if not isinstance(expires_in, (int, float)) or isinstance(expires_in, bool) or expires_in <= 0:
            raise ProviderError("token-refresh-failed", "Claude token refresh response missing expires_in", 502)
        updated = json.loads(json.dumps(data))
        updated_oauth = updated["claudeAiOauth"]
        updated_oauth["accessToken"] = access_token
        rotated = payload.get("refresh_token")
        if isinstance(rotated, str) and rotated:
            updated_oauth["refreshToken"] = rotated
        now = time.time()
        updated_oauth["expiresAt"] = int((now + float(expires_in)) * 1000)
        refresh_expires_in = payload.get("refresh_token_expires_in")
        if (
            isinstance(refresh_expires_in, (int, float))
            and not isinstance(refresh_expires_in, bool)
            and refresh_expires_in > 0
        ):
            updated_oauth["refreshTokenExpiresAt"] = int((now + float(refresh_expires_in)) * 1000)
        scope = payload.get("scope")
        granted_scopes = scope.split() if isinstance(scope, str) else []
        if granted_scopes:
            updated_oauth["scopes"] = granted_scopes
        updated_oauth["clientId"] = self.client_id
        return updated

    def _classify_http_error(self, error):
        status = error.code
        code = self._safe_error_code(error)
        if status == 429:
            reason = "token-refresh-rate-limited"
            message = f"Claude token refresh rate limited: HTTP {status}"
        elif 500 <= status < 600:
            reason = "token-refresh-failed"
            message = f"Claude token refresh failed: HTTP {status}"
        elif status in (400, 401, 403) or code in _LOGIN_REQUIRED_ERROR_CODES:
            reason = "token-refresh-login-required"
            message = f"Claude token refresh requires re-login: HTTP {status}"
        else:
            reason = "token-refresh-failed"
            message = f"Claude token refresh failed: HTTP {status}"
        if code:
            message = f"{message} ({code})"
        return ProviderError(reason, message, 502)

    def _safe_error_code(self, error):
        # Extract only a short enum-like error code from the response. Never
        # surface error_description free text or a raw body (either could echo
        # credential material). Must not raise.
        try:
            raw = error.read(4096)
        except Exception:
            return None
        try:
            payload = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            return None
        code = None
        if isinstance(payload, dict):
            err = payload.get("error")
            if isinstance(err, str):
                code = err
            elif isinstance(err, dict):
                code = err.get("type") or err.get("code")
            if code is None:
                code = payload.get("type")
        if isinstance(code, str) and _SAFE_ERROR_CODE_RE.match(code):
            return code
        return None

    def _persist(self, data):
        # Only a credentials-file source is ever refreshed (see _can_refresh), so
        # a rotated credential always has a durable sink. Guard defensively.
        if self.credentials_file is None:
            raise ProviderError(
                "refresh-source-unpersistable",
                "credentials-env source cannot persist a rotated Claude credential",
                502,
            )
        try:
            self._write_credentials(data)
        except OSError as error:
            raise ProviderError(
                "token-refresh-persist-failed",
                "Claude token refresh succeeded but the rotated credential could not be persisted",
                502,
            ) from error

    def _write_credentials(self, data):
        path = self.credentials_file
        path.parent.mkdir(parents=True, exist_ok=True)
        recovery_prefix = path.name if path.name.startswith(".") else f".{path.name}"
        fd, temporary_name = tempfile.mkstemp(
            prefix=f"{recovery_prefix}.recovery.",
            suffix=".tmp",
            dir=path.parent,
        )
        temporary = Path(temporary_name)
        retain_recovery = False
        try:
            # Create secret-bearing temporary state as 0600 from its first byte;
            # writing with the process umask and chmodding afterward creates a
            # brief world/group-readable exposure window on permissive umasks.
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                os.fchmod(file.fileno(), 0o600)
                json.dump(data, file, indent=2)
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())
            try:
                os.replace(temporary, path)
            except OSError:
                # The upstream may already have invalidated the old refresh
                # token. Retain the fully-written 0600 file as the only possible
                # recovery copy instead of deleting the rotated credential.
                retain_recovery = True
                raise
            try:
                directory_fd = os.open(str(path.parent), os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                # Replacement already succeeded and the canonical content is
                # complete. Some filesystems do not support opening/fsyncing a
                # directory; report reduced crash durability without turning a
                # successful credential replacement into a failed refresh.
                self._log("credential replaced but directory fsync failed; crash durability is uncertain")
        finally:
            if not retain_recovery:
                temporary.unlink(missing_ok=True)

    def _log(self, message):
        # Provider diagnostics only — callers must never pass token material.
        print(f"claude-oauth provider {self.name}: {message}", flush=True)

    # --- direct / file-bundle mode ------------------------------------------

    def files(self, agent_id, audit, request_id):
        # Insecure dev/fallback path: the agent receives the real credential
        # (access + refresh token). Mediated mode is the zero-possession path.
        # serve_expired: direct mode is possession — the agent holds the refresh
        # token, so vend even an expired credential (Claude Code self-refreshes)
        # rather than failing closed the way the mediated injection path does.
        data, _oauth, _access_token, exp, refreshed = self._fresh_credentials(
            agent_id, audit, request_id, "files", self.files_refresh_margin_seconds,
            serve_expired=True,
        )
        content = json.dumps(data, indent=2) + "\n"
        files = [{"name": self.file_name, "content": content, "mode": "0600"}]
        expires_at = rfc3339(exp) if exp is not None else None
        return files, expires_at, {"access_token_expires_at": expires_at, "refreshed": refreshed}

    # --- mediated placeholder mode ------------------------------------------

    def placeholder_files(self, agent_id, audit, request_id, grant=None):
        if self.placeholder is None:
            raise ProviderError("placeholder-files-not-configured", f"provider {self.name} has no placeholder-file config", 403)
        # Read (and validate) the real credential so custody is proven and a
        # missing/broken broker credential fails loudly — but the real
        # accessToken/refreshToken are NEVER emitted into the file. This is a
        # pure custody proof; it does not trigger a network refresh (the
        # placeholder carries only inert tokens with a far-future expiry).
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
        _data, _oauth, access_token, exp, _refreshed = self._fresh_credentials(
            agent_id, audit, request_id, "injection"
        )
        headers = {"authorization": f"Bearer {access_token}"}
        headers.update(self.injection_extra_headers)
        # Every injected name is stripped from the incoming request so the
        # agent's placeholder version is removed before injection.
        strip = list(headers.keys())
        expires_at = rfc3339(exp) if exp is not None else None
        return headers, expires_at, strip

    # --- manual refresh probe (broker-side operator tool) -------------------

    def force_refresh(self):
        """One-shot refresh for the manual probe (scripts/claude-refresh-probe.py).

        Persists rotated tokens on success and returns ONLY redacted metadata —
        never token values. Refuses a credentials-env source because a rotated
        credential cannot be written back to an env var.

        Uses the same cross-process refresh guard as the broker's own refresh, so
        running the probe against a live broker cannot race its refresh: the two
        rotating refresh-token exchanges serialize on the shared lock file rather
        than both spending the same refresh token and invalidating each other.
        """
        if self.credentials_env is not None:
            raise ProviderError(
                "refresh-source-unpersistable",
                "credentials-env source cannot persist rotated Claude tokens; configure credentials-file",
                400,
            )
        with self._refresh_guard():
            data, oauth = self._read_credentials()
            self._access_token(oauth)
            old_exp = self._expiry_seconds(oauth)
            old_refresh_exp = self._refresh_expiry_seconds(oauth)
            old_refresh = oauth.get("refreshToken")
            refreshed = self._refresh(data, oauth)
            self._persist(refreshed)
            self._reset_cooldown()
            new_oauth = refreshed["claudeAiOauth"]
            new_exp = self._expiry_seconds(new_oauth)
            new_refresh_exp = self._refresh_expiry_seconds(new_oauth)
            return {
                "status": "ok",
                "source": "credentials-file",
                "keys": sorted(new_oauth.keys()),
                "old_expires_at": rfc3339(old_exp) if old_exp is not None else None,
                "new_expires_at": rfc3339(new_exp) if new_exp is not None else None,
                "old_refresh_expires_at": rfc3339(old_refresh_exp) if old_refresh_exp is not None else None,
                "new_refresh_expires_at": rfc3339(new_refresh_exp) if new_refresh_exp is not None else None,
                "refresh_token_rotated": bool(new_oauth.get("refreshToken") != old_refresh),
            }


def rfc3339(exp):
    return datetime.fromtimestamp(exp, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
