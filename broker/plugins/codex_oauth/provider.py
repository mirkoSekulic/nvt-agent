import base64
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from broker.core.config import env_value, fail, list_value, string_value
from broker.plugins.github_app.provider import ProviderError


DEFAULT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_TOKEN_URL = "https://auth.openai.com/oauth/token"
DEFAULT_REFRESH_MARGIN_SECONDS = 600
DEFAULT_STUB_REFRESH_TOKEN = "nvt-broker-stub"


class CodexOAuthProvider:
    def __init__(self, entry):
        self.entry = entry
        self.name = string_value(entry.get("name"), "provider.name", required=True)
        self.config = entry.get("config") or {}
        if not isinstance(self.config, dict):
            fail(f"provider {self.name} config must be a YAML object")
        self.auth_file = Path(string_value(self.config.get("auth-file"), f"provider {self.name} config.auth-file", required=True))
        if not self.auth_file.is_absolute():
            fail(f"provider {self.name} config.auth-file must be an absolute path")
        self.token_url = string_value(self.config.get("token-url") or DEFAULT_TOKEN_URL, f"provider {self.name} config.token-url", required=True)
        parsed = urlparse(self.token_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            fail(f"provider {self.name} config.token-url must be an http(s) URL")
        self.client_id = self._provider_value("client-id", DEFAULT_CLIENT_ID)
        self.refresh_margin_seconds = self._int_config("refresh-margin-seconds", DEFAULT_REFRESH_MARGIN_SECONDS)
        self.stub_refresh_token = string_value(
            self.config.get("stub-refresh-token") or DEFAULT_STUB_REFRESH_TOKEN,
            f"provider {self.name} config.stub-refresh-token",
            required=True,
        )
        self.extra_files = self._extra_files()
        self.lock = threading.Lock()

    def _provider_value(self, key, default=None):
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
        fail(f"provider {self.name} requires {key} or {env_key}")

    def _int_config(self, key, default):
        value = self.config.get(key, default)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            fail(f"provider {self.name} config.{key} must be a positive integer")
        return value

    def _extra_files(self):
        output = []
        for index, item in enumerate(list_value(self.config.get("extra-files"), f"provider {self.name} config.extra-files")):
            if not isinstance(item, dict):
                fail(f"provider {self.name} config.extra-files[{index}] must be a YAML object")
            name = string_value(item.get("name"), f"provider {self.name} config.extra-files[{index}].name", required=True)
            validate_file_name(name)
            path = Path(string_value(item.get("path"), f"provider {self.name} config.extra-files[{index}].path", required=True))
            if not path.is_absolute():
                fail(f"provider {self.name} config.extra-files[{index}].path must be an absolute path")
            mode = string_value(item.get("mode"), f"provider {self.name} config.extra-files[{index}].mode")
            if mode is not None:
                validate_mode(mode)
            output.append({"name": name, "path": path, "mode": mode})
        return output

    def files(self, agent_id, audit, request_id):
        with self.lock:
            auth = self._read_auth()
            access_token = self._token(auth, "access_token")
            exp = self._jwt_exp(access_token)
            now = int(time.time())
            refreshed = False
            if exp - now <= self.refresh_margin_seconds:
                refresh_persisted = False
                try:
                    refreshed_auth = self._refresh(auth)
                    self._write_auth(refreshed_auth)
                    refresh_persisted = True
                    access_token = self._token(refreshed_auth, "access_token")
                    exp = self._jwt_exp(access_token)
                    auth = refreshed_auth
                    refreshed = True
                    audit.write(
                        request_id=request_id,
                        agent=agent_id,
                        provider=self.name,
                        operation="files.refresh",
                        allowed=True,
                        expires_at=rfc3339(exp),
                    )
                except ProviderError:
                    if refresh_persisted:
                        audit.write(
                            request_id=request_id,
                            agent=agent_id,
                            provider=self.name,
                            operation="files.refresh",
                            allowed=True,
                            expires_at=None,
                            validation_error=True,
                        )
                    if exp <= now:
                        raise
                    print(f"codex-oauth provider {self.name}: refresh failed; serving current valid access token", flush=True)
            vended = json.loads(json.dumps(auth))
            tokens = vended.setdefault("tokens", {})
            if not isinstance(tokens, dict):
                raise ProviderError("auth-file-invalid", "Codex auth tokens must be an object", 502)
            tokens["refresh_token"] = self.stub_refresh_token
            files = [
                {
                    "name": "auth.json",
                    "content": json.dumps(vended, indent=2) + "\n",
                    "mode": "0600",
                }
            ]
            for item in self.extra_files:
                files.append(self._read_extra_file(item))
            expires_at = rfc3339(exp)
            audit.write(
                request_id=request_id,
                agent=agent_id,
                provider=self.name,
                operation="files.vend",
                allowed=True,
                expires_at=expires_at,
                refreshed=refreshed,
            )
            return files, expires_at

    def _read_auth(self):
        try:
            with self.auth_file.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except FileNotFoundError as error:
            raise ProviderError("auth-file-not-found", "Codex auth file not found", 502) from error
        except json.JSONDecodeError as error:
            raise ProviderError("auth-file-invalid", "Codex auth file is not valid JSON", 502) from error
        if not isinstance(data, dict):
            raise ProviderError("auth-file-invalid", "Codex auth file must be a JSON object", 502)
        tokens = data.get("tokens")
        if not isinstance(tokens, dict):
            raise ProviderError("auth-file-invalid", "Codex auth file tokens must be an object", 502)
        self._token(data, "refresh_token")
        return data

    def _token(self, auth, key):
        tokens = auth.get("tokens")
        value = tokens.get(key) if isinstance(tokens, dict) else None
        if not isinstance(value, str) or not value:
            raise ProviderError("auth-file-invalid", f"Codex auth file missing tokens.{key}", 502)
        return value

    def _jwt_exp(self, token):
        parts = token.split(".")
        if len(parts) < 2:
            raise ProviderError("access-token-invalid", "Codex access token is not a JWT", 502)
        segment = parts[1]
        padding = "=" * ((4 - len(segment) % 4) % 4)
        try:
            payload = json.loads(base64.urlsafe_b64decode((segment + padding).encode("ascii")).decode("utf-8"))
        except Exception as error:
            raise ProviderError("access-token-invalid", "Codex access token payload is invalid", 502) from error
        exp = payload.get("exp") if isinstance(payload, dict) else None
        if not isinstance(exp, int) or isinstance(exp, bool):
            raise ProviderError("access-token-invalid", "Codex access token payload missing exp", 502)
        return exp

    def _refresh(self, auth):
        refresh_token = self._token(auth, "refresh_token")
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
            raise ProviderError("token-refresh-failed", f"Codex token refresh failed: HTTP {error.code}", 502) from error
        except URLError as error:
            raise ProviderError("token-refresh-failed", "Codex token refresh failed: upstream unreachable", 502) from error
        except json.JSONDecodeError as error:
            raise ProviderError("token-refresh-failed", "Codex token refresh response was not valid JSON", 502) from error
        if not isinstance(payload, dict):
            raise ProviderError("token-refresh-failed", "Codex token refresh response was not an object", 502)
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ProviderError("token-refresh-failed", "Codex token refresh response missing access_token", 502)
        updated = json.loads(json.dumps(auth))
        tokens = updated["tokens"]
        tokens["access_token"] = access_token
        for key in ("refresh_token", "id_token"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                tokens[key] = value
        updated["last_refresh"] = datetime.now(timezone.utc).isoformat()
        return updated

    def _write_auth(self, auth):
        self.auth_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            mode = self.auth_file.stat().st_mode & 0o777
        except FileNotFoundError:
            mode = 0o600
        temporary = self.auth_file.with_name(f".{self.auth_file.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            with temporary.open("w", encoding="utf-8") as file:
                json.dump(auth, file, indent=2)
                file.write("\n")
            temporary.chmod(mode)
            os.replace(temporary, self.auth_file)
        finally:
            temporary.unlink(missing_ok=True)

    def _read_extra_file(self, item):
        try:
            content = item["path"].read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise ProviderError("extra-file-invalid", f"extra file {item['name']} is not UTF-8", 502) from error
        except OSError as error:
            raise ProviderError("extra-file-read-failed", f"extra file {item['name']} could not be read", 502) from error
        output = {"name": item["name"], "content": content}
        if item["mode"]:
            output["mode"] = item["mode"]
        return output


def validate_file_name(name):
    if not isinstance(name, str) or not name or "/" in name or "\\" in name or name == "." or ".." in name:
        fail("file bundle names must be plain relative filenames")


def validate_mode(mode):
    if not isinstance(mode, str) or len(mode) != 4 or any(char not in "01234567" for char in mode):
        fail("file bundle modes must be four-digit octal strings")


def rfc3339(exp):
    return datetime.fromtimestamp(exp, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
