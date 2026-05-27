import base64
import fnmatch
import json
import os
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse, unquote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from broker.core.config import env_value, fail, list_value, string_value


TOKEN_BUFFER_SECONDS = 300
DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_PAGES = 20
DEFAULT_PER_PAGE = 100
REQUEST_HEADER_ALLOWLIST = {"accept", "if-none-match", "x-github-api-version", "content-type"}


class ProviderError(Exception):
    def __init__(self, reason, message=None, status=400):
        super().__init__(message or reason)
        self.reason = reason
        self.message = message or reason
        self.status = status


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GithubAppProvider:
    def __init__(self, entry):
        self.entry = entry
        self.name = string_value(entry.get("name"), "provider.name", required=True)
        self.config = entry.get("config") or {}
        if not isinstance(self.config, dict):
            fail(f"provider {self.name} config must be a YAML object")
        self.allow = entry.get("allow") or {}
        if not isinstance(self.allow, dict):
            fail(f"provider {self.name} allow must be a YAML object")
        self.api_url = string_value(self.config.get("api-url") or "https://api.github.com", f"provider {self.name} api-url", required=True).rstrip("/")
        self.upstream = urlparse(self.api_url)
        if self.upstream.scheme not in {"http", "https"} or not self.upstream.hostname:
            fail(f"provider {self.name} api-url must be an http(s) URL")
        self.allowed_repositories = self._allowed_strings("repositories")
        self.allowed_methods = {method.upper() for method in self._allowed_strings("methods") or ["GET"]}
        self.permissions = self._permissions()
        self.max_response_bytes = self._int_config("max-response-bytes", DEFAULT_MAX_RESPONSE_BYTES)
        self.max_pages = self._int_config("max-pages", DEFAULT_MAX_PAGES)
        self.per_page = self._int_config("per-page", DEFAULT_PER_PAGE)
        self.cache = {}
        self.cache_lock = threading.Lock()
        self.identity_cache = None
        self.identity_lock = threading.Lock()
        self.key_locks = {}
        self.opener = build_opener(NoRedirect)

    def _allowed_strings(self, key):
        values = list_value(self.allow.get(key), f"provider {self.name} allow.{key}")
        output = []
        for index, value in enumerate(values):
            if not isinstance(value, str) or not value:
                fail(f"provider {self.name} allow.{key}[{index}] must be a non-empty string")
            output.append(value)
        return output

    def _permissions(self):
        permissions = self.allow.get("permissions") or {}
        if not isinstance(permissions, dict):
            fail(f"provider {self.name} allow.permissions must be a YAML object")
        output = {}
        for key, value in permissions.items():
            if not isinstance(key, str) or not isinstance(value, str):
                fail(f"provider {self.name} allow.permissions must be string:string")
            output[key] = value
        return output

    def _int_config(self, key, default):
        value = self.config.get(key, default)
        if not isinstance(value, int) or value <= 0:
            fail(f"provider {self.name} config.{key} must be a positive integer")
        return value

    def _provider_value(self, key):
        value = self.config.get(key)
        env_key = f"{key}-env"
        env_name = self.config.get(env_key)
        if value is not None and env_name is not None:
            fail(f"provider {self.name} cannot set both {key} and {env_key}")
        if value is not None:
            if isinstance(value, int):
                return str(value)
            if isinstance(value, str):
                return value
            fail(f"provider {self.name} {key} must be a string or integer")
        if isinstance(env_name, str):
            return env_value(env_name)
        fail(f"provider {self.name} requires {key} or {env_key}")

    def _private_key(self):
        private_key_env = self.config.get("private-key-env")
        private_key_base64_env = self.config.get("private-key-base64-env") or self.config.get("private-key-b64-env")
        if private_key_env and private_key_base64_env:
            fail(f"provider {self.name} cannot set both private-key-env and private-key-base64-env")
        if isinstance(private_key_env, str):
            return env_value(private_key_env)
        if isinstance(private_key_base64_env, str):
            try:
                return base64.b64decode(env_value(private_key_base64_env)).decode("utf-8")
            except Exception as error:
                fail(f"could not decode {private_key_base64_env}: {error}")
        fail(f"provider {self.name} requires private-key-env or private-key-base64-env")

    def _b64url(self, data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _openssl_sign(self, signing_input):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as key_file:
            key_file.write(self._private_key())
            key_path = Path(key_file.name)
        try:
            key_path.chmod(0o600)
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", str(key_path)],
                check=True,
                input=signing_input.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return result.stdout
        finally:
            key_path.unlink(missing_ok=True)

    def _jwt(self):
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": self._provider_value("app-id")}
        signing_input = ".".join([
            self._b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            self._b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
        ])
        return f"{signing_input}.{self._b64url(self._openssl_sign(signing_input))}"

    def _parse_time(self, value):
        if not isinstance(value, str):
            return 0
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0

    def normalize_target(self, target):
        return github_repo_from_target(target)

    def target_from_repo(self, repo):
        return f"github.com/{repo}"

    def _cache_key(self, repo):
        permission_key = ",".join(f"{key}:{self.permissions[key]}" for key in sorted(self.permissions))
        return "|".join([self.name, repo, permission_key])

    def _key_lock(self, key):
        with self.cache_lock:
            lock = self.key_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self.key_locks[key] = lock
            return lock

    def token_for_repo(self, repo, effective_repositories):
        self._ensure_repo_allowed(repo, effective_repositories)
        key = self._cache_key(repo)
        with self._key_lock(key):
            cached = self.cache.get(key, {})
            if cached.get("token") and self._parse_time(cached.get("expires_at")) > time.time() + TOKEN_BUFFER_SECONDS:
                return cached["token"], cached.get("expires_at")
            token, expires_at = self._mint_token(repo)
            self.cache[key] = {"token": token, "expires_at": expires_at}
            return token, expires_at

    def _mint_token(self, repo):
        owner, name = repo.split("/", 1)
        body = {"repositories": [name]}
        if self.permissions:
            body["permissions"] = self.permissions
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        installation_id = self._provider_value("installation-id")
        request = Request(
            f"{self.api_url}/app/installations/{installation_id}/access_tokens",
            method="POST",
            data=data,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._jwt()}",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
            },
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            text = error.read().decode("utf-8", errors="replace")
            raise ProviderError("token-mint-failed", f"GitHub token request failed: {error.code} {error.reason}: {text}", 502)
        except URLError as error:
            raise ProviderError("token-mint-failed", f"GitHub token request failed: {error.reason}", 502)
        token = payload.get("token")
        if not isinstance(token, str) or not token:
            raise ProviderError("token-mint-failed", "GitHub token response did not include token", 502)
        expires_at = payload.get("expires_at") or datetime.now(timezone.utc).isoformat()
        return token, expires_at

    def _github_json(self, path, token):
        request = Request(
            f"{self.api_url}{path}",
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            text = error.read().decode("utf-8", errors="replace")
            raise ProviderError("identity-lookup-failed", f"GitHub identity request failed: {error.code} {error.reason}: {text}", 502)
        except URLError as error:
            raise ProviderError("identity-lookup-failed", f"GitHub identity request failed: {error.reason}", 502)

    def _load_identity(self):
        jwt = self._jwt()
        app = self._github_json("/app", jwt)
        slug = app.get("slug")
        if not isinstance(slug, str) or not slug:
            raise ProviderError("identity-lookup-failed", "GitHub App response did not include slug", 502)
        bot_login = f"{slug}[bot]"
        user = self._github_json(f"/users/{quote(bot_login, safe='')}", jwt)
        bot_id = user.get("id")
        if not isinstance(bot_id, int):
            raise ProviderError("identity-lookup-failed", "GitHub bot user response did not include numeric id", 502)
        return {
            "name": bot_login,
            "email": f"{bot_id}+{bot_login}@users.noreply.github.com",
        }

    def identity_for_repo(self, repo, effective_repositories):
        self._ensure_repo_allowed(repo, effective_repositories)
        with self.identity_lock:
            if self.identity_cache is None:
                self.identity_cache = self._load_identity()
            return dict(self.identity_cache)

    def _effective_port(self, parsed):
        if parsed.port:
            return parsed.port
        if parsed.scheme == "https":
            return 443
        if parsed.scheme == "http":
            return 80
        return None

    def _validate_url(self, url, method, effective_repositories):
        parsed = urlparse(url)
        if parsed.username or parsed.password:
            raise ProviderError("url-userinfo-not-allowed")
        if parsed.scheme != self.upstream.scheme:
            raise ProviderError("scheme-not-allowed")
        if parsed.hostname != self.upstream.hostname or self._effective_port(parsed) != self._effective_port(self.upstream):
            raise ProviderError("host-not-allowed")
        if method.upper() not in self.allowed_methods:
            raise ProviderError("method-not-allowed")
        repo = self._repo_from_path(parsed.path)
        self._ensure_repo_allowed(repo, effective_repositories)
        return parsed, repo

    def _repo_from_path(self, path):
        parts = [unquote(part) for part in path.split("/") if part]
        if len(parts) < 3 or parts[0] != "repos":
            raise ProviderError("path-not-allowed")
        if any(part in {".", ".."} or "/" in part or "\\" in part for part in parts):
            raise ProviderError("path-not-allowed")
        owner = parts[1]
        repo = parts[2]
        if not owner or not repo:
            raise ProviderError("path-not-allowed")
        return f"{owner}/{repo}"

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

    def _filtered_headers(self, headers):
        output = {}
        for key, value in (headers or {}).items():
            lower = key.lower()
            if lower in REQUEST_HEADER_ALLOWLIST:
                output[lower] = str(value)
        return output

    def _read_response(self, response, cap):
        chunks = []
        total = 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                raise ProviderError("response-too-large", status=502)
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")

    def _request_url_for_page(self, parsed, page):
        query = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key not in {"page", "per_page"}]
        query.extend([("per_page", str(self.per_page)), ("page", str(page))])
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urlencode(query), ""))

    def http_request(self, method, url, headers, paginate, effective_repositories):
        method = method.upper()
        parsed, repo = self._validate_url(url, method, effective_repositories)
        token, _expires_at = self.token_for_repo(repo, effective_repositories)
        if paginate:
            return self._paginated_request(parsed, token, headers)
        return self._single_request(url, method, token, headers, self.max_response_bytes), repo

    def _single_request(self, url, method, token, headers, cap):
        request_headers = {
            **self._filtered_headers(headers),
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        request = Request(url, method=method, headers=request_headers)
        try:
            with self.opener.open(request, timeout=30) as response:
                body = self._read_response(response, cap)
                return {
                    "status": response.status,
                    "headers": {key.lower(): value for key, value in response.headers.items()},
                    "body": body,
                }
        except HTTPError as error:
            body = self._read_response(error, cap)
            return {
                "status": error.code,
                "headers": {key.lower(): value for key, value in error.headers.items()},
                "body": body,
            }
        except URLError as error:
            raise ProviderError("upstream-unreachable", str(error.reason), 502)

    def _paginated_request(self, parsed, token, headers):
        items = []
        final_headers = {}
        first_headers = {}
        total_bytes = 2
        for page in range(1, self.max_pages + 1):
            result = self._single_request(self._request_url_for_page(parsed, page), "GET", token, headers, self.max_response_bytes)
            if page == 1:
                first_headers = result["headers"]
            final_headers = result["headers"]
            if result["status"] < 200 or result["status"] >= 300:
                return result, self._repo_from_path(parsed.path)
            try:
                payload = json.loads(result["body"])
            except json.JSONDecodeError:
                raise ProviderError("pagination-non-json-response", status=502)
            if not isinstance(payload, list):
                raise ProviderError("pagination-non-array-response", status=502)
            items.extend(payload)
            total_bytes += len(result["body"].encode("utf-8"))
            if total_bytes > self.max_response_bytes:
                raise ProviderError("response-too-large", status=502)
            if len(payload) < self.per_page:
                body = json.dumps(items, separators=(",", ":"))
                return {"status": 200, "headers": {**first_headers, **final_headers}, "body": body}, self._repo_from_path(parsed.path)
        raise ProviderError("pagination-page-cap-exceeded", status=502)


def github_repo_from_target(target):
    value = target.strip().removesuffix(".git").strip("/")
    if value.startswith("https://") or value.startswith("http://"):
        parsed = urlparse(value)
        value = f"{parsed.hostname or ''}{parsed.path}".strip("/").removesuffix(".git")
    if value.startswith("github.com/"):
        parts = value.split("/")
        if len(parts) >= 3:
            return f"{parts[1]}/{parts[2]}"
    if value.count("/") == 1:
        return value
    raise ProviderError("target-invalid")
