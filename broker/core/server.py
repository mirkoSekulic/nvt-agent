import json
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from broker.core.audit import AuditLog
from broker.core.config import BrokerConfigError, load_config
from broker.core.providers import load_providers
from broker.plugins.github_app.provider import ProviderError


MAX_REQUEST_BYTES = 1024 * 1024


class Broker:
    def __init__(self, config_path=None, audit_path=None):
        self.config = load_config(config_path)
        self.providers = load_providers(self.config)
        self.audit = AuditLog(audit_path)

    def provider(self, name):
        provider = self.providers.get(name)
        if provider is None:
            raise ProviderError("provider-not-found")
        return provider

    def http_request(self, request_id, payload):
        provider_name = string_field(payload, "provider")
        method = string_field(payload, "method").upper()
        url = string_field(payload, "url")
        headers = payload.get("headers") or {}
        if not isinstance(headers, dict):
            raise ProviderError("headers-invalid")
        paginate = bool(payload.get("paginate", False))
        provider = self.provider(provider_name)
        result, repo = provider.http_request(method, url, headers, paginate)
        self.audit.write(
            request_id=request_id,
            provider=provider_name,
            operation="http.request",
            method=method,
            url=url,
            target=f"github.com/{repo}",
            allowed=True,
            status=result["status"],
            response_size=len(result["body"].encode("utf-8")),
        )
        return {"ok": True, **result}

    def token(self, request_id, payload):
        provider_name = string_field(payload, "provider")
        target = string_field(payload, "target")
        purpose = payload.get("purpose")
        repo = github_repo_from_target(target)
        provider = self.provider(provider_name)
        token, expires_at = provider.token_for_repo(repo)
        self.audit.write(
            request_id=request_id,
            provider=provider_name,
            operation="token",
            target=f"github.com/{repo}",
            purpose=purpose,
            allowed=True,
        )
        return {"ok": True, "token": token, "expires_at": expires_at}

    def denied(self, request_id, payload, reason, message=None):
        self.audit.write(
            request_id=request_id,
            provider=payload.get("provider") if isinstance(payload, dict) else None,
            operation=payload.get("type") if isinstance(payload, dict) else None,
            allowed=False,
            reason=reason,
        )
        return {"ok": False, "error": reason, "message": message or reason}


def string_field(payload, key):
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ProviderError(f"{key}-required")
    return value


def github_repo_from_target(target):
    value = target.strip().removesuffix(".git").strip("/")
    if value.startswith("https://") or value.startswith("http://"):
        from urllib.parse import urlparse

        parsed = urlparse(value)
        value = f"{parsed.hostname or ''}{parsed.path}".strip("/").removesuffix(".git")
    if value.startswith("github.com/"):
        parts = value.split("/")
        if len(parts) >= 3:
            return f"{parts[1]}/{parts[2]}"
    if value.count("/") == 1:
        return value
    raise ProviderError("target-invalid")


def make_handler(broker):
    class Handler(BaseHTTPRequestHandler):
        server_version = "nvt-brokerd/0.1"

        def log_message(self, format, *args):
            return

        def do_GET(self):
            if self.path == "/health":
                self.write_json(200, {"ok": True, "status": "ready"})
                return
            self.write_json(404, {"ok": False, "error": "not-found"})

        def do_POST(self):
            request_id = str(uuid.uuid4())
            payload = {}
            try:
                payload = self.read_payload()
                if self.path == "/v1/http/request":
                    response = broker.http_request(request_id, payload)
                    self.write_json(200, response)
                    return
                if self.path == "/v1/token":
                    response = broker.token(request_id, payload)
                    self.write_json(200, response)
                    return
                self.write_json(404, {"ok": False, "error": "not-found"})
            except ProviderError as error:
                self.write_json(error.status, broker.denied(request_id, payload, error.reason, error.message))
            except Exception as error:
                self.write_json(500, broker.denied(request_id, payload, "internal-error", str(error)))

        def read_payload(self):
            length = int(self.headers.get("content-length") or "0")
            if length <= 0 or length > MAX_REQUEST_BYTES:
                raise ProviderError("request-size-invalid")
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
            except json.JSONDecodeError:
                raise ProviderError("malformed-json")
            if not isinstance(payload, dict):
                raise ProviderError("request-not-object")
            return payload

        def write_json(self, status, payload):
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def serve(bind, config_path=None, audit_path=None):
    broker = Broker(config_path, audit_path)
    host, port = parse_bind(bind)
    server = ThreadingHTTPServer((host, port), make_handler(broker))
    server.serve_forever()


def parse_bind(bind):
    if ":" not in bind:
        raise BrokerConfigError("bind must be host:port")
    host, port = bind.rsplit(":", 1)
    return host, int(port)
