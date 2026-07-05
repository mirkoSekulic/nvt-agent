import json
import os
import ssl
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from broker.core.audit import AuditLog
from broker.core.agents import AgentRegistry
from broker.core.config import BrokerConfigError, load_config
from broker.core.providers import load_providers
from broker.plugins.github_app.provider import ProviderError


MAX_REQUEST_BYTES = 1024 * 1024

# Documented zero-entropy placeholder from protocol/injection.md. It is the
# only credential-shaped value allowed inside a mediated agent container.
INJECTION_PLACEHOLDER = "NVT-PLACEHOLDER-NOT-A-KEY"


class Broker:
    def __init__(self, config_path=None, audit_path=None):
        self.config = load_config(config_path)
        self.providers = load_providers(self.config)
        self.audit = AuditLog(audit_path)
        self.agents = AgentRegistry()

    def provider(self, name):
        provider = self.providers.get(name)
        if provider is None:
            raise ProviderError("provider-not-found")
        return provider

    def authenticate_role(self, authorization, role):
        identity = self.agents.authenticate(authorization)
        if identity.get("role", "agent") != role:
            raise ProviderError(
                "role-not-allowed",
                f"this endpoint requires a {role}-role identity",
                403,
            )
        return identity

    def ensure_not_header_inject(self, agent, provider_name):
        grant = self.agents.grant(agent, provider_name)
        if grant is not None and grant.get("materialization") == "header-inject":
            raise ProviderError(
                "materialization-mismatch",
                f"grant for {provider_name} is header-inject; secret-bearing endpoints are disabled",
                403,
            )

    def http_request(self, request_id, payload, authorization):
        agent = self.authenticate_role(authorization, "agent")
        provider_name = string_field(payload, "provider")
        method = string_field(payload, "method").upper()
        url = string_field(payload, "url")
        headers = payload.get("headers") or {}
        if not isinstance(headers, dict):
            raise ProviderError("headers-invalid")
        paginate = bool(payload.get("paginate", False))
        provider = self.provider(provider_name)
        effective_repositories = self.agents.effective_repositories(agent, provider_name)
        result, repo = provider.http_request(method, url, headers, paginate, effective_repositories)
        self.audit.write(
            request_id=request_id,
            agent=agent["id"],
            provider=provider_name,
            operation="http.request",
            method=method,
            url=url,
            target=provider.target_from_repo(repo),
            allowed=True,
            status=result["status"],
            response_size=len(result["body"].encode("utf-8")),
        )
        return {"ok": True, **result}

    def token(self, request_id, payload, authorization):
        agent = self.authenticate_role(authorization, "agent")
        provider_name = string_field(payload, "provider")
        self.ensure_not_header_inject(agent, provider_name)
        target = string_field(payload, "target")
        purpose = payload.get("purpose")
        provider = self.provider(provider_name)
        repo = provider.normalize_target(target)
        effective_repositories = self.agents.effective_repositories(agent, provider_name)
        token, expires_at = provider.token_for_repo(repo, effective_repositories)
        self.audit.write(
            request_id=request_id,
            agent=agent["id"],
            provider=provider_name,
            operation="token",
            target=provider.target_from_repo(repo),
            purpose=purpose,
            allowed=True,
        )
        return {"ok": True, "token": token, "expires_at": expires_at}

    def identity(self, request_id, payload, authorization):
        agent = self.authenticate_role(authorization, "agent")
        provider_name = string_field(payload, "provider")
        target = string_field(payload, "target")
        provider = self.provider(provider_name)
        repo = provider.normalize_target(target)
        effective_repositories = self.agents.effective_repositories(agent, provider_name)
        identity = provider.identity_for_repo(repo, effective_repositories)
        self.audit.write(
            request_id=request_id,
            agent=agent["id"],
            provider=provider_name,
            operation="identity",
            target=provider.target_from_repo(repo),
            allowed=True,
        )
        return {"ok": True, **identity}

    def headers(self, request_id, payload, authorization):
        agent = self.authenticate_role(authorization, "agent")
        provider_name = string_field(payload, "provider")
        self.ensure_not_header_inject(agent, provider_name)
        target = string_field(payload, "target")
        provider = self.provider(provider_name)
        repo = provider.normalize_target(target)
        effective_repositories = self.agents.effective_repositories(agent, provider_name)
        headers = provider.headers_for_repo(repo, effective_repositories)
        self.audit.write(
            request_id=request_id,
            agent=agent["id"],
            provider=provider_name,
            operation="headers",
            target=provider.target_from_repo(repo),
            allowed=True,
        )
        return {"ok": True, "headers": headers}

    def files(self, request_id, payload, authorization):
        agent = self.authenticate_role(authorization, "agent")
        provider_name = string_field(payload, "provider")
        self.ensure_not_header_inject(agent, provider_name)
        provider = self.provider(provider_name)
        self.agents.ensure_provider_grant(agent, provider_name)
        if not hasattr(provider, "files"):
            raise ProviderError("files-not-supported", f"provider {provider_name} does not support file bundles")
        files, expires_at = provider.files(agent["id"], self.audit, request_id)
        self.audit.write(
            request_id=request_id,
            agent=agent["id"],
            provider=provider_name,
            operation="files",
            allowed=True,
            expires_at=expires_at,
            file_count=len(files),
        )
        return {"ok": True, "files": files, "expires_at": expires_at}

    def _injection_grant(self, subject, capability):
        grant = self.agents.grant(subject, capability)
        if grant is None:
            raise ProviderError("provider-not-granted", None, 403)
        if grant.get("materialization") != "header-inject":
            raise ProviderError(
                "materialization-mismatch",
                f"grant for {capability} is not header-inject",
                403,
            )
        return grant

    def _injection_provider(self, capability):
        provider = self.provider(capability)
        hosts = getattr(provider, "injection_hosts", None) or []
        if not hosts or not hasattr(provider, "injection_headers"):
            raise ProviderError(
                "injection-not-supported",
                f"provider {capability} does not support header injection",
                403,
            )
        return provider, hosts

    def injection_headers(self, request_id, payload, authorization):
        identity = self.authenticate_role(authorization, "egress")
        paired = self.agents.by_id(identity.get("paired_agent") or "")
        if paired is None or paired.get("role", "agent") != "agent":
            raise ProviderError("pairing-invalid", "egress identity has no valid paired agent", 403)
        capability = string_field(payload, "capability")
        host = string_field(payload, "host")
        method = string_field(payload, "method").upper()
        path = string_field(payload, "path")
        self._injection_grant(paired, capability)
        provider, hosts = self._injection_provider(capability)
        if host not in hosts:
            raise ProviderError("host-not-allowed", f"host {host} is not allowed for {capability}", 403)
        headers, expires_at, strip = provider.injection_headers(host, method, path, paired["id"], self.audit, request_id)
        self.audit.write(
            request_id=request_id,
            agent=identity["id"],
            paired_agent=paired["id"],
            provider=capability,
            operation="injection.headers",
            host=host,
            method=method,
            path=path,
            allowed=True,
            expires_at=expires_at,
        )
        return {"ok": True, "headers": headers, "expires_at": expires_at, "strip_request_headers": strip}

    def injection_routing(self, request_id, payload, authorization):
        identity = self.agents.authenticate(authorization)
        if identity.get("role", "agent") == "egress":
            subject = self.agents.by_id(identity.get("paired_agent") or "")
            if subject is None or subject.get("role", "agent") != "agent":
                raise ProviderError("pairing-invalid", "egress identity has no valid paired agent", 403)
        else:
            subject = identity
        capability = string_field(payload, "capability")
        self._injection_grant(subject, capability)
        _, hosts = self._injection_provider(capability)
        self.audit.write(
            request_id=request_id,
            agent=identity["id"],
            paired_agent=subject["id"],
            provider=capability,
            operation="injection.routing",
            allowed=True,
        )
        return {"ok": True, "hosts": hosts, "placeholder": INJECTION_PLACEHOLDER}

    def denied(self, request_id, payload, reason, message=None, authorization=None):
        agent_id = None
        try:
            agent_id = self.agents.authenticate(authorization)["id"] if authorization else None
        except ProviderError:
            agent_id = None
        self.audit.write(
            request_id=request_id,
            agent=agent_id,
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
                    response = broker.http_request(request_id, payload, self.headers.get("authorization"))
                    self.write_json(200, response)
                    return
                if self.path == "/v1/token":
                    response = broker.token(request_id, payload, self.headers.get("authorization"))
                    self.write_json(200, response)
                    return
                if self.path == "/v1/identity":
                    response = broker.identity(request_id, payload, self.headers.get("authorization"))
                    self.write_json(200, response)
                    return
                if self.path == "/v1/headers":
                    response = broker.headers(request_id, payload, self.headers.get("authorization"))
                    self.write_json(200, response)
                    return
                if self.path == "/v1/files":
                    response = broker.files(request_id, payload, self.headers.get("authorization"))
                    self.write_json(200, response)
                    return
                if self.path == "/v1/injection/headers":
                    response = broker.injection_headers(request_id, payload, self.headers.get("authorization"))
                    self.write_json(200, response)
                    return
                if self.path == "/v1/injection/routing":
                    response = broker.injection_routing(request_id, payload, self.headers.get("authorization"))
                    self.write_json(200, response)
                    return
                self.write_json(404, {"ok": False, "error": "not-found"})
            except ProviderError as error:
                self.write_json(error.status, broker.denied(request_id, payload, error.reason, error.message, self.headers.get("authorization")))
            except Exception as error:
                self.write_json(500, broker.denied(request_id, payload, "internal-error", str(error), self.headers.get("authorization")))

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
    cert = os.environ.get("NVT_BROKER_TLS_CERT")
    key = os.environ.get("NVT_BROKER_TLS_KEY")
    if bool(cert) != bool(key):
        raise BrokerConfigError("NVT_BROKER_TLS_CERT and NVT_BROKER_TLS_KEY must be set together")
    if cert and key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert, keyfile=key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def parse_bind(bind):
    if ":" not in bind:
        raise BrokerConfigError("bind must be host:port")
    host, port = bind.rsplit(":", 1)
    return host, int(port)
