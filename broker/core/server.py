import json
import os
import re
import ssl
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from broker.core.audit import AuditLog
from broker.core.agents import AgentRegistry
from broker.core.config import BrokerConfigError, load_config
from broker.core.providers import load_providers
from broker.plugins.github_app.provider import ProviderError


MAX_REQUEST_BYTES = 1024 * 1024

# Cap entries per injection report. Combined with MAX_REQUEST_BYTES this
# bounds a single report; oversized reports are denied with the standard
# error shape, never truncated silently.
MAX_REPORT_ENTRIES = 100

# path_class is a sanitized class computed by egressd (protocol/injection.md):
# the git classes or a single lowercase path segment. The broker enforces the
# shape so a buggy egressd or a leaked egress token cannot write raw paths or
# arbitrary strings into the audit log.
PATH_CLASS_RE = re.compile(r"^[a-z0-9._-]{1,64}$")

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
        if grant is None:
            return
        materialization = grant.get("materialization")
        # Both header-inject and placeholder-file keep the real secret out of
        # the agent's hands, so neither may reach a secret-bearing endpoint.
        if materialization in ("header-inject", "placeholder-file"):
            raise ProviderError(
                "materialization-mismatch",
                f"grant for {provider_name} is {materialization}; secret-bearing endpoints are disabled",
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
        files_result = provider.files(agent["id"], self.audit, request_id)
        if len(files_result) == 2:
            files, provider_expires_at = files_result
            files_metadata = {}
        else:
            files, provider_expires_at, files_metadata = files_result
        expires_at = capped_files_expiry(provider_expires_at, getattr(provider, "bundle_ttl_seconds", None))
        vend_audit = {
            **files_metadata,
            "request_id": request_id,
            "agent": agent["id"],
            "provider": provider_name,
            "operation": "files.vend",
            "allowed": True,
            "expires_at": expires_at,
            "bundle_expires_at": expires_at,
        }
        self.audit.write(**vend_audit)
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

    def placeholder_files(self, request_id, payload, authorization):
        # The agent fetches its own placeholder file: it is inert (placeholders
        # only), so — unlike header-inject — the agent identity itself is the
        # caller. Scoped exactly like every other grant; another agent's
        # bindings are unreachable. Distinct from /v1/files: this path can only
        # emit placeholders (the provider method never has the real bundle).
        agent = self.authenticate_role(authorization, "agent")
        provider_name = string_field(payload, "provider")
        grant = self.agents.grant(agent, provider_name)
        if grant is None:
            raise ProviderError("provider-not-granted", None, 403)
        if grant.get("materialization") != "placeholder-file":
            raise ProviderError(
                "materialization-mismatch",
                f"grant for {provider_name} is not placeholder-file",
                403,
            )
        provider = self.provider(provider_name)
        if not hasattr(provider, "placeholder_files"):
            raise ProviderError(
                "placeholder-files-not-supported",
                f"provider {provider_name} does not support placeholder files",
                403,
            )
        files, hosts, expires_at = provider.placeholder_files(agent["id"], self.audit, request_id, grant)
        self.audit.write(
            request_id=request_id,
            agent=agent["id"],
            provider=provider_name,
            operation="placeholder-files",
            allowed=True,
            expires_at=expires_at,
            file_count=len(files),
        )
        return {"ok": True, "files": files, "hosts": hosts, "expires_at": expires_at}

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
        grant = self._injection_grant(paired, capability)
        provider, hosts = self._injection_provider(capability)
        if host not in hosts:
            raise ProviderError("host-not-allowed", f"host {host} is not allowed for {capability}", 403)
        headers, expires_at, strip = provider.injection_headers(host, method, path, paired["id"], self.audit, request_id, grant)
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
        provider, hosts = self._injection_provider(capability)
        self.audit.write(
            request_id=request_id,
            agent=identity["id"],
            paired_agent=subject["id"],
            provider=capability,
            operation="injection.routing",
            allowed=True,
        )
        response = {"ok": True, "hosts": hosts, "placeholder": INJECTION_PLACEHOLDER}
        # Non-secret routing hint: git-capable providers make runtime bootstrap
        # install the git redirect/trust wiring (protocol/injection.md).
        if getattr(provider, "injection_git", False):
            response["git"] = True
        return response

    def injection_report(self, request_id, payload, authorization):
        # Observability, not a security control (protocol/injection.md §Audit):
        # egressd reports each proxied request here so the broker's audit log
        # covers individual requests, not just per-fetch injection. Authorization
        # is role + pairing only — entries are NOT re-checked against grants: a
        # report for a just-revoked capability is still audit-worthy, and a
        # compromised egressd could spam granted capabilities regardless.
        identity = self.authenticate_role(authorization, "egress")
        paired = self.agents.by_id(identity.get("paired_agent") or "")
        if paired is None or paired.get("role", "agent") != "agent":
            raise ProviderError("pairing-invalid", "egress identity has no valid paired agent", 403)
        entries = payload.get("entries")
        if not isinstance(entries, list):
            raise ProviderError("entries-required", "entries must be a list", 400)
        if len(entries) > MAX_REPORT_ENTRIES:
            raise ProviderError(
                "entries-too-many",
                f"a report carries at most {MAX_REPORT_ENTRIES} entries",
                400,
            )
        records = [self._report_record(entry, index) for index, entry in enumerate(entries)]
        # Write only after every entry validated: a malformed batch is rejected
        # whole, never partially audited.
        for record in records:
            self.audit.write(
                request_id=request_id,
                agent=identity["id"],
                paired_agent=paired["id"],
                operation="injection.request",
                allowed=True,
                **record,
            )
        return {"ok": True, "reported": len(records)}

    def _report_record(self, entry, index):
        if not isinstance(entry, dict):
            raise ProviderError("entry-invalid", f"entries[{index}] must be an object", 400)
        capability = entry.get("capability")
        if not isinstance(capability, str) or not capability:
            raise ProviderError("entry-invalid", f"entries[{index}].capability is required", 400)
        host = entry.get("host")
        if not isinstance(host, str) or not host:
            raise ProviderError("entry-invalid", f"entries[{index}].host is required", 400)
        # Two shapes: a proxied HTTP request, or a forward-proxy CONNECT tunnel.
        # A `decision` key selects CONNECT; otherwise it is an HTTP request.
        if "decision" in entry:
            decision = entry.get("decision")
            if decision not in ("allow", "deny"):
                raise ProviderError("entry-invalid", f"entries[{index}].decision must be allow or deny", 400)
            port = entry.get("port")
            if not isinstance(port, int) or isinstance(port, bool) or port < 1 or port > 65535:
                raise ProviderError("entry-invalid", f"entries[{index}].port must be a valid port", 400)
            return {"provider": capability, "host": host, "port": port, "decision": decision}
        method = entry.get("method")
        if not isinstance(method, str) or not method:
            raise ProviderError("entry-invalid", f"entries[{index}].method is required", 400)
        path_class = entry.get("path_class")
        if not isinstance(path_class, str) or not path_class:
            raise ProviderError("entry-invalid", f"entries[{index}].path_class is required", 400)
        if not PATH_CLASS_RE.match(path_class):
            raise ProviderError(
                "entry-invalid",
                f"entries[{index}].path_class must match {PATH_CLASS_RE.pattern} (sanitized class, never a raw path)",
                400,
            )
        status = entry.get("status")
        if not isinstance(status, int) or isinstance(status, bool) or status < 0:
            raise ProviderError("entry-invalid", f"entries[{index}].status must be a non-negative integer", 400)
        return {
            "provider": capability,
            "host": host,
            "method": method.upper(),
            "path_class": path_class,
            "status": status,
        }

    def denied(self, request_id, payload, reason, message=None, authorization=None, operation=None):
        agent_id = None
        try:
            agent_id = self.agents.authenticate(authorization)["id"] if authorization else None
        except ProviderError:
            agent_id = None
        provider = None
        context = {}
        if isinstance(payload, dict):
            provider = payload.get("provider") or payload.get("capability")
            # Denied entries must carry the request context the caller named
            # (protocol/injection.md audit rules): denials are exactly the
            # paths where audit matters most.
            for key in ("host", "method", "path", "target"):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    context[key] = value
        self.audit.write(
            request_id=request_id,
            agent=agent_id,
            provider=provider if isinstance(provider, str) else None,
            operation=operation,
            allowed=False,
            reason=reason,
            **context,
        )
        return {"ok": False, "error": reason, "message": message or reason}


def string_field(payload, key):
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ProviderError(f"{key}-required")
    return value


def capped_files_expiry(provider_expires_at, bundle_ttl_seconds):
    if provider_expires_at is None:
        return None
    if bundle_ttl_seconds is None:
        return provider_expires_at
    provider_expiry = parse_rfc3339(provider_expires_at)
    bundle_expiry = datetime.fromtimestamp(int(time.time()) + bundle_ttl_seconds, timezone.utc)
    return format_rfc3339(min(provider_expiry, bundle_expiry))


def parse_rfc3339(value):
    if not isinstance(value, str) or not value:
        raise ProviderError("files-expiry-invalid", "provider file bundle expiry must be an RFC3339 string", 502)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as error:
        raise ProviderError("files-expiry-invalid", "provider file bundle expiry must be RFC3339", 502) from error


def format_rfc3339(value):
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def operation_from_path(path):
    if isinstance(path, str) and path.startswith("/v1/"):
        return path.removeprefix("/v1/").replace("/", ".")
    return None


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
                if self.path == "/v1/placeholder-files":
                    response = broker.placeholder_files(request_id, payload, self.headers.get("authorization"))
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
                if self.path == "/v1/injection/report":
                    response = broker.injection_report(request_id, payload, self.headers.get("authorization"))
                    self.write_json(200, response)
                    return
                self.write_json(404, {"ok": False, "error": "not-found"})
            except ProviderError as error:
                self.write_json(error.status, broker.denied(request_id, payload, error.reason, error.message, self.headers.get("authorization"), operation_from_path(self.path)))
            except Exception as error:
                self.write_json(500, broker.denied(request_id, payload, "internal-error", str(error), self.headers.get("authorization"), operation_from_path(self.path)))

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
