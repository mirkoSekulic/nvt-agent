#!/usr/bin/env python3
"""Trusted executable Azure provider. No credential-returning agent capabilities."""
import datetime
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time
from urllib.parse import parse_qsl, urlsplit

PROTOCOL = "nvt.broker-provider/v1"
LIMIT = 1024 * 1024
ARM = "management.azure.com"
LOGS = "api.loganalytics.io"
AUDIENCES = {ARM: "https://management.azure.com/", LOGS: "https://api.loganalytics.io"}
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
SEGMENT = r"[a-z0-9][a-z0-9_.()-]{0,127}"
# Reviewed type/version pairs, not arbitrary ARM GET authorization.
TYPES = {
    "microsoft.compute/virtualmachines": {"2025-11-01", "2025-04-01", "2024-11-01"},
    "microsoft.network/virtualnetworks": {"2025-07-01"},
    "microsoft.network/networkinterfaces": {"2023-11-01"},
    "microsoft.network/networksecuritygroups": {"2022-01-01"},
    "microsoft.network/publicipaddresses": {"2024-07-01"},
    "microsoft.containerservice/managedclusters": {"2026-05-01"},
    "microsoft.storage/storageaccounts": {"2025-08-01"},
    "microsoft.resources/deployments": {"2025-04-01"},
}
RESOURCE_VERSIONS = {"2024-11-01"}


class Failure(Exception):
    def __init__(self, reason="azure-config-invalid", status=400):
        self.reason, self.status = reason, status


def strings(value):
    if not isinstance(value, list) or not 0 < len(value) <= 256 or any(not isinstance(s, str) for s in value) or len(set(value)) != len(value):
        raise Failure()
    return value


def scope(value, tenant):
    if not isinstance(value, str) or len(value) > 2048:
        raise Failure()
    if value == "query-identity/" + tenant or re.fullmatch("workspace/" + UUID, value):
        return value
    if value.startswith("arm:"):
        path = value[4:]
        if re.fullmatch(r"/subscriptions/" + UUID + r"(?:/resourcegroups/" + SEGMENT + r"(?:/providers/[a-z.]+/" + SEGMENT + "/" + SEGMENT + ")?)?", path):
            return value
    raise Failure()


def policy(value):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {"defaultAction", "rules"} or value.get("defaultAction") not in {"allow", "deny"}:
        raise Failure()
    rules = value.get("rules", [])
    if not isinstance(rules, list) or len(rules) > 256:
        raise Failure()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {"operation", "resource"} or rule["operation"] not in {"observe", "mutate"} or not isinstance(rule["resource"], str) or not 0 < len(rule["resource"]) <= 4096 or any(c in rule["resource"] for c in "*\x00\r\n"):
            raise Failure()
    return value


def permits(value, operation, resource):
    return value is None or value["defaultAction"] == "allow" or {"operation": operation, "resource": resource} in value.get("rules", [])


class AzureCLITokenSource:
    """Replaceable trusted source; invokes only a fixed token command, never agent commands."""
    def __init__(self, directory, tenant, executable="/opt/nvt-azure/bin/python"):
        self.directory, self.tenant, self.executable = directory, tenant, executable

    def acquire(self, audience):
        if audience not in AUDIENCES.values():
            raise Failure("azure-audience-denied", 403)
        environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": self.directory,
                       "AZURE_CONFIG_DIR": self.directory, "AZURE_CORE_COLLECT_TELEMETRY": "false",
                       "AZURE_LOGGING_ENABLE_LOG_FILE": "false",
                       "AZURE_EXTENSION_USE_DYNAMIC_INSTALL": "no"}
        command = [self.executable, str(Path(__file__).with_name("token_source.py")), self.tenant, audience]
        try:
            with subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as child:
                try:
                    output = bytearray()
                    deadline = time.monotonic() + 30
                    with selectors.DefaultSelector() as selector:
                        selector.register(child.stdout, selectors.EVENT_READ)
                        while True:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0 or not selector.select(remaining):
                                raise Failure("azure-credentials-unavailable", 503)
                            chunk = os.read(child.stdout.fileno(), min(65536, LIMIT + 1 - len(output)))
                            if not chunk:
                                break
                            output.extend(chunk)
                            if len(output) > LIMIT:
                                raise Failure("azure-credentials-unavailable", 503)
                    if child.wait(timeout=max(0.01, deadline - time.monotonic())):
                        raise Failure("azure-credentials-unavailable", 503)
                    result = json.loads(output)
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.wait()
            expiry = result.get("expires_on")
            token = result.get("accessToken")
            if (result.get("tenant", "").lower() != self.tenant or result.get("tokenType") != "Bearer"
                    or not isinstance(expiry, (int, str)) or isinstance(expiry, bool)
                    or not isinstance(token, str) or not 0 < len(token) <= 65536
                    or any(ord(c) <= 32 or ord(c) > 126 for c in token)
                    or int(expiry) <= time.time() + 60):
                raise Failure("azure-credentials-unavailable", 503)
            return token, int(expiry)
        except (OSError, ValueError, TypeError, AttributeError, subprocess.SubprocessError):
            raise Failure("azure-credentials-unavailable", 503) from None


class AzureProvider:
    def __init__(self, params, source=None):
        config, allow = params.get("config"), params.get("allow")
        if not isinstance(config, dict) or not isinstance(allow, dict) or set(config) - {"tenant", "subscriptions", "state-dir", "cloud"} or set(allow) - {"resources", "authorization"}:
            raise Failure()
        self.tenant = config.get("tenant", "")
        if not re.fullmatch(UUID, self.tenant) or config.get("cloud", "AzureCloud") != "AzureCloud":
            raise Failure()
        self.subscriptions = strings(config.get("subscriptions"))
        if any(not re.fullmatch(UUID, s) for s in self.subscriptions):
            raise Failure()
        self.ceiling = self.scopes(allow.get("resources"))
        self.policy = policy(allow.get("authorization"))
        directory = config.get("state-dir")
        if not isinstance(directory, str) or not Path(directory).is_absolute():
            raise Failure()
        self.source = source or AzureCLITokenSource(directory, self.tenant)

    def scopes(self, values):
        result = [scope(s, self.tenant) for s in strings(values)]
        for item in result:
            if item.startswith("arm:") and item.split("/")[2] not in self.subscriptions:
                raise Failure()
        if any(s.startswith("workspace/") for s in result) and any(s.startswith("query-identity/") for s in result):
            raise Failure()
        return result

    def initialize_result(self):
        return {"protocol_version": PROTOCOL, "capabilities": ["injection.authorization", "injection.headers"],
                "injection_hosts": [ARM, LOGS], "injection_git": False, "bundle_ttl_seconds": None}

    def classify(self, params):
        host, method, raw = params.get("host"), params.get("method"), params.get("path")
        if host not in AUDIENCES or params.get("upgrade", False) is not False or not isinstance(raw, str) or not raw.startswith("/") or "#" in raw or re.search(r"%(?![0-9a-fA-F]{2})", raw) or len(raw) > 8192 or any(ord(c) < 32 or ord(c) > 126 for c in raw):
            return None
        parsed = urlsplit(raw)
        if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/"):
            return None
        path = parsed.path.lower()
        # This exact reviewed collection has a trailing slash in the pinned SDK.
        if re.fullmatch(r"/subscriptions/" + UUID + r"/resourcegroups/" + SEGMENT + r"/providers/microsoft.resources/deployments/", path):
            path = path[:-1]
        if "%" in path or "\\" in path or "//" in path or any(s in {".", "..", ""} for s in path[1:].split("/")):
            return None
        try:
            pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=32, errors="strict")
        except ValueError:
            return None
        if len({k.lower() for k, _ in pairs}) != len(pairs) or any(k != k.lower() or not v or any(ord(c) < 32 for c in v) for k, v in pairs):
            return None
        query = dict(pairs)
        if host == LOGS:
            if method == "POST" and not query and re.fullmatch("/v1/workspaces/" + UUID + "/query", path):
                # Deliberately the entire identity's RBAC query boundary. URL workspace
                # names, body workspaces, KQL workspace()/app() and stored functions
                # cannot prove a narrower boundary with this protocol.
                return "observe", "query-identity/" + self.tenant
            return None
        match = re.match(r"^/subscriptions/(" + UUID + r")(?=/|$)", path)
        if not match or match[1] not in self.subscriptions:
            return None
        version = query.pop("api-version", None)
        if not version:
            return None
        root = match[0]
        tail = path[len(root):]
        rg = re.match(r"/resourcegroups/" + SEGMENT + r"(?=/|$)", tail)
        base = root + (rg[0] if rg else "")
        rest = path[len(base):]
        if method == "GET" and version in RESOURCE_VERSIONS:
            if (tail == "/resourcegroups" or (rg and not rest)) and not query:
                return "observe", "arm:" + (root if tail == "/resourcegroups" else base)
            if rest == "/resources":
                # Generic resource list needs an exact reviewed type filter; $expand
                # and compound filters cannot broaden that reviewed type scope.
                filt = query.get("$filter", "")
                type_match = re.fullmatch(r"resourceType eq '([A-Za-z.]+/[A-Za-z]+)'", filt)
                expansion = query.get("$expand", "")
                if set(query) <= {"$filter", "$expand"} and type_match and type_match[1].lower() in TYPES and expansion in {"", "createdTime,changedTime,provisioningState"}:
                    return "observe", "arm:" + base
        resource_match = re.fullmatch(r"/providers/([a-z.]+)/(" + SEGMENT + r")(?:/(" + SEGMENT + r"))?(?:/(instanceview|start|restart|deallocate))?", rest)
        if resource_match:
            kind = resource_match[1] + "/" + resource_match[2]
            name, action = resource_match[3], resource_match[4]
            target = base + "/providers/" + kind + ("/" + name if name else "")
            # A list is scoped to the parent, not a fictional individual resource.
            target_scope = "arm:" + (target if name else base)
            if kind == "microsoft.compute/virtualmachines" and name and method == "GET" and query == {"$expand": "instanceView"}:
                query = {}
            if version not in TYPES.get(kind, set()) or query:
                return None
            if method == "GET" and (not action or (action == "instanceview" and name and kind == "microsoft.compute/virtualmachines")):
                return "observe", target_scope
            if name and ((method == "DELETE" and not action) or (method == "POST" and action in {"start", "restart", "deallocate"} and kind == "microsoft.compute/virtualmachines")):
                return "mutate", target_scope
        # Metrics are read-only; authorize their parent resource independently.
        suffix = "/providers/microsoft.insights/metrics"
        if method == "GET" and path.endswith(suffix) and version == "2018-01-01":
            parent = path[:-len(suffix)]
            parent_match = re.fullmatch(r"/subscriptions/" + UUID + r"/resourcegroups/" + SEGMENT + r"/providers/([a-z.]+/" + SEGMENT + r")/" + SEGMENT, parent)
            if parent_match and parent_match[1] in TYPES and set(query) <= {"timespan", "interval", "metricnames", "aggregation", "top", "orderby", "$filter", "resulttype", "metricnamespace", "autoadjusttimegrain", "validatedimensions", "rollupby"}:
                return "observe", "arm:" + parent
        if method == "GET" and tail == "/providers/microsoft.insights/eventtypes/management/values" and version == "2015-04-01" and set(query) <= {"$filter", "$select"}:
            # Filters can select other resources in this subscription: require the
            # subscription grant rather than trusting a user-supplied OData filter.
            return "observe", "arm:" + root
        return None

    @staticmethod
    def covers(allowed, requested):
        return allowed == requested or (allowed.startswith("arm:") and requested.startswith(allowed + "/"))

    def injection_authorization(self, params):
        denied = {"allowed": False, "operation": "unclassified", "resource": "azure/unclassified"}
        try:
            grant = params.get("grant")
            if not isinstance(grant, dict) or grant.get("materialization") != "header-inject":
                return denied
            granted = self.scopes(grant.get("resources"))
            grant_policy = policy(grant.get("authorization"))
            classified = self.classify(params)
            if not classified:
                return denied
            operation, target = classified
            ceiling = [s for s in self.ceiling if self.covers(s, target) and permits(self.policy, operation, "azure/" + s)]
            selected = [s for s in granted if self.covers(s, target) and permits(grant_policy, operation, "azure/" + s)]
            return {"allowed": bool(ceiling and selected), "operation": operation,
                    "resource": "azure/" + (sorted(selected)[0] if selected else "out-of-scope")}
        except (Failure, ValueError, TypeError):
            return denied

    def injection_headers(self, params):
        # Core always calls authorization with the full URI first. Materialization
        # intentionally retains the path-only protocol; never reclassify it here.
        host = params.get("host")
        if host not in AUDIENCES:
            raise Failure("azure-audience-denied", 403)
        token, expiry = self.source.acquire(AUDIENCES[host])
        if expiry <= time.time() + 60:
            raise Failure("azure-credentials-unavailable", 503)
        # Do not retain a second provider token cache. CLI/MSAL refreshes privately;
        # the existing egress cache is capped at 60 seconds and expiry minus slack.
        expires = datetime.datetime.fromtimestamp(min(expiry - 60, time.time() + 60), datetime.timezone.utc)
        return {"headers": {"authorization": "Bearer " + token}, "expires_at": expires.isoformat(),
                "strip_request_headers": ["authorization", "x-ms-authorization-auxiliary"]}


def main():
    provider = None
    while True:
        line = sys.stdin.buffer.readline(LIMIT + 1)
        if not line:
            return
        if len(line) > LIMIT or not line.endswith(b"\n"):
            return
        request = {}
        try:
            request = json.loads(line)
            method, params = request["method"], request.get("params", {})
            if method == "initialize" and provider is None and params.get("protocol_version") == PROTOCOL:
                provider = AzureProvider(params)
                result = provider.initialize_result()
            elif method == "shutdown":
                return
            elif provider and method == "injection.authorization":
                result = provider.injection_authorization(params)
            elif provider and method == "injection.headers":
                result = provider.injection_headers(params)
            else:
                raise Failure("azure-operation-unsupported", 403)
            response = {"jsonrpc": "2.0", "id": request.get("id"), "result": result}
        except Exception as error:
            reason, status = (error.reason, error.status) if isinstance(error, Failure) else ("azure-provider-unavailable", 503)
            response = {"jsonrpc": "2.0", "id": request.get("id") if isinstance(request, dict) else None,
                        "error": {"code": -32000, "message": "provider error", "data": {"reason": reason, "status": status}}}
        print(json.dumps(response, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
