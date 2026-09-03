#!/usr/bin/env python3
"""Generic trusted kubeconfig executable provider.

The process owns the private kubeconfig and credential-helper state.  Its only
agent-visible result is a sanitized kubeconfig and public route trust metadata;
bearer credentials are returned solely by injection.headers.
"""

import base64
import binascii
import datetime
import hashlib
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
import threading
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import yaml


PROTOCOL = "nvt.broker-provider/v1"
MAX_CONTEXTS = 512
MAX_HELPER_OUTPUT = 1024 * 1024
MAX_NO_EXPIRY_CACHE_SECONDS = 60
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SAFE_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]*$")
SAFE_QUERY_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9.-]*$")


class ProviderFailure(Exception):
    def __init__(self, reason, status=400, message=None):
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.message = message


class CredentialExecutor:
    """Replaceable trusted-side helper execution seam."""

    def execute(self, command, environment, cwd, timeout):
        raise NotImplementedError


class SubprocessCredentialExecutor(CredentialExecutor):
    def execute(self, command, environment, cwd, timeout):
        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ProviderFailure("credential-helper-failed", 503) from error
        if completed.returncode != 0 or len(completed.stdout) > MAX_HELPER_OUTPUT:
            raise ProviderFailure("credential-helper-failed", 503)
        return completed.stdout


class KubeconfigProvider:
    def __init__(self, params, executor=None):
        self.instance = required_string(params, "provider_instance_name")
        config = required_object(params, "config")
        allow = params.get("allow") or {}
        if not isinstance(allow, dict) or "resources" not in allow:
            raise ProviderFailure("provider-config-invalid")
        if set(allow) - {"resources", "authorization"}:
            raise ProviderFailure("provider-config-invalid")
        self.allowed_ceiling = string_list(allow.get("resources", []), "allow.resources", MAX_CONTEXTS)
        self.allowed_ceiling = set(self.allowed_ceiling)
        self.operation_authorization = operation_policy(allow.get("authorization"), "allow.authorization")
        kubeconfig_path = Path(required_string(config, "private-kubeconfig"))
        self.state_dir = Path(required_string(config, "state-dir"))
        self.helper_allowlist = set(string_list(config.get("helper-allowlist", []), "helper-allowlist", 64))
        self.helper_timeout = positive_number(config.get("helper-timeout-seconds", 30), "helper-timeout-seconds")
        self.helper_environment = self._helper_environment(config.get("helper-environment", []))
        self.executor = executor or SubprocessCredentialExecutor()
        self.lock = threading.Lock()
        self.token_cache = {}
        self._prepare_state()
        self.document = self._load_document(kubeconfig_path)
        self.contexts, self.clusters, self.users = self._index_document(self.document)
        unknown = self.allowed_ceiling - set(self.contexts)
        if unknown:
            raise ProviderFailure("provider-config-invalid", message="allowed kubeconfig context is unavailable")
        published = sorted(self.allowed_ceiling)
        if not published or len(published) > MAX_CONTEXTS:
            raise ProviderFailure("provider-config-invalid")
        self.routes = {}
        self.context_hosts = {}
        self._build_routes(published, kubeconfig_path.parent)

    def _prepare_state(self):
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = self.state_dir.stat()
        if not stat.S_ISDIR(info.st_mode):
            raise ProviderFailure("provider-config-invalid")
        os.chmod(self.state_dir, 0o700)

    def _helper_environment(self, raw):
        entries = raw or []
        if not isinstance(entries, list) or len(entries) > 64:
            raise ProviderFailure("provider-config-invalid")
        result = {}
        for item in entries:
            if not isinstance(item, dict) or set(item) != {"name", "value"}:
                raise ProviderFailure("provider-config-invalid")
            name, value = item.get("name"), item.get("value")
            if not isinstance(name, str) or not ENV_NAME.fullmatch(name) or not isinstance(value, str):
                raise ProviderFailure("provider-config-invalid")
            if value == "state:":
                value = str(self.state_dir)
            elif value.startswith("state:"):
                relative = value.removeprefix("state:")
                if not safe_relative(relative):
                    raise ProviderFailure("provider-config-invalid")
                value = str(self.state_dir / relative)
            result[name] = value
        return result

    @staticmethod
    def _load_document(path):
        try:
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_HELPER_OUTPUT:
                raise ProviderFailure("provider-config-invalid")
            with path.open("r", encoding="utf-8") as stream:
                value = yaml.safe_load(stream)
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            raise ProviderFailure("provider-config-invalid") from error
        if not isinstance(value, dict) or value.get("apiVersion") != "v1" or value.get("kind") != "Config":
            raise ProviderFailure("provider-config-invalid")
        return value

    @staticmethod
    def _index_document(document):
        def named(items, field):
            if not isinstance(items, list) or len(items) > MAX_CONTEXTS:
                raise ProviderFailure("provider-config-invalid")
            output = {}
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get(field), dict):
                    raise ProviderFailure("provider-config-invalid")
                if item["name"] in output:
                    raise ProviderFailure("provider-config-invalid")
                output[item["name"]] = item[field]
            return output

        return named(document.get("contexts"), "context"), named(document.get("clusters"), "cluster"), named(document.get("users"), "user")

    def _build_routes(self, published, base_dir):
        cluster_users = {}
        for context_name in published:
            context = self.contexts[context_name]
            cluster_name = required_string(context, "cluster")
            user_name = required_string(context, "user")
            if cluster_name not in self.clusters or user_name not in self.users:
                raise ProviderFailure("provider-config-invalid")
            previous = cluster_users.setdefault(cluster_name, user_name)
            if previous != user_name:
                raise ProviderFailure(
                    "provider-config-invalid",
                    message="one kubeconfig cluster name cannot select multiple auth-info identities",
                )
        first_context = {}
        for context_name in published:
            cluster_name = self.contexts[context_name]["cluster"]
            first_context.setdefault(cluster_name, context_name)
        for cluster_name, context_name in first_context.items():
            context = self.contexts[context_name]
            user_name = context["user"]
            host = route_host(self.instance, context_name)
            upstream, server_name, ca_pem = parse_cluster(self.clusters[cluster_name], base_dir)
            route = {
                "id": context_name,
                "host": host,
                "upstream": upstream,
                "server_name": server_name,
                "ca_pem": ca_pem,
                "allow_private_upstream": True,
                "user": user_name,
                "cluster": cluster_name,
            }
            self.routes[host] = route
            for candidate in published:
                if self.contexts[candidate]["cluster"] == cluster_name:
                    candidate_host = route_host(self.instance, candidate)
                    self.context_hosts[candidate] = host
                    self.routes[candidate_host] = {**route, "id": candidate, "host": candidate_host}

    def initialize_result(self):
        return {
            "protocol_version": PROTOCOL,
            "capabilities": ["catalog", "injection.authorization", "injection.headers"],
            "injection_hosts": sorted(self.routes),
            "injection_git": False,
            "bundle_ttl_seconds": None,
        }

    def effective_contexts(self, grant):
        if not isinstance(grant, dict):
            raise ProviderFailure("grant-invalid", 403)
        requested = string_list(grant.get("resources", []), "grant.resources", MAX_CONTEXTS)
        if not requested:
            raise ProviderFailure("resource-not-granted", 403)
        result = set(requested)
        if not result.issubset(self.allowed_ceiling) or not result.issubset(self.contexts):
            raise ProviderFailure("resource-not-granted", 403)
        return sorted(result)

    def catalog(self, params):
        contexts = self.effective_contexts(params.get("grant"))
        selected_clusters = []
        selected_users = []
        cluster_seen = set()
        user_seen = set()
        context_entries = []
        routes = []
        route_seen = set()
        for name in contexts:
            source = self.contexts[name]
            cluster_name, user_name = source["cluster"], source["user"]
            if cluster_name not in cluster_seen:
                cluster_seen.add(cluster_name)
                selected_clusters.append({"name": cluster_name, "cluster": {"server": "https://" + route_host(self.instance, name)}})
            if user_name not in user_seen:
                user_seen.add(user_name)
                selected_users.append({"name": user_name, "user": {}})
            clean_context = {"cluster": cluster_name, "user": user_name}
            namespace = source.get("namespace")
            if isinstance(namespace, str) and namespace:
                clean_context["namespace"] = namespace
            context_entries.append({"name": name, "context": clean_context})
            host = route_host(self.instance, name)
            if host not in route_seen:
                route_seen.add(host)
                route = self.routes[host]
                routes.append({key: route[key] for key in ("id", "host", "upstream", "server_name", "ca_pem", "allow_private_upstream")})
        current = self.document.get("current-context")
        if current not in contexts:
            current = contexts[0]
        sanitized = {
            "apiVersion": "v1",
            "kind": "Config",
            "preferences": {},
            "clusters": selected_clusters,
            "users": selected_users,
            "contexts": context_entries,
            "current-context": current,
        }
        content = yaml.safe_dump(sanitized, sort_keys=False)
        return {
            "files": [{"path": ".kube/config", "content": content, "mode": "0600"}],
            "routes": routes,
            "expires_at": None,
        }

    def injection_headers(self, params):
        host = required_string(params, "host")
        route = self.routes.get(host)
        if route is None:
            raise ProviderFailure("host-not-allowed", 403)
        granted = self.effective_contexts(params.get("grant"))
        if route["id"] not in granted:
            raise ProviderFailure("resource-not-granted", 403)
        token, expires_at = self._token(route["user"], route["cluster"])
        return {
            "headers": {"authorization": "Bearer " + token},
            "expires_at": expires_at,
            "strip_request_headers": ["authorization", "proxy-authorization"],
        }

    def injection_authorization(self, params):
        host = required_string(params, "host")
        method = required_string(params, "method").upper()
        path = required_string(params, "path")
        upgrade = params.get("upgrade", False)
        if not isinstance(upgrade, bool):
            raise ProviderFailure("provider-request-invalid")
        route = self.routes.get(host)
        if route is None:
            raise ProviderFailure("host-not-allowed", 403)
        grant = params.get("grant")
        granted = self.effective_contexts(grant)
        if route["id"] not in granted:
            raise ProviderFailure("resource-not-granted", 403)
        grant_policy = operation_policy((grant or {}).get("authorization"), "grant.authorization", status=403)
        resource = "context/" + route["id"]
        if self.operation_authorization is None and grant_policy is None:
            # Preserve the pre-policy behavior exactly. Negotiating the
            # capability lets a later grant opt in without making unrestricted
            # grants subject to the classifier.
            return {"allowed": True, "operation": "unrestricted", "resource": resource}
        try:
            classify_kubernetes_observation(method, path, upgrade)
        except ProviderFailure as error:
            if error.reason != "operation-unclassified":
                raise
            return {"allowed": False, "operation": "unclassified", "resource": resource}
        allowed = policy_allows(self.operation_authorization, "observe", resource)
        allowed = allowed and policy_allows(grant_policy, "observe", resource)
        return {"allowed": allowed, "operation": "observe", "resource": resource}

    def _token(self, user_name, cluster_name):
        user = self.users[user_name]
        forbidden = {
            "client-certificate", "client-certificate-data", "client-key", "client-key-data",
            "username", "password", "auth-provider",
        }
        if forbidden.intersection(user):
            raise ProviderFailure("unsupported-kubeconfig-auth", 403)
        if isinstance(user.get("token"), str) and user["token"]:
            if set(user) - {"token"}:
                raise ProviderFailure("unsupported-kubeconfig-auth", 403)
            return user["token"], None
        exec_config = user.get("exec")
        if not isinstance(exec_config, dict) or set(user) != {"exec"}:
            raise ProviderFailure("unsupported-kubeconfig-auth", 403)
        now = datetime.datetime.now(datetime.timezone.utc)
        with self.lock:
            cache_key = (user_name, cluster_name)
            cached = self.token_cache.get(cache_key)
            if cached and (
                cached[1] is not None and now < cached[1] - datetime.timedelta(seconds=60)
                or cached[1] is None and now < cached[2] + datetime.timedelta(seconds=MAX_NO_EXPIRY_CACHE_SECONDS)
            ):
                return cached[0], format_expiry(cached[1])
            token, expiry = self._exec_credential(exec_config, cluster_name)
            if len(self.token_cache) >= MAX_CONTEXTS:
                self.token_cache.clear()
            self.token_cache[cache_key] = (token, expiry, now)
            return token, format_expiry(expiry)

    def _exec_credential(self, config, cluster_name):
        allowed_keys = {"apiVersion", "command", "args", "env", "interactiveMode", "provideClusterInfo", "installHint"}
        if set(config) - allowed_keys:
            raise ProviderFailure("unsupported-kubeconfig-auth", 403)
        api_version = config.get("apiVersion")
        if api_version not in ("client.authentication.k8s.io/v1", "client.authentication.k8s.io/v1beta1"):
            raise ProviderFailure("unsupported-kubeconfig-auth", 403)
        if config.get("interactiveMode") not in (None, "Never") or not isinstance(config.get("provideClusterInfo", False), bool):
            raise ProviderFailure("unsupported-kubeconfig-auth", 403)
        command = required_string(config, "command")
        # Absolute or relative paths must be allowlisted verbatim.  A basename
        # entry authorizes only the corresponding PATH lookup, not an arbitrary
        # attacker-chosen executable that happens to share that basename.
        if command not in self.helper_allowlist:
            raise ProviderFailure("credential-helper-not-allowed", 403)
        helper_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        executable = command if Path(command).is_absolute() else shutil.which(command, path=helper_path)
        if not executable:
            raise ProviderFailure("credential-helper-unavailable", 503)
        args = string_list(config.get("args", []), "exec.args", 256)
        environment = {
            "PATH": helper_path,
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
            "HOME": str(self.state_dir),
            **self.helper_environment,
        }
        for item in config.get("env", []) or []:
            if not isinstance(item, dict) or set(item) != {"name", "value"} or not ENV_NAME.fullmatch(str(item.get("name", ""))) or not isinstance(item.get("value"), str):
                raise ProviderFailure("unsupported-kubeconfig-auth", 403)
            if item["name"] in {"HOME", "PATH", "KUBERNETES_EXEC_INFO"} or item["name"].startswith("NVT_"):
                raise ProviderFailure("unsupported-kubeconfig-auth", 403)
            environment[item["name"]] = item["value"]
        spec = {"interactive": False}
        if config.get("provideClusterInfo", False):
            cluster = self.clusters[cluster_name]
            cluster_info = {"server": cluster["server"]}
            if cluster.get("tls-server-name"):
                cluster_info["tls-server-name"] = cluster["tls-server-name"]
            # Route construction already resolved and validated CA files; use
            # the frozen public PEM rather than a provider-private path.
            for route in self.routes.values():
                if route["cluster"] == cluster_name:
                    cluster_info["certificate-authority-data"] = base64.b64encode(route["ca_pem"].encode()).decode()
                    break
            spec["cluster"] = cluster_info
        environment["KUBERNETES_EXEC_INFO"] = json.dumps({"apiVersion": api_version, "kind": "ExecCredential", "spec": spec})
        raw = self.executor.execute([executable, *args], environment, str(self.state_dir), self.helper_timeout)
        try:
            result = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ProviderFailure("credential-helper-invalid", 502) from error
        if not isinstance(result, dict) or result.get("kind") != "ExecCredential" or result.get("apiVersion") not in (
            "client.authentication.k8s.io/v1", "client.authentication.k8s.io/v1beta1"
        ):
            raise ProviderFailure("credential-helper-invalid", 502)
        status = result.get("status")
        if not isinstance(status, dict) or status.get("clientCertificateData") or status.get("clientKeyData"):
            raise ProviderFailure("unsupported-kubeconfig-auth", 403)
        token = status.get("token")
        if not isinstance(token, str) or not token:
            raise ProviderFailure("credential-helper-invalid", 502)
        expiry = None
        if status.get("expirationTimestamp") is not None:
            try:
                expiry = datetime.datetime.fromisoformat(status["expirationTimestamp"].replace("Z", "+00:00")).astimezone(datetime.timezone.utc)
            except (AttributeError, ValueError) as error:
                raise ProviderFailure("credential-helper-invalid", 502) from error
            if expiry <= datetime.datetime.now(datetime.timezone.utc):
                raise ProviderFailure("credential-expired", 503)
        return token, expiry


def route_host(instance, context):
    digest = hashlib.sha256((instance + "\0" + context).encode()).hexdigest()[:20]
    return "k-" + digest + ".kube.nvt.invalid"


def operation_policy(value, field, status=400):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {"defaultAction", "rules"}:
        raise ProviderFailure("provider-config-invalid" if status == 400 else "grant-invalid", status)
    default = value.get("defaultAction", "deny")
    rules = value.get("rules", [])
    if default not in ("allow", "deny") or not isinstance(rules, list) or len(rules) > 256:
        raise ProviderFailure("provider-config-invalid" if status == 400 else "grant-invalid", status)
    normalized = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {"operation", "resource"}:
            raise ProviderFailure("provider-config-invalid" if status == 400 else "grant-invalid", status)
        operation, resource = rule.get("operation"), rule.get("resource")
        if (not isinstance(operation, str) or not operation or len(operation.encode()) > 4096 or
                not isinstance(resource, str) or not resource or len(resource.encode()) > 8192):
            raise ProviderFailure("provider-config-invalid" if status == 400 else "grant-invalid", status)
        normalized.add((operation, resource))
    return default, frozenset(normalized)


def policy_allows(policy, operation, resource):
    if policy is None:
        return True
    default, rules = policy
    return default == "allow" or (operation, resource) in rules


def classify_kubernetes_observation(method, raw_path, upgrade=False):
    """Fail closed unless this is one canonical Kubernetes observation request."""
    if (method != "GET" or upgrade or len(raw_path.encode()) > 8192 or
            raw_path.count("?") > 1 or raw_path.endswith("?")):
        raise ProviderFailure("operation-unclassified", 403)
    parsed = urlsplit(raw_path)
    path = parsed.path
    if (parsed.scheme or parsed.netloc or parsed.fragment or not path.startswith("/") or
            "\\" in path or "%" in path or "//" in path):
        raise ProviderFailure("operation-unclassified", 403)
    segments = path.split("/")[1:]
    if any(not segment or segment in (".", "..") or not SAFE_PATH_SEGMENT.fullmatch(segment) for segment in segments):
        raise ProviderFailure("operation-unclassified", 403)
    validate_canonical_query(parsed.query)

    # Non-resource endpoints used for discovery, client negotiation, and
    # ordinary health checks. The openapi v3 suffix is server-published public
    # schema data and contains only already-canonical path segments.
    if path in ("/api", "/apis", "/version", "/openapi/v2", "/openapi/v3"):
        return
    if segments[0] in ("healthz", "livez", "readyz"):
        return
    if segments[:2] == ["openapi", "v3"] and len(segments) > 2:
        return

    tail = None
    core_api = False
    if len(segments) >= 2 and segments[0] == "api":
        core_api = True
        if len(segments) == 2:  # /api/v1 discovery
            return
        tail = segments[2:]
    elif len(segments) >= 3 and segments[0] == "apis":
        if len(segments) == 3:  # /apis/<group>/<version> discovery
            return
        tail = segments[3:]
    if not tail:
        raise ProviderFailure("operation-unclassified", 403)
    if tail[0] == "proxy":
        raise ProviderFailure("operation-unclassified", 403)
    if tail[0] == "watch":
        tail = tail[1:]
        if not tail:
            raise ProviderFailure("operation-unclassified", 403)

    # Kubernetes resource URLs have either a cluster-scoped tail
    # resource[/name[/subresource]], or a namespaced tail
    # namespaces/<namespace>/resource[/name[/subresource]]. The namespaces
    # resource itself uses the former shape.
    if tail[0] == "namespaces" and len(tail) >= 3:
        resource_name = tail[2]
        remainder = tail[3:]
    else:
        resource_name = tail[0]
        remainder = tail[1:]
    if len(remainder) > 2:
        raise ProviderFailure("operation-unclassified", 403)
    subresource = remainder[1] if len(remainder) == 2 else None
    if core_api and resource_name == "secrets":
        raise ProviderFailure("operation-unclassified", 403)
    if subresource is not None and subresource not in ("status", "scale", "log"):
        raise ProviderFailure("operation-unclassified", 403)
    if subresource == "log" and resource_name != "pods":
        raise ProviderFailure("operation-unclassified", 403)


def validate_canonical_query(query):
    if not query:
        return
    if re.fullmatch(r"(?:[^%]|%[0-9A-Fa-f]{2})*", query) is None:
        raise ProviderFailure("operation-unclassified", 403)
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True, max_num_fields=64)
    except ValueError as error:
        raise ProviderFailure("operation-unclassified", 403) from error
    if not pairs or len({key for key, _ in pairs}) != len(pairs):
        raise ProviderFailure("operation-unclassified", 403)
    for key, value in pairs:
        if not SAFE_QUERY_KEY.fullmatch(key) or any(character in value for character in "\x00\r\n"):
            raise ProviderFailure("operation-unclassified", 403)


def parse_cluster(cluster, base_dir):
    server = required_string(cluster, "server")
    parsed = urlsplit(server)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ProviderFailure("provider-config-invalid")
    if cluster.get("insecure-skip-tls-verify"):
        raise ProviderFailure("provider-config-invalid")
    if isinstance(cluster.get("certificate-authority-data"), str) and cluster["certificate-authority-data"]:
        try:
            ca_bytes = base64.b64decode(cluster["certificate-authority-data"], validate=True)
        except ValueError as error:
            raise ProviderFailure("provider-config-invalid") from error
    elif isinstance(cluster.get("certificate-authority"), str) and cluster["certificate-authority"]:
        path = Path(cluster["certificate-authority"])
        if not path.is_absolute():
            path = base_dir / path
        try:
            ca_bytes = path.read_bytes()
        except OSError as error:
            raise ProviderFailure("provider-config-invalid") from error
    else:
        raise ProviderFailure("provider-config-invalid", message="kubeconfig cluster must pin certificate authority data")
    ca_pem = certificates_only_pem(ca_bytes)
    port = parsed.port or 443
    if ":" in parsed.hostname:
        upstream = f"[{parsed.hostname}]:{port}"
    else:
        upstream = parsed.hostname if port == 443 else f"{parsed.hostname}:{port}"
    server_name = cluster.get("tls-server-name") or parsed.hostname
    if not isinstance(server_name, str) or not server_name or any(character in server_name for character in "/\\@?# \t\r\n"):
        raise ProviderFailure("provider-config-invalid")
    return upstream, server_name, ca_pem


def certificates_only_pem(value):
    if len(value) == 0 or len(value) > 256 * 1024:
        raise ProviderFailure("provider-config-invalid")
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    position = 0
    certificates = []
    while position < len(value):
        while position < len(value) and value[position] in b" \t\r\n":
            position += 1
        if position == len(value):
            break
        if not value.startswith(begin, position):
            raise ProviderFailure("provider-config-invalid")
        body_start = position + len(begin)
        body_end = value.find(end, body_start)
        if body_end < 0:
            raise ProviderFailure("provider-config-invalid")
        encoded = b"".join(value[body_start:body_end].split())
        try:
            der = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ProviderFailure("provider-config-invalid") from error
        if not der:
            raise ProviderFailure("provider-config-invalid")
        canonical = base64.b64encode(der).decode("ascii")
        lines = [canonical[index:index + 64] for index in range(0, len(canonical), 64)]
        certificates.append(begin.decode("ascii") + "\n" + "\n".join(lines) + "\n" + end.decode("ascii") + "\n")
        position = body_end + len(end)
    if not certificates:
        raise ProviderFailure("provider-config-invalid")
    result = "".join(certificates)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=result)
    except ssl.SSLError as error:
        raise ProviderFailure("provider-config-invalid") from error
    return result


def required_object(value, key):
    result = value.get(key)
    if not isinstance(result, dict):
        raise ProviderFailure("provider-config-invalid")
    return result


def required_string(value, key):
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise ProviderFailure("provider-config-invalid")
    return result


def string_list(value, field, maximum):
    if not isinstance(value, list) or len(value) > maximum or any(not isinstance(item, str) or not item for item in value) or len(set(value)) != len(value):
        raise ProviderFailure("provider-config-invalid", message=field + " is invalid")
    return list(value)


def positive_number(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0 or value > 300:
        raise ProviderFailure("provider-config-invalid", message=field + " is invalid")
    return value


def safe_relative(value):
    path = Path(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts


def format_expiry(value):
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z") if value else None


def response(request_id, result=None, error=None):
    value = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        data = {"reason": error.reason, "status": error.status}
        if error.message:
            data["message"] = error.message
        value["error"] = {"code": -32000, "message": "provider error", "data": data}
    else:
        value["result"] = result
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main():
    provider = None
    for raw in sys.stdin:
        request_id = None
        try:
            request = json.loads(raw)
            request_id = request.get("id")
            method = request.get("method")
            params = request.get("params")
            if not isinstance(request_id, str) or not isinstance(params, dict):
                raise ProviderFailure("provider-request-invalid")
            if method == "initialize":
                if provider is not None or params.get("protocol_version") != PROTOCOL:
                    raise ProviderFailure("provider-request-invalid")
                provider = KubeconfigProvider(params)
                result = provider.initialize_result()
            elif provider is None:
                raise ProviderFailure("provider-unavailable", 503)
            elif method == "catalog":
                result = provider.catalog(params)
            elif method == "injection.authorization":
                result = provider.injection_authorization(params)
            elif method == "injection.headers":
                result = provider.injection_headers(params)
            elif method == "shutdown":
                response(request_id, {})
                return
            else:
                raise ProviderFailure("operation-not-supported", 403)
            response(request_id, result)
        except ProviderFailure as error:
            response(request_id or "invalid", error=error)
        except Exception:
            response(request_id or "invalid", error=ProviderFailure("provider-internal-error", 500))


if __name__ == "__main__":
    main()
