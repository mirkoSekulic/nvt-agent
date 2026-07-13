"""Supervision and validation for trusted executable broker providers."""

import json
import os
import subprocess
import threading
import time
import uuid
import re
from dataclasses import dataclass

from broker.core.config import BrokerConfigError
from broker.core.errors import ProviderError


PROTOCOL_VERSION = "nvt.broker-provider/v1"
MAX_PROTOCOL_LINE_BYTES = 1024 * 1024
MAX_PENDING_REQUESTS = 128
MAX_TEXT_LENGTH = 4096
MAX_TARGET_LENGTH = 8192
CAPABILITIES = {
    "http.request",
    "token",
    "identity",
    "headers",
    "files",
    "placeholder-files",
    "injection.headers",
}
SAFE_ENVIRONMENT = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
}


@dataclass(frozen=True)
class ExecutableTarget:
    value: str
    audit_target: str


class _Pending:
    def __init__(self):
        self.event = threading.Event()
        self.response = None
        self.error = None


class ExecutableProviderAdapter:
    """One long-lived, correlated JSON-RPC process for one provider instance."""

    def __init__(self, entry, plugin):
        self._name = entry["name"]
        self._plugin_name = plugin["name"]
        self._entry = entry
        self._plugin = plugin
        self._lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._pending = {}
        self._process = None
        self._generation = 0
        self._closing = False
        self._ready = False
        self._restart_thread = None
        self._restart_delay = 0.1
        self._restart_requested = False
        self._capabilities = set()
        self._injection_hosts = []
        self._injection_git = False
        self._bundle_ttl_seconds = None
        self._configured_config = self._config_object()
        self._configured_allow = self._allow_object()
        try:
            self._start(initial=True)
        except Exception:
            self.close()
            raise

    @property
    def name(self):
        return self._name

    @property
    def ready(self):
        with self._lock:
            return self._ready

    @property
    def external(self):
        return True

    @property
    def injection_hosts(self):
        return list(self._injection_hosts)

    @property
    def injection_git(self):
        return self._injection_git

    @property
    def bundle_ttl_seconds(self):
        return self._bundle_ttl_seconds

    def supports(self, capability):
        if capability == "injection":
            return "injection.headers" in self._capabilities and bool(self._injection_hosts)
        return capability in self._capabilities

    def normalize_target(self, target):
        result = self._request("target.normalize", {"target": target})
        return self._target_result(result)

    def target_from_repo(self, repo):
        if not isinstance(repo, ExecutableTarget):
            raise ProviderError("provider-protocol-error", "provider returned an invalid target", 502)
        return repo.audit_target

    def http_request(self, method, url, headers, paginate, effective_repositories):
        self._ensure_capability("http.request")
        result = self._request("http.request", {
            "method": method,
            "url": url,
            "headers": headers,
            "paginate": paginate,
            "effective_repositories": effective_repositories,
        })
        result = self._object(result, "http.request result")
        audit_target = self._audit_target(result.pop("audit_target", None))
        self._require_keys(result, {"status", "headers", "body"}, "http.request result")
        if not isinstance(result["status"], int) or isinstance(result["status"], bool) or not 100 <= result["status"] <= 599:
            self._protocol_error("http.request status is invalid")
        self._string_map(result["headers"], "http.request headers")
        if not isinstance(result["body"], str) or len(result["body"].encode("utf-8")) > MAX_PROTOCOL_LINE_BYTES:
            self._protocol_error("http.request body is invalid")
        return result, ExecutableTarget("", audit_target)

    def token_for_repo(self, repo, effective_repositories):
        self._ensure_capability("token")
        result = self._operation_for_target("token", repo, effective_repositories)
        self._require_keys(result, {"token", "expires_at"}, "token result")
        self._bounded_string(result["token"], "token result token", MAX_PROTOCOL_LINE_BYTES)
        self._optional_string(result["expires_at"], "token result expires_at")
        return result["token"], result["expires_at"]

    def identity_for_repo(self, repo, effective_repositories):
        self._ensure_capability("identity")
        result = self._operation_for_target("identity", repo, effective_repositories)
        self._require_keys(result, {"name", "email"}, "identity result")
        self._bounded_string(result["name"], "identity result name", MAX_TEXT_LENGTH)
        self._bounded_string(result["email"], "identity result email", MAX_TEXT_LENGTH)
        return result

    def headers_for_repo(self, repo, effective_repositories):
        self._ensure_capability("headers")
        result = self._operation_for_target("headers", repo, effective_repositories)
        self._require_keys(result, {"headers"}, "headers result")
        self._string_list(result["headers"], "headers result headers")
        return result["headers"]

    def files(self, agent_id, audit, request_id):
        self._ensure_capability("files")
        result = self._request("files", {"agent_id": agent_id, "request_id": request_id})
        result = self._object(result, "files result")
        self._require_keys(result, {"files", "expires_at"}, "files result")
        self._file_list(result["files"], "files result files", path_key="name")
        self._optional_string(result["expires_at"], "files result expires_at")
        return result["files"], result["expires_at"]

    def placeholder_files(self, agent_id, audit, request_id, grant):
        self._ensure_capability("placeholder-files")
        result = self._request("placeholder-files", {
            "agent_id": agent_id, "request_id": request_id, "grant": grant,
        })
        result = self._object(result, "placeholder-files result")
        self._require_keys(result, {"files", "hosts", "expires_at"}, "placeholder-files result")
        self._file_list(result["files"], "placeholder-files result files", path_key="path")
        self._string_list(result["hosts"], "placeholder-files result hosts")
        self._optional_string(result["expires_at"], "placeholder-files result expires_at")
        return result["files"], result["hosts"], result["expires_at"]

    def injection_headers(self, host, method, path, agent_id, audit, request_id, grant):
        self._ensure_capability("injection.headers")
        result = self._request("injection.headers", {
            "host": host, "method": method, "path": path, "agent_id": agent_id,
            "request_id": request_id, "grant": grant,
        })
        result = self._object(result, "injection.headers result")
        self._require_keys(result, {"headers", "expires_at", "strip_request_headers"}, "injection.headers result")
        self._string_map(result["headers"], "injection.headers result headers")
        self._optional_string(result["expires_at"], "injection.headers result expires_at")
        self._string_list(result["strip_request_headers"], "injection.headers result strip_request_headers")
        return result["headers"], result["expires_at"], result["strip_request_headers"]

    def close(self):
        with self._lock:
            if self._closing:
                return
            self._closing = True
            process = self._process
        if process is not None and process.poll() is None:
            try:
                self._request("shutdown", {}, timeout=min(2.0, self._plugin["request_timeout"]), allow_unready=True)
            except ProviderError:
                pass
        self._stop_process(process)
        self._fail_generation(self._generation, "provider-unavailable", schedule_restart=False)
        thread = self._restart_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)

    def _start(self, initial=False):
        environment = dict(SAFE_ENVIRONMENT)
        for name in self._plugin["pass_env"]:
            environment[name] = os.environ[name]
        try:
            process = subprocess.Popen(
                self._plugin["command"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=environment, bufsize=0,
            )
        except OSError as error:
            if initial:
                raise BrokerConfigError(f"provider {self._name} executable could not start") from error
            raise ProviderError("provider-unavailable", "provider is unavailable", 503) from error
        with self._lock:
            if self._closing:
                self._stop_process(process)
                return
            self._generation += 1
            generation = self._generation
            self._process = process
            self._ready = False
        threading.Thread(target=self._read_stdout, args=(process, generation), daemon=True).start()
        threading.Thread(target=self._drain_stderr, args=(process,), daemon=True).start()
        try:
            result = self._request("initialize", {
                "protocol_version": PROTOCOL_VERSION,
                "provider_instance_name": self._name,
                "plugin_name": self._plugin_name,
                "config": self._configured_config,
                "allow": self._configured_allow,
            }, timeout=self._plugin["initialize_timeout"], allow_unready=True)
            self._validate_initialize(result)
        except ProviderError as error:
            self._fail_generation(generation, error.reason, schedule_restart=not initial)
            if initial:
                raise BrokerConfigError(f"provider {self._name} initialize failed: {error.reason}") from error
            raise
        with self._lock:
            if self._generation == generation and process.poll() is None:
                self._ready = True

    def _config_object(self):
        value = self._entry.get("config") or {}
        if not isinstance(value, dict):
            raise BrokerConfigError(f"provider {self._name} config must be a YAML object")
        return value

    def _allow_object(self):
        value = self._entry.get("allow") or {}
        if not isinstance(value, dict):
            raise BrokerConfigError(f"provider {self._name} allow must be a YAML object")
        return value

    def _validate_initialize(self, value):
        value = self._object(value, "initialize result")
        self._require_keys(value, {"protocol_version", "capabilities"}, "initialize result", optional={
            "injection_hosts", "injection_git", "bundle_ttl_seconds",
        })
        if value["protocol_version"] != PROTOCOL_VERSION:
            self._protocol_error("provider selected an unsupported protocol version")
        capabilities = value["capabilities"]
        if not isinstance(capabilities, list) or any(not isinstance(item, str) for item in capabilities):
            self._protocol_error("provider capabilities must be a string list")
        if len(set(capabilities)) != len(capabilities) or not set(capabilities).issubset(CAPABILITIES):
            self._protocol_error("provider declared unknown or duplicate capabilities")
        hosts = value.get("injection_hosts", [])
        host_pattern = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
        if (not isinstance(hosts, list) or len(set(hosts)) != len(hosts) or
                any(not isinstance(host, str) or not host_pattern.fullmatch(host) for host in hosts)):
            self._protocol_error("provider injection_hosts metadata is invalid")
        injection_git = value.get("injection_git", False)
        if not isinstance(injection_git, bool):
            self._protocol_error("provider injection_git metadata is invalid")
        ttl = value.get("bundle_ttl_seconds")
        if ttl is not None and (not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0):
            self._protocol_error("provider bundle_ttl_seconds metadata is invalid")
        if (hosts or injection_git) and "injection.headers" not in capabilities:
            self._protocol_error("provider injection metadata requires injection.headers")
        self._capabilities = set(capabilities)
        self._injection_hosts = list(hosts)
        self._injection_git = injection_git
        self._bundle_ttl_seconds = ttl

    def _operation_for_target(self, method, repo, effective_repositories):
        if not isinstance(repo, ExecutableTarget):
            self._protocol_error("broker supplied an invalid normalized target")
        return self._object(self._request(method, {
            "target": repo.value, "effective_repositories": effective_repositories,
        }), f"{method} result")

    def _target_result(self, result):
        result = self._object(result, "target.normalize result")
        self._require_keys(result, {"target", "audit_target"}, "target.normalize result")
        target = result["target"]
        if not isinstance(target, str) or not target or len(target.encode("utf-8")) > MAX_TARGET_LENGTH:
            self._protocol_error("provider normalized target is invalid")
        return ExecutableTarget(target, self._audit_target(result["audit_target"]))

    def _audit_target(self, value):
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_TARGET_LENGTH:
            self._protocol_error("provider audit_target is invalid")
        if any(ord(character) < 0x20 or ord(character) == 0x7f for character in value):
            self._protocol_error("provider audit_target contains control characters")
        return value

    def _ensure_capability(self, capability):
        if capability not in self._capabilities:
            reason = capability.replace(".", "-") + "-not-supported"
            raise ProviderError(reason, f"provider {self._name} does not support {capability}")

    def _request(self, method, params, timeout=None, allow_unready=False):
        with self._lock:
            if self._closing and method != "shutdown":
                raise ProviderError("provider-unavailable", "provider is unavailable", 503)
            if not allow_unready and not self._ready:
                raise ProviderError("provider-unavailable", "provider is unavailable", 503)
            process = self._process
            generation = self._generation
            if process is None or process.poll() is not None:
                self._fail_generation(generation, "provider-unavailable")
                raise ProviderError("provider-unavailable", "provider is unavailable", 503)
            if len(self._pending) >= MAX_PENDING_REQUESTS:
                raise ProviderError("provider-unavailable", "provider request capacity is exhausted", 503)
            request_id = str(uuid.uuid4())
            pending = _Pending()
            self._pending[request_id] = pending
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(data) > MAX_PROTOCOL_LINE_BYTES:
            with self._lock:
                self._pending.pop(request_id, None)
            raise ProviderError("provider-protocol-error", "provider request exceeds the protocol line limit", 502)
        wait_timeout = timeout if timeout is not None else self._plugin["request_timeout"]
        write_done = threading.Event()
        write_error = []
        def write_frame():
            try:
                with self._write_lock:
                    view = memoryview(data)
                    while view:
                        written = process.stdin.write(view)
                        if not written:
                            raise BrokenPipeError()
                        view = view[written:]
                    process.stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as error:
                write_error.append(error)
            finally:
                write_done.set()
        threading.Thread(target=write_frame, daemon=True).start()
        if not write_done.wait(wait_timeout):
            self._fail_generation(generation, "provider-unavailable")
            raise ProviderError("provider-unavailable", "provider request timed out", 503)
        if write_error:
            self._fail_generation(generation, "provider-unavailable")
            raise ProviderError("provider-unavailable", "provider is unavailable", 503)
        if not pending.event.wait(wait_timeout):
            self._fail_generation(generation, "provider-unavailable")
            raise ProviderError("provider-unavailable", "provider request timed out", 503)
        if pending.error is not None:
            raise pending.error
        return pending.response

    def _read_stdout(self, process, generation):
        while True:
            try:
                line = process.stdout.readline(MAX_PROTOCOL_LINE_BYTES + 1)
            except (OSError, ValueError):
                self._fail_generation(generation, "provider-unavailable")
                return
            if not line:
                self._fail_generation(generation, "provider-unavailable")
                return
            if len(line) > MAX_PROTOCOL_LINE_BYTES or not line.endswith(b"\n"):
                self._fail_generation(generation, "provider-protocol-error")
                return
            try:
                message = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._fail_generation(generation, "provider-protocol-error")
                return
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                self._fail_generation(generation, "provider-protocol-error")
                return
            response_id = message.get("id")
            if not isinstance(response_id, str):
                self._fail_generation(generation, "provider-protocol-error")
                return
            with self._lock:
                if generation != self._generation:
                    return
                pending = self._pending.pop(response_id, None)
            if pending is None:
                self._fail_generation(generation, "provider-protocol-error")
                return
            has_result = "result" in message
            has_error = "error" in message
            if has_result == has_error or set(message) - {"jsonrpc", "id", "result", "error"}:
                pending.error = ProviderError("provider-protocol-error", "provider returned an invalid response", 502)
                pending.event.set()
                self._fail_generation(generation, "provider-protocol-error")
                return
            if has_error:
                try:
                    pending.error = self._provider_error(message["error"])
                except ProviderError as error:
                    pending.error = error
                    pending.event.set()
                    self._fail_generation(generation, "provider-protocol-error")
                    return
            else:
                pending.response = message["result"]
            pending.event.set()

    def _provider_error(self, envelope):
        if not isinstance(envelope, dict) or set(envelope) - {"code", "message", "data"}:
            self._protocol_error("provider returned an invalid error envelope")
        if not isinstance(envelope.get("code"), int) or isinstance(envelope.get("code"), bool):
            self._protocol_error("provider returned an invalid error code")
        data = envelope.get("data")
        if not isinstance(data, dict) or set(data) - {"reason", "status", "message"}:
            self._protocol_error("provider returned invalid error data")
        reason = data.get("reason")
        status = data.get("status")
        message = data.get("message")
        if not isinstance(reason, str) or not reason or len(reason) > 128:
            self._protocol_error("provider error reason is invalid")
        if not isinstance(status, int) or isinstance(status, bool) or not 400 <= status <= 599:
            self._protocol_error("provider error status is invalid")
        if message is not None and (not isinstance(message, str) or not message or len(message) > MAX_TEXT_LENGTH):
            self._protocol_error("provider error message is invalid")
        return ProviderError(reason, message, status)

    def _fail_generation(self, generation, reason, schedule_restart=True):
        error = ProviderError(reason, "provider is unavailable" if reason == "provider-unavailable" else "provider protocol failed", 503 if reason == "provider-unavailable" else 502)
        with self._lock:
            if generation != self._generation:
                return
            self._ready = False
            process = self._process
            self._process = None
            pending = list(self._pending.values())
            self._pending.clear()
        for item in pending:
            item.error = error
            item.event.set()
        self._stop_process(process)
        if schedule_restart and not self._closing:
            self._schedule_restart()

    def _schedule_restart(self):
        with self._lock:
            if self._restart_thread is not None and self._restart_thread.is_alive():
                self._restart_requested = True
                return
            delay = self._restart_delay
            self._restart_delay = min(self._restart_delay * 2, 5.0)
            self._restart_thread = threading.Thread(target=self._restart, args=(delay,), daemon=True)
            self._restart_thread.start()

    def _restart(self, delay):
        while True:
            time.sleep(delay)
            with self._lock:
                if self._closing:
                    return
            try:
                self._start(initial=False)
                with self._lock:
                    if self._ready and not self._restart_requested:
                        return
                    self._restart_requested = False
            except (ProviderError, BrokerConfigError):
                with self._lock:
                    delay = self._restart_delay
                    self._restart_delay = min(self._restart_delay * 2, 5.0)

    @staticmethod
    def _drain_stderr(process):
        try:
            while process.stderr.read(8192):
                pass
        except (OSError, ValueError):
            pass

    @staticmethod
    def _stop_process(process):
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
        else:
            try:
                process.wait(timeout=0)
            except (subprocess.TimeoutExpired, OSError):
                pass

    def _object(self, value, field):
        if not isinstance(value, dict):
            self._protocol_error(f"{field} must be an object")
        return dict(value)

    def _require_keys(self, value, required, field, optional=None):
        allowed = required | (optional or set())
        if not required.issubset(value) or set(value) - allowed:
            self._protocol_error(f"{field} has invalid fields")

    def _bounded_string(self, value, field, maximum):
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
            self._protocol_error(f"{field} is invalid")

    def _optional_string(self, value, field):
        if value is not None:
            self._bounded_string(value, field, MAX_TEXT_LENGTH)

    def _string_list(self, value, field):
        if not isinstance(value, list) or len(value) > 1024:
            self._protocol_error(f"{field} is invalid")
        for item in value:
            self._bounded_string(item, field, MAX_TEXT_LENGTH)

    def _string_map(self, value, field):
        if not isinstance(value, dict) or len(value) > 1024:
            self._protocol_error(f"{field} is invalid")
        for key, item in value.items():
            self._bounded_string(key, field, MAX_TEXT_LENGTH)
            self._bounded_string(item, field, MAX_PROTOCOL_LINE_BYTES)

    def _file_list(self, value, field, path_key):
        if not isinstance(value, list) or len(value) > 1024:
            self._protocol_error(f"{field} is invalid")
        for item in value:
            if not isinstance(item, dict) or path_key not in item or "content" not in item:
                self._protocol_error(f"{field} is invalid")
            if set(item) - {path_key, "content", "mode"}:
                self._protocol_error(f"{field} is invalid")
            self._bounded_string(item[path_key], field, MAX_TEXT_LENGTH)
            if not isinstance(item["content"], str) or len(item["content"].encode("utf-8")) > MAX_PROTOCOL_LINE_BYTES:
                self._protocol_error(f"{field} is invalid")
            if "mode" in item:
                self._bounded_string(item["mode"], field, 16)

    @staticmethod
    def _protocol_error(message):
        raise ProviderError("provider-protocol-error", message, 502)
