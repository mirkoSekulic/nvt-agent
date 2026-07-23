"""Supervision and validation for trusted executable broker providers."""

import ipaddress
import json
import os
import queue
import re
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass

from broker.core.config import BrokerConfigError
from broker.core.errors import ProviderError
from broker.core.provider_adapter import ProviderAdapter


PROTOCOL_VERSION = "nvt.broker-provider/v1"
MAX_PROTOCOL_LINE_BYTES = 1024 * 1024
MAX_PENDING_REQUESTS = 128
MAX_TEXT_LENGTH = 4096
MAX_TARGET_LENGTH = 8192
RESTART_INITIAL_SECONDS = 0.1
RESTART_MAX_SECONDS = 5.0
STABILITY_RESET_SECONDS = 5.0
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
    def __init__(self, generation):
        self.generation = generation
        self.event = threading.Event()
        self.response = None
        self.error = None


class _Write:
    def __init__(self, data, deadline):
        self.data = data
        self.deadline = deadline
        self.event = threading.Event()
        self.error = None


class _Generation:
    def __init__(self, number, process):
        self.number = number
        self.process = process
        self.writes = queue.Queue(MAX_PENDING_REQUESTS)
        self.stop = threading.Event()
        self.started_at = time.monotonic()
        self.writer = None
        self.stdout_reader = None
        self.stderr_reader = None


class ExecutableProviderAdapter(ProviderAdapter):
    """One long-lived, correlated JSON-RPC process for one provider instance."""

    def __init__(self, entry, plugin):
        self._name = entry["name"]
        self._plugin_name = plugin["name"]
        self._entry = entry
        self._plugin = plugin
        self._lock = threading.RLock()
        self._pending = {}
        self._current = None
        self._generation = 0
        self._closing = False
        self._ready = False
        self._restart_delay = RESTART_INITIAL_SECONDS
        self._restart_event = threading.Event()
        self._supervisor_stop = threading.Event()
        self._retired = queue.Queue()
        self._supervisor = None
        self._capabilities = set()
        self._injection_hosts = []
        self._injection_git = False
        self._bundle_ttl_seconds = None
        self._configured_config = self._config_object()
        self._configured_allow = self._allow_object()
        try:
            self._start(initial=True)
            self._supervisor = threading.Thread(
                target=self._supervise, name=f"provider-supervisor-{self._name}", daemon=True,
            )
            self._supervisor.start()
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

    def validate_state(self):
        # Executable providers own validation at initialize time. Runtime
        # degradation invalidates acceptance until their supervisor has
        # successfully initialized a replacement generation.
        return self.ready

    @property
    def _process(self):
        """Compatibility for focused lifecycle tests; process ownership is generation-scoped."""
        with self._lock:
            return self._current.process if self._current is not None else None

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
        self._require_keys(
            result,
            {"headers", "expires_at", "strip_request_headers"},
            "injection.headers result",
            optional={"append_headers"},
        )
        self._string_map(result["headers"], "injection.headers result headers")
        append_headers = result.get("append_headers", {})
        self._string_map(append_headers, "injection.headers result append_headers")
        self._optional_string(result["expires_at"], "injection.headers result expires_at")
        self._string_list(result["strip_request_headers"], "injection.headers result strip_request_headers")
        return result["headers"], result["expires_at"], result["strip_request_headers"], append_headers

    def close(self):
        with self._lock:
            if self._closing:
                return
            self._closing = True
            generation = self._current
        if generation is not None and generation.process.poll() is None:
            try:
                self._request("shutdown", {}, timeout=min(2.0, self._plugin["request_timeout"]), allow_unready=True)
            except ProviderError:
                pass
        self._fail_generation(generation.number if generation else self._generation, "provider-unavailable", restart=False)
        self._supervisor_stop.set()
        self._restart_event.set()
        supervisor = self._supervisor
        if supervisor is not None and supervisor is not threading.current_thread():
            supervisor.join(timeout=8)
        self._retire_pending()

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
            if self._current is not None:
                self._stop_process(process)
                raise ProviderError("provider-unavailable", "provider is already running", 503)
            self._generation += 1
            generation = _Generation(self._generation, process)
            self._current = generation
            self._ready = False
        generation.writer = threading.Thread(
            target=self._write_stdin, args=(generation,), name=f"provider-writer-{self._name}-{generation.number}", daemon=True,
        )
        generation.stdout_reader = threading.Thread(
            target=self._read_stdout, args=(generation,), name=f"provider-stdout-{self._name}-{generation.number}", daemon=True,
        )
        generation.stderr_reader = threading.Thread(
            target=self._drain_stderr, args=(generation,), name=f"provider-stderr-{self._name}-{generation.number}", daemon=True,
        )
        generation.writer.start()
        generation.stdout_reader.start()
        generation.stderr_reader.start()
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
            self._fail_generation(generation.number, error.reason, restart=False)
            if initial:
                raise BrokerConfigError(f"provider {self._name} initialize failed: {error.reason}") from error
            raise
        with self._lock:
            if self._current is generation and process.poll() is None:
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
        if not isinstance(hosts, list) or any(not isinstance(host, str) for host in hosts):
            self._protocol_error("provider injection_hosts metadata is invalid")
        if len(set(hosts)) != len(hosts):
            self._protocol_error("provider injection_hosts metadata is invalid")
        for host in hosts:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                self._protocol_error("provider injection_hosts metadata is invalid")
            if not host_pattern.fullmatch(host):
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
        timeout = timeout if timeout is not None else self._plugin["request_timeout"]
        deadline = time.monotonic() + timeout
        with self._lock:
            if self._closing and method != "shutdown":
                raise ProviderError("provider-unavailable", "provider is unavailable", 503)
            if not allow_unready and not self._ready:
                raise ProviderError("provider-unavailable", "provider is unavailable", 503)
            generation = self._current
            if generation is None or generation.process.poll() is not None:
                self._fail_generation(self._generation, "provider-unavailable")
                raise ProviderError("provider-unavailable", "provider is unavailable", 503)
            if len(self._pending) >= MAX_PENDING_REQUESTS:
                raise ProviderError("provider-unavailable", "provider request capacity is exhausted", 503)
            request_id = str(uuid.uuid4())
            pending = _Pending(generation.number)
            self._pending[request_id] = pending
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(data) > MAX_PROTOCOL_LINE_BYTES:
            with self._lock:
                self._pending.pop(request_id, None)
            raise ProviderError("provider-protocol-error", "provider request exceeds the protocol line limit", 502)
        write = _Write(data, deadline)
        try:
            generation.writes.put(write, timeout=max(0, deadline - time.monotonic()))
        except queue.Full:
            self._fail_generation(generation.number, "provider-unavailable")
            raise ProviderError("provider-unavailable", "provider request timed out", 503)
        remaining = max(0, deadline - time.monotonic())
        if not write.event.wait(remaining):
            self._fail_generation(generation.number, "provider-unavailable")
            raise ProviderError("provider-unavailable", "provider request timed out", 503)
        if write.error is not None:
            self._fail_generation(generation.number, "provider-unavailable")
            raise ProviderError("provider-unavailable", "provider is unavailable", 503)
        remaining = max(0, deadline - time.monotonic())
        if not pending.event.wait(remaining):
            self._fail_generation(generation.number, "provider-unavailable")
            raise ProviderError("provider-unavailable", "provider request timed out", 503)
        if pending.error is not None:
            raise pending.error
        self._mark_stable(generation)
        return pending.response

    def _write_stdin(self, generation):
        while not generation.stop.is_set():
            try:
                item = generation.writes.get(timeout=0.1)
            except queue.Empty:
                continue
            if time.monotonic() >= item.deadline:
                item.error = TimeoutError()
                item.event.set()
                continue
            try:
                view = memoryview(item.data)
                while view:
                    written = generation.process.stdin.write(view)
                    if not written:
                        raise BrokenPipeError()
                    view = view[written:]
                generation.process.stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as error:
                item.error = error
            finally:
                item.event.set()

    def _read_stdout(self, generation):
        process = generation.process
        while True:
            try:
                line = process.stdout.readline(MAX_PROTOCOL_LINE_BYTES + 1)
            except (OSError, ValueError):
                self._fail_generation(generation.number, "provider-unavailable")
                return
            if not line:
                self._fail_generation(generation.number, "provider-unavailable")
                return
            if len(line) > MAX_PROTOCOL_LINE_BYTES or not line.endswith(b"\n"):
                self._fail_generation(generation.number, "provider-protocol-error")
                return
            try:
                message = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._fail_generation(generation.number, "provider-protocol-error")
                return
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                self._fail_generation(generation.number, "provider-protocol-error")
                return
            response_id = message.get("id")
            if not isinstance(response_id, str):
                self._fail_generation(generation.number, "provider-protocol-error")
                return
            with self._lock:
                if self._current is not generation:
                    return
                pending = self._pending.pop(response_id, None)
            if pending is None:
                self._fail_generation(generation.number, "provider-protocol-error")
                return
            has_result = "result" in message
            has_error = "error" in message
            if has_result == has_error or set(message) - {"jsonrpc", "id", "result", "error"}:
                pending.error = ProviderError("provider-protocol-error", "provider returned an invalid response", 502)
                pending.event.set()
                self._fail_generation(generation.number, "provider-protocol-error")
                return
            if has_error:
                try:
                    pending.error = self._provider_error(message["error"])
                except ProviderError as error:
                    pending.error = error
                    pending.event.set()
                    self._fail_generation(generation.number, "provider-protocol-error")
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

    def _fail_generation(self, generation_number, reason, restart=True):
        error = ProviderError(reason, "provider is unavailable" if reason == "provider-unavailable" else "provider protocol failed", 503 if reason == "provider-unavailable" else 502)
        with self._lock:
            generation = self._current
            if generation is None or generation.number != generation_number:
                return
            self._ready = False
            self._current = None
            pending = [item for item in self._pending.values() if item.generation == generation_number]
            self._pending = {key: item for key, item in self._pending.items() if item.generation != generation_number}
        generation.stop.set()
        while True:
            try:
                write = generation.writes.get_nowait()
            except queue.Empty:
                break
            write.error = error
            write.event.set()
        for item in pending:
            item.error = error
            item.event.set()
        self._retired.put(generation)
        if restart and not self._closing:
            self._restart_event.set()

    def _supervise(self):
        while not self._supervisor_stop.is_set():
            self._restart_event.wait(0.5)
            if self._supervisor_stop.is_set():
                return
            if not self._restart_event.is_set():
                continue
            self._restart_event.clear()
            self._retire_pending()
            while not self._supervisor_stop.is_set():
                with self._lock:
                    if self._current is not None:
                        break
                    delay = self._restart_delay
                    self._restart_delay = min(delay * 2, RESTART_MAX_SECONDS)
                if self._supervisor_stop.wait(delay):
                    return
                try:
                    self._start(initial=False)
                    break
                except (ProviderError, BrokerConfigError):
                    self._retire_pending()
                    continue

    def _retire_pending(self):
        while True:
            try:
                generation = self._retired.get_nowait()
            except queue.Empty:
                return
            self._stop_process(generation.process)
            for thread in (generation.writer, generation.stdout_reader, generation.stderr_reader):
                if thread is not None and thread is not threading.current_thread():
                    thread.join(timeout=1)

    def _mark_stable(self, generation):
        if time.monotonic() - generation.started_at < STABILITY_RESET_SECONDS:
            return
        with self._lock:
            if self._current is generation and self._ready:
                self._restart_delay = RESTART_INITIAL_SECONDS

    @staticmethod
    def _drain_stderr(generation):
        process = generation.process
        try:
            while not generation.stop.is_set() and process.stderr.read(8192):
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
