"""Principal-owned dynamic provider accounts.

This module deliberately knows nothing about provider brands or enrollment
commands. Administrators bind opaque enrollment templates to existing broker
provider plugins; authenticated callers can only submit credential bytes for
one of those templates.
"""

import base64
import binascii
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from broker.core.config import BrokerConfigError, ENV_NAME_RE, fail, list_value, string_value
from broker.core.dynamic_provider import DynamicProviderAdapter
from broker.core.errors import ProviderError


AUTH_SCHEME = "NVT-Principal-v1"
AUTH_AUDIENCE = "nvt.broker.principal-accounts/v1"
API_PREFIX = "/v1/principal-accounts/"
API_OPERATIONS = {
    API_PREFIX + "complete-enrollment": "enroll",
    API_PREFIX + "reconnect": "reconnect",
    API_PREFIX + "revoke": "revoke",
    API_PREFIX + "readiness": "readiness",
    API_PREFIX + "resolve": "resolve",
}
API_PATHS = frozenset(API_OPERATIONS)
MAX_CREDENTIAL_BYTES = 768 * 1024
# A maximum-size credential encodes to exactly 1 MiB of base64. Reserve a
# bounded 4 KiB for the strict JSON envelope instead of advertising a payload
# that cannot pass the HTTP body limit.
MAX_BODY_BYTES = 1028 * 1024
MAX_IDENTITY_BYTES = 1024
MAX_NAME_BYTES = 128
MAX_OPERATION_BYTES = 128
MAX_OPERATIONS = 32
METADATA_VERSION = 1
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
FILE_RE = re.compile(r"^credential-[0-9]+-[A-Za-z0-9_-]{16,64}\.bin$")
PROVIDER_ID_RE = re.compile(r"^dpa_[A-Za-z0-9_-]{32}$")


@dataclass(frozen=True)
class Principal:
    issuer: str
    subject: str
    principal_id: str


@dataclass(frozen=True)
class CredentialTemplate:
    name: str
    label: str
    enrollment_adapter: str
    provider_template: str


@dataclass(frozen=True)
class ProviderTemplate:
    name: str
    plugin: str
    credential_config_key: str
    config: dict
    allow: dict


@dataclass(frozen=True)
class DynamicAccountsConfig:
    enabled: bool
    state_dir: Path | None = None
    hmac_key: bytes | None = None
    max_assertion_seconds: int = 300
    max_accounts: int = 10000
    credential_templates: dict | None = None
    provider_templates: dict | None = None


class _MetadataCommitError(Exception):
    def __init__(self, committed, cause):
        super().__init__("metadata commit failed")
        self.committed = committed
        self.__cause__ = cause


def load_dynamic_accounts_config(config, supported_plugins):
    raw = config.get("dynamic-accounts")
    if raw is None:
        return DynamicAccountsConfig(enabled=False)
    if not isinstance(raw, dict):
        fail("dynamic-accounts must be a YAML object")
    unknown = set(raw) - {
        "enabled", "state-dir", "authentication", "max-accounts",
        "credential-templates", "provider-templates",
    }
    if unknown:
        fail(f"dynamic-accounts has unknown keys: {', '.join(sorted(unknown))}")
    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        fail("dynamic-accounts.enabled must be a boolean")
    if not enabled:
        # Disabled means inert: no environment secret, storage, or templates
        # are required or inspected, preserving the static broker path.
        return DynamicAccountsConfig(enabled=False)

    state_dir = Path(string_value(raw.get("state-dir"), "dynamic-accounts.state-dir", required=True))
    if not state_dir.is_absolute():
        fail("dynamic-accounts.state-dir must be an absolute path")
    max_accounts = raw.get("max-accounts", 10000)
    if not isinstance(max_accounts, int) or isinstance(max_accounts, bool) or not 1 <= max_accounts <= 100000:
        fail("dynamic-accounts.max-accounts must be an integer from 1 through 100000")

    authentication = raw.get("authentication")
    if not isinstance(authentication, dict):
        fail("dynamic-accounts.authentication must be a YAML object")
    unknown = set(authentication) - {"hmac-key-env", "max-assertion-seconds"}
    if unknown:
        fail(f"dynamic-accounts.authentication has unknown keys: {', '.join(sorted(unknown))}")
    key_env = string_value(
        authentication.get("hmac-key-env"),
        "dynamic-accounts.authentication.hmac-key-env",
        required=True,
    )
    if not ENV_NAME_RE.fullmatch(key_env):
        fail("dynamic-accounts.authentication.hmac-key-env must be an environment variable name")
    key_text = os.environ.get(key_env)
    if key_text is None:
        fail(f"environment variable {key_env} is not set")
    key = key_text.encode("utf-8")
    if len(key) < 32 or len(key) > 4096:
        fail(f"environment variable {key_env} must contain 32 through 4096 bytes")
    max_assertion = authentication.get("max-assertion-seconds", 300)
    if not isinstance(max_assertion, int) or isinstance(max_assertion, bool) or not 1 <= max_assertion <= 900:
        fail("dynamic-accounts.authentication.max-assertion-seconds must be an integer from 1 through 900")

    provider_templates = {}
    for index, item in enumerate(list_value(raw.get("provider-templates"), "dynamic-accounts.provider-templates")):
        field = f"dynamic-accounts.provider-templates[{index}]"
        if not isinstance(item, dict):
            fail(f"{field} must be a YAML object")
        unknown = set(item) - {"name", "plugin", "credential-config-key", "config", "allow"}
        if unknown:
            fail(f"{field} has unknown keys: {', '.join(sorted(unknown))}")
        name = _configured_name(item.get("name"), f"{field}.name")
        if name in provider_templates:
            fail(f"duplicate dynamic provider template name: {name}")
        plugin = _configured_name(item.get("plugin"), f"{field}.plugin")
        if plugin not in supported_plugins:
            fail(f"unsupported {field}.plugin: {plugin}")
        credential_key = _configured_name(item.get("credential-config-key"), f"{field}.credential-config-key")
        template_config = item.get("config", {})
        if not isinstance(template_config, dict):
            fail(f"{field}.config must be a YAML object")
        if credential_key in template_config:
            fail(f"{field}.config must not set its credential-config-key")
        allow = item.get("allow", {})
        if not isinstance(allow, dict):
            fail(f"{field}.allow must be a YAML object")
        provider_templates[name] = ProviderTemplate(name, plugin, credential_key, dict(template_config), dict(allow))

    credential_templates = {}
    for index, item in enumerate(list_value(raw.get("credential-templates"), "dynamic-accounts.credential-templates")):
        field = f"dynamic-accounts.credential-templates[{index}]"
        if not isinstance(item, dict):
            fail(f"{field} must be a YAML object")
        unknown = set(item) - {"name", "label", "enrollment-adapter", "provider-template"}
        if unknown:
            fail(f"{field} has unknown keys: {', '.join(sorted(unknown))}")
        name = _configured_name(item.get("name"), f"{field}.name")
        if name in credential_templates:
            fail(f"duplicate dynamic credential template name: {name}")
        label = string_value(item.get("label"), f"{field}.label", required=True)
        if len(label.encode("utf-8")) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in label):
            fail(f"{field}.label is invalid")
        adapter = _configured_name(item.get("enrollment-adapter"), f"{field}.enrollment-adapter")
        provider_template = _configured_name(item.get("provider-template"), f"{field}.provider-template")
        if provider_template not in provider_templates:
            fail(f"{field}.provider-template is unknown")
        credential_templates[name] = CredentialTemplate(name, label, adapter, provider_template)
    if not provider_templates or not credential_templates:
        fail("enabled dynamic-accounts requires provider-templates and credential-templates")

    return DynamicAccountsConfig(
        enabled=True,
        state_dir=state_dir,
        hmac_key=key,
        max_assertion_seconds=max_assertion,
        max_accounts=max_accounts,
        credential_templates=credential_templates,
        provider_templates=provider_templates,
    )


def _configured_name(value, field):
    value = string_value(value, field, required=True)
    if not NAME_RE.fullmatch(value):
        fail(f"{field} must match {NAME_RE.pattern}")
    return value


def principal_id(issuer, subject):
    digest = hashlib.sha256()
    digest.update(b"nvt-principal-account-v1\0")
    for value in (issuer, subject):
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return "p_" + _b64url(digest.digest())


def is_dynamic_provider_id(value):
    return isinstance(value, str) and PROVIDER_ID_RE.fullmatch(value) is not None


class PrincipalAuthenticator:
    def __init__(self, key, max_assertion_seconds, clock=time.time):
        self._key = key
        self._maximum = max_assertion_seconds
        self._clock = clock

    def authenticate(self, authorization):
        if not isinstance(authorization, str) or not authorization.startswith(AUTH_SCHEME + " "):
            raise ProviderError("unauthorized", "unauthorized", 401)
        token = authorization[len(AUTH_SCHEME) + 1 :]
        if len(token) > 8192 or token.count(".") != 1:
            raise ProviderError("unauthorized", "unauthorized", 401)
        encoded, signature = token.split(".")
        try:
            raw = _decode_b64url(encoded)
            provided = _decode_b64url(signature)
        except (ValueError, binascii.Error):
            raise ProviderError("unauthorized", "unauthorized", 401)
        expected = hmac.digest(self._key, raw, "sha256")
        if not hmac.compare_digest(provided, expected):
            raise ProviderError("unauthorized", "unauthorized", 401)
        try:
            payload = _strict_json(raw)
        except ValueError:
            raise ProviderError("unauthorized", "unauthorized", 401)
        if not isinstance(payload, dict) or set(payload) != {"version", "audience", "issuer", "subject", "expires_at"}:
            raise ProviderError("unauthorized", "unauthorized", 401)
        issuer = payload.get("issuer")
        subject = payload.get("subject")
        expires = payload.get("expires_at")
        if (
            not isinstance(payload.get("version"), int)
            or isinstance(payload.get("version"), bool)
            or payload.get("version") != 1
            or payload.get("audience") != AUTH_AUDIENCE
            or not _identity_value(issuer)
            or not _identity_value(subject)
            or not isinstance(expires, int)
            or isinstance(expires, bool)
        ):
            raise ProviderError("unauthorized", "unauthorized", 401)
        now = int(self._clock())
        if expires <= now or expires > now + self._maximum:
            raise ProviderError("unauthorized", "unauthorized", 401)
        return Principal(issuer, subject, principal_id(issuer, subject))


def sign_principal_assertion(key, issuer, subject, expires_at):
    """Test/integrator helper; callers still own authentication to this identity."""
    raw = json.dumps(
        {"audience": AUTH_AUDIENCE, "expires_at": expires_at, "issuer": issuer, "subject": subject, "version": 1},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"{AUTH_SCHEME} {_b64url(raw)}.{_b64url(hmac.digest(key, raw, 'sha256'))}"


def _identity_value(value):
    return (
        isinstance(value, str)
        and 0 < len(value.encode("utf-8")) <= MAX_IDENTITY_BYTES
        and value == value.strip()
        and not any(ord(c) < 32 or ord(c) == 127 for c in value)
    )


def _strict_json(raw):
    def pairs(values):
        output = {}
        for key, value in values:
            if key in output:
                raise ValueError("duplicate key")
            output[key] = value
        return output

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid JSON") from error


def decode_api_request(raw, operation):
    if len(raw) > MAX_BODY_BYTES:
        raise ProviderError("invalid-request", "invalid-request", 400)
    try:
        payload = _strict_json(raw)
    except ValueError as error:
        raise ProviderError("invalid-request", "invalid-request", 400) from error
    if not isinstance(payload, dict):
        raise ProviderError("invalid-request", "invalid-request", 400)
    expected = {
        "enroll": {"template", "operation_id", "credential_base64"},
        "reconnect": {"operation_id", "credential_base64"},
        "revoke": {"operation_id"},
        "readiness": set(),
        "resolve": set(),
    }[operation]
    if set(payload) != expected:
        raise ProviderError("invalid-request", "invalid-request", 400)
    if "template" in payload:
        _api_string(payload["template"], MAX_NAME_BYTES)
    if "operation_id" in payload:
        _api_string(payload["operation_id"], MAX_OPERATION_BYTES)
    credential = None
    if "credential_base64" in payload:
        value = payload["credential_base64"]
        _api_string(value, MAX_CREDENTIAL_BYTES * 2)
        try:
            credential = bytearray(base64.b64decode(value, validate=True))
        except (ValueError, binascii.Error) as error:
            raise ProviderError("invalid-request", "invalid-request", 400) from error
        if not credential or len(credential) > MAX_CREDENTIAL_BYTES:
            raise ProviderError("invalid-request", "invalid-request", 400)
    return payload, credential


def _api_string(value, maximum):
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ProviderError("invalid-request", "invalid-request", 400)


class DynamicAccountManager:
    def __init__(self, config, provider_factory, static_provider_names=(), clock=time.time):
        self.config = config
        self._factory = provider_factory
        self._static_names = frozenset(static_provider_names)
        if any(is_dynamic_provider_id(name) for name in self._static_names):
            raise BrokerConfigError("static provider name collides with the dynamic provider id namespace")
        self._clock = clock
        self._lock = threading.RLock()
        self._providers = {}
        self._accounts = {}
        self._healthy = True
        self._root = config.state_dir
        self._accounts_dir = self._root / "accounts"
        self._writer_lock_fd = None
        self._prepare_storage()
        self._load()

    @property
    def healthy(self):
        with self._lock:
            return self._healthy

    def system_ready(self):
        with self._lock:
            # Kubernetes readiness represents the shared registry/storage
            # boundary. A principal's credential/provider health is reported
            # only by its authenticated readiness/resolve paths, so one bad
            # account cannot remove every static and dynamic user from the
            # broker Service or block that owner's reconnect.
            return self._healthy

    def close(self):
        with self._lock:
            providers = list(self._providers.values())
            self._providers.clear()
            self._accounts.clear()
        for provider in providers:
            provider.close()
        descriptor = self._writer_lock_fd
        self._writer_lock_fd = None
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def provider(self, provider_id):
        with self._lock:
            if not self._healthy:
                raise ProviderError("dynamic-accounts-unavailable", "dynamic-accounts-unavailable", 503)
            provider = self._providers.get(provider_id)
            if provider is None:
                if any(
                    account["state"] == "active" and account["provider_instance_id"] == provider_id
                    for account in self._accounts.values()
                ):
                    raise ProviderError("account-unready", "account-unready", 503)
                raise ProviderError("provider-not-found")
            ready = self._provider_is_ready(provider)
            if not ready:
                raise ProviderError("account-unready", "account-unready", 503)
            return provider

    def enroll(self, principal, template_name, operation_id, credential):
        with self._lock:
            self._require_healthy()
            current = self._accounts.get(principal.principal_id)
            if current and current["state"] == "active":
                repeated = self._idempotent(current, "enroll", operation_id)
                if repeated:
                    return repeated
                raise ProviderError("account-already-enrolled", "account-already-enrolled", 409)
            if current is not None:
                self._ensure_new_operation(current, operation_id)
            template = self.config.credential_templates.get(template_name)
            if template is None:
                raise ProviderError("unknown-template", "unknown-template", 400)
            if current is None and len(self._accounts) >= self.config.max_accounts:
                raise ProviderError("capacity-exceeded", "capacity-exceeded", 429)
            provider_id = self._new_provider_id()
            return self._replace(principal, current, template, operation_id, credential, "enroll", provider_id)

    def reconnect(self, principal, operation_id, credential):
        with self._lock:
            self._require_healthy()
            current = self._own_active(principal)
            repeated = self._idempotent(current, "reconnect", operation_id)
            if repeated:
                return repeated
            template = self.config.credential_templates[current["template"]]
            return self._replace(
                principal, current, template, operation_id, credential, "reconnect", current["provider_instance_id"]
            )

    def revoke(self, principal, operation_id):
        with self._lock:
            self._require_healthy()
            current = self._own_account(principal)
            repeated = self._idempotent(current, "revoke", operation_id)
            if repeated:
                return repeated
            if current["state"] != "active":
                raise ProviderError("account-not-found", "account-not-found", 404)
            result = {"ok": True, "state": "revoked"}
            metadata = dict(current)
            metadata.update(
                state="revoked",
                credential_file=None,
                updated_at=int(self._clock()),
                operations=self._record_operation(
                    current, "revoke", operation_id, result, current["provider_instance_id"]
                ),
            )
            try:
                self._write_metadata(principal.principal_id, metadata)
            except _MetadataCommitError as error:
                if error.committed:
                    # The tombstone is visible but its directory fsync was not
                    # confirmed. Preserve the old generation for restart to
                    # choose, and stop all dynamic service in this process.
                    self._latch_unhealthy()
                raise ProviderError("account-storage-unavailable", "account-storage-unavailable", 503) from error
            except Exception as error:
                raise ProviderError("account-storage-unavailable", "account-storage-unavailable", 503) from error
            provider = self._providers.pop(current["provider_instance_id"], None)
            self._accounts[principal.principal_id] = metadata
            if provider is not None:
                provider.close()
            self._unlink_credential(principal.principal_id, current.get("credential_file"))
            return result

    def readiness(self, principal):
        with self._lock:
            self._require_healthy()
            current = self._own_active(principal)
            provider = self._providers.get(current["provider_instance_id"])
            ready = self._provider_is_ready(provider)
            if not ready:
                raise ProviderError("account-unready", "account-unready", 503)
            return {
                "ok": True,
                "state": "ready",
                "template": current["template"],
                "generation": current["generation"],
            }

    def resolve(self, principal):
        with self._lock:
            self._require_healthy()
            current = self._own_active(principal)
            provider = self._providers.get(current["provider_instance_id"])
            ready = self._provider_is_ready(provider)
            if not ready:
                raise ProviderError("account-unready", "account-unready", 503)
            return {
                "ok": True,
                "template": current["template"],
                "provider_instance_id": current["provider_instance_id"],
                "generation": current["generation"],
            }

    @staticmethod
    def _provider_is_ready(provider):
        try:
            return provider is not None and provider.ready and provider.validate_state()
        except Exception:
            # Dynamic account APIs expose one provider-neutral failure. The
            # trusted provider's diagnostic may contain implementation details
            # or credential-derived text and must not escape this boundary.
            return False

    def _replace(self, principal, current, template, operation_id, credential, action, provider_id):
        generation = (current or {}).get("generation", 0) + 1
        account_dir = self._account_dir(principal.principal_id)
        filename = f"credential-{generation}-{_b64url(secrets.token_bytes(18))}.bin"
        credential_path = account_dir / filename
        try:
            self._ensure_account_directory(account_dir)
            _atomic_write_new(credential_path, credential)
        except Exception as error:
            _safe_unlink(credential_path)
            raise ProviderError("account-storage-unavailable", "account-storage-unavailable", 503) from error
        provider = None
        try:
            provider = self._create_provider(template, provider_id, credential_path)
            if not provider.ready or not provider.validate_state():
                raise ProviderError("provider-initialization-failed", "provider-initialization-failed", 503)
        except Exception as error:
            if provider is not None:
                provider.close()
            _safe_unlink(credential_path)
            if isinstance(error, ProviderError) and error.reason == "provider-initialization-failed":
                raise
            raise ProviderError("provider-initialization-failed", "provider-initialization-failed", 503) from error

        result = {"ok": True, "state": "ready", "template": template.name, "generation": generation}
        metadata = {
            "version": METADATA_VERSION,
            "principal_id": principal.principal_id,
            "issuer": principal.issuer,
            "subject": principal.subject,
            "state": "active",
            "template": template.name,
            "provider_instance_id": provider_id,
            "generation": generation,
            "credential_file": filename,
            "created_at": (current or {}).get("created_at", int(self._clock())),
            "updated_at": int(self._clock()),
            "operations": self._record_operation(current, action, operation_id, result, provider_id),
        }
        try:
            self._write_metadata(principal.principal_id, metadata)
        except _MetadataCommitError as error:
            if error.committed:
                # Do not delete the possibly committed generation. Restart
                # selects the fs-visible old or new manifest and removes the
                # other generation as an orphan.
                self._latch_unhealthy(provider)
            else:
                provider.close()
                _safe_unlink(credential_path)
            raise ProviderError("account-storage-unavailable", "account-storage-unavailable", 503) from error
        except Exception as error:
            provider.close()
            _safe_unlink(credential_path)
            raise ProviderError("account-storage-unavailable", "account-storage-unavailable", 503) from error
        old_file = None
        if current and current["state"] == "active":
            handle = self._providers.get(current["provider_instance_id"])
            old_file = current.get("credential_file")
            if handle is None:
                # Startup may have retained this valid account metadata while
                # its previous credential/provider failed local validation.
                # A successful owner-bound reconnect restores only this
                # account; it is not a registry-wide recovery operation.
                self._providers[provider_id] = DynamicProviderAdapter(provider)
            else:
                handle.swap(provider)
        else:
            self._providers[provider_id] = DynamicProviderAdapter(provider)
        self._accounts[principal.principal_id] = metadata
        if old_file and old_file != filename:
            self._unlink_credential(principal.principal_id, old_file)
        return result

    def _create_provider(self, credential_template, provider_id, credential_path):
        template = self.config.provider_templates[credential_template.provider_template]
        entry = {
            "name": provider_id,
            "plugin": template.plugin,
            "config": {**template.config, template.credential_config_key: str(credential_path)},
            "allow": template.allow,
        }
        return self._factory.create(entry)

    def _prepare_storage(self):
        try:
            if self._root.is_symlink():
                raise OSError("symlink")
            self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self._accounts_dir.is_symlink():
                raise OSError("symlink")
            self._accounts_dir.mkdir(mode=0o700, exist_ok=True)
            os.chmod(self._root, 0o700)
            os.chmod(self._accounts_dir, 0o700)
            if self._root.is_symlink() or self._accounts_dir.is_symlink():
                raise OSError("symlink")
            lock_path = self._root / ".writer.lock"
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(lock_path, flags, 0o600)
            os.fchmod(descriptor, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except Exception:
                os.close(descriptor)
                raise
            self._writer_lock_fd = descriptor
        except OSError as error:
            raise BrokerConfigError("dynamic account storage is unavailable") from error

    def _load(self):
        loaded = []
        seen_provider_ids = set()
        try:
            entries = list(self._accounts_dir.iterdir())
            if len(entries) > self.config.max_accounts:
                raise ValueError("account capacity")
            for entry in entries:
                if entry.is_symlink() or not entry.is_dir() or not entry.name.startswith("p_"):
                    raise ValueError("invalid account directory")
                if stat.S_IMODE(entry.stat().st_mode) != 0o700:
                    raise ValueError("account directory is not private")
                if not (entry / "metadata.json").exists():
                    self._recover_uncommitted_directory(entry)
                    continue
                metadata = self._read_metadata(entry)
                if metadata["provider_instance_id"] in self._static_names or metadata["provider_instance_id"] in seen_provider_ids:
                    raise ValueError("provider collision")
                seen_provider_ids.add(metadata["provider_instance_id"])
                self._accounts[entry.name] = metadata
                if metadata["state"] == "active":
                    credential = entry / metadata["credential_file"]
                    template = self.config.credential_templates.get(metadata["template"])
                    if template is None:
                        raise ValueError("unknown template")
                    credential_available = True
                    try:
                        _require_private_file(credential)
                    except FileNotFoundError:
                        credential_available = False
                    if credential_available:
                        provider = None
                        try:
                            provider = self._create_provider(
                                template, metadata["provider_instance_id"], credential
                            )
                            if not provider.ready or not provider.validate_state():
                                raise ProviderError(
                                    "provider-initialization-failed",
                                    "provider-initialization-failed",
                                    503,
                                )
                        except Exception:
                            # The metadata/ownership registry is valid. Keep
                            # this account addressable to its owner for
                            # reconnect/revoke, but publish no provider handle.
                            if provider is not None:
                                provider.close()
                        else:
                            if metadata["provider_instance_id"] in self._providers:
                                provider.close()
                                raise ValueError("provider collision")
                            handle = DynamicProviderAdapter(provider)
                            self._providers[metadata["provider_instance_id"]] = handle
                            loaded.append(handle)
                self._cleanup_orphans(entry, metadata.get("credential_file"))
        except Exception:
            for provider in loaded:
                provider.close()
            self._providers.clear()
            self._accounts.clear()
            self._healthy = False

    def _read_metadata(self, account_dir):
        path = account_dir / "metadata.json"
        _require_private_file(path)
        data = path.read_bytes()
        if len(data) > 128 * 1024:
            raise ValueError("metadata size")
        metadata = _strict_json(data)
        _validate_metadata(metadata, account_dir.name)
        return metadata

    def _write_metadata(self, account_id, metadata):
        account_dir = self._account_dir(account_id)
        account_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        data = json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
        temporary = account_dir / f".metadata-{secrets.token_hex(12)}.tmp"
        committed = False
        try:
            _atomic_write_new(temporary, data)
            os.replace(temporary, account_dir / "metadata.json")
            committed = True
            _fsync_dir(account_dir)
        except Exception as error:
            raise _MetadataCommitError(committed, error) from error
        finally:
            _safe_unlink(temporary)

    def _cleanup_orphans(self, account_dir, current_file):
        for path in account_dir.iterdir():
            if path.name == "metadata.json" or path.name == current_file:
                continue
            if path.is_symlink() or not path.is_file() or not (FILE_RE.fullmatch(path.name) or path.name.startswith(".metadata-")):
                raise ValueError("unexpected account file")
            _safe_unlink(path)

    def _recover_uncommitted_directory(self, account_dir):
        """Remove only recognized files from a never-committed first enroll."""
        for path in account_dir.iterdir():
            if path.is_symlink() or not path.is_file() or not (
                FILE_RE.fullmatch(path.name) or path.name.startswith(".metadata-")
            ):
                raise ValueError("unexpected uncommitted account file")
            _safe_unlink(path)
        account_dir.rmdir()
        _fsync_dir(self._accounts_dir)

    def _ensure_account_directory(self, account_dir):
        if account_dir.is_symlink():
            raise OSError("symlink")
        created = not account_dir.exists()
        account_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if account_dir.is_symlink() or not account_dir.is_dir():
            raise OSError("invalid account directory")
        os.chmod(account_dir, 0o700)
        if created:
            # The credential and metadata fsyncs cannot make a newly created
            # account durable unless its entry in accounts/ is durable too.
            try:
                _fsync_dir(self._accounts_dir)
            except Exception:
                # Do not leave an unconfirmed directory for a later request to
                # mistake for an already durable entry. If even the cleanup
                # cannot be made durable, storage integrity is uncertain.
                try:
                    account_dir.rmdir()
                    _fsync_dir(self._accounts_dir)
                except Exception:
                    self._latch_unhealthy()
                raise

    def _own_active(self, principal):
        current = self._own_account(principal)
        if current.get("state") != "active":
            raise ProviderError("account-not-found", "account-not-found", 404)
        return current

    def _own_account(self, principal):
        current = self._accounts.get(principal.principal_id)
        if (
            current is None
            or current.get("issuer") != principal.issuer
            or current.get("subject") != principal.subject
        ):
            # This is intentionally indistinguishable from no account.
            raise ProviderError("account-not-found", "account-not-found", 404)
        return current

    def _idempotent(self, current, action, operation_id):
        for operation in current.get("operations", []):
            if operation["id"] == operation_id:
                if (
                    operation["action"] != action
                    or operation["provider_instance_id"] != current["provider_instance_id"]
                ):
                    raise ProviderError("operation-conflict", "operation-conflict", 409)
                return dict(operation["result"])
        return None

    def _record_operation(self, current, action, operation_id, result, provider_id):
        operations = list((current or {}).get("operations", []))
        operations.append(
            {"id": operation_id, "action": action, "provider_instance_id": provider_id, "result": dict(result)}
        )
        return operations[-MAX_OPERATIONS:]

    def _ensure_new_operation(self, current, operation_id):
        if any(operation["id"] == operation_id for operation in current.get("operations", [])):
            raise ProviderError("operation-conflict", "operation-conflict", 409)

    def _new_provider_id(self):
        retained_ids = {account["provider_instance_id"] for account in self._accounts.values()}
        for _ in range(16):
            value = "dpa_" + _b64url(secrets.token_bytes(24))
            if value not in self._static_names and value not in self._providers and value not in retained_ids:
                return value
        raise ProviderError("provider-id-unavailable", "provider-id-unavailable", 503)

    def _require_healthy(self):
        if not self._healthy:
            raise ProviderError("dynamic-accounts-unavailable", "dynamic-accounts-unavailable", 503)

    def _latch_unhealthy(self, extra_provider=None):
        providers = list(self._providers.values())
        if extra_provider is not None and all(extra_provider is not provider for provider in providers):
            providers.append(extra_provider)
        self._providers.clear()
        self._healthy = False
        for provider in providers:
            provider.close()

    def _account_dir(self, account_id):
        if not account_id.startswith("p_") or "/" in account_id:
            raise ValueError("invalid account id")
        return self._accounts_dir / account_id

    def _unlink_credential(self, account_id, filename):
        if isinstance(filename, str) and FILE_RE.fullmatch(filename):
            _safe_unlink(self._account_dir(account_id) / filename)


def _validate_metadata(value, directory_name):
    expected = {
        "version", "principal_id", "issuer", "subject", "state", "template", "provider_instance_id",
        "generation", "credential_file", "created_at", "updated_at", "operations",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("invalid metadata")
    if value["version"] != METADATA_VERSION or value["principal_id"] != directory_name:
        raise ValueError("invalid metadata")
    if not _identity_value(value["issuer"]) or not _identity_value(value["subject"]):
        raise ValueError("invalid principal identity")
    if principal_id(value["issuer"], value["subject"]) != directory_name:
        raise ValueError("invalid principal binding")
    if value["state"] not in ("active", "revoked"):
        raise ValueError("invalid state")
    if not NAME_RE.fullmatch(value["template"]) or not (
        isinstance(value["provider_instance_id"], str) and PROVIDER_ID_RE.fullmatch(value["provider_instance_id"])
    ):
        raise ValueError("invalid template/provider")
    if not isinstance(value["generation"], int) or isinstance(value["generation"], bool) or value["generation"] < 1:
        raise ValueError("invalid generation")
    if value["state"] == "active":
        if not isinstance(value["credential_file"], str) or not FILE_RE.fullmatch(value["credential_file"]):
            raise ValueError("invalid credential reference")
        if not value["credential_file"].startswith(f"credential-{value['generation']}-"):
            raise ValueError("credential generation mismatch")
    elif value["credential_file"] is not None:
        raise ValueError("invalid revoked credential")
    for key in ("created_at", "updated_at"):
        if not isinstance(value[key], int) or isinstance(value[key], bool) or value[key] < 0:
            raise ValueError("invalid timestamp")
    if not isinstance(value["operations"], list) or len(value["operations"]) > MAX_OPERATIONS:
        raise ValueError("invalid operations")
    for operation in value["operations"]:
        if (
            not isinstance(operation, dict)
            or set(operation) != {"id", "action", "provider_instance_id", "result"}
            or not isinstance(operation["id"], str)
            or not operation["id"]
            or len(operation["id"].encode("utf-8")) > MAX_OPERATION_BYTES
            or operation["action"] not in ("enroll", "reconnect", "revoke")
            or not isinstance(operation["provider_instance_id"], str)
            or not PROVIDER_ID_RE.fullmatch(operation["provider_instance_id"])
            or not isinstance(operation["result"], dict)
        ):
            raise ValueError("invalid operation")
        _validate_operation_result(operation["action"], operation["result"])


def _validate_operation_result(action, result):
    if action in ("enroll", "reconnect"):
        if (
            set(result) != {"ok", "state", "template", "generation"}
            or result["ok"] is not True
            or result["state"] != "ready"
            or not isinstance(result["template"], str)
            or not NAME_RE.fullmatch(result["template"])
            or not isinstance(result["generation"], int)
            or isinstance(result["generation"], bool)
            or result["generation"] < 1
        ):
            raise ValueError("invalid operation result")
    elif result != {"ok": True, "state": "revoked"}:
        raise ValueError("invalid operation result")


def _atomic_write_new(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_private_file(path):
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or stat.S_IMODE(details.st_mode) != 0o600:
        raise ValueError("file is not private")


def _fsync_dir(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _safe_unlink(path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_b64url(value):
    if not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid base64url")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if _b64url(decoded) != value:
        raise ValueError("non-canonical base64url")
    return decoded
