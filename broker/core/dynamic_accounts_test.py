import base64
import hmac
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import broker.core.dynamic_accounts as dynamic_accounts_module
from broker.core.config import BrokerConfigError
from broker.core.dynamic_accounts import (
    CoordinationAuthenticator,
    DynamicAccountManager,
    MAX_BODY_BYTES,
    MAX_CREDENTIAL_BYTES,
    Principal,
    PrincipalAuthenticator,
    decode_api_request,
    load_dynamic_accounts_config,
    principal_id,
    sign_principal_assertion,
    sign_coordination_assertion,
)
from broker.core.errors import ProviderError
from broker.core.providers import InProcessProviderAdapter
from broker.core.server import Broker
from broker.plugins.claude_oauth.provider import ClaudeOAuthProvider


class FakeProvider:
    def __init__(self, entry, fail=False):
        self.name = entry["name"]
        self.path = Path(entry["config"]["credential-file"])
        self.closed = False
        self.external = False
        self.validation_entered = None
        self.validation_release = None
        self.validation_error = None
        if fail or self.path.read_bytes().startswith(b"invalid"):
            raise RuntimeError("provider rejected credential SECRET-NEEDLE")

    @property
    def ready(self):
        return not self.closed

    def validate_state(self):
        if self.validation_error is not None:
            raise self.validation_error
        if self.validation_entered is not None:
            self.validation_entered.set()
            self.validation_release.wait(timeout=5)
        return not self.closed and self.path.is_file()

    def close(self):
        self.closed = True


class FakeFactory:
    supported_plugins = frozenset({"synthetic"})

    def __init__(self):
        self.fail = False
        self.fail_provider_ids = set()
        self.created = []

    def create(self, entry):
        provider = FakeProvider(entry, self.fail or entry["name"] in self.fail_provider_ids)
        self.created.append(provider)
        return provider


class ClaudeFactory:
    supported_plugins = frozenset({"claude-oauth"})

    def __init__(self):
        self.created = []

    def create(self, entry):
        provider = InProcessProviderAdapter(ClaudeOAuthProvider(entry))
        self.created.append(provider)
        return provider


def configuration(root, *, maximum=8, template="member", switching=False):
    value = {
        "dynamic-accounts": {
            "enabled": True,
            "state-dir": str(root),
            "max-accounts": maximum,
            "authentication": {"hmac-key-env": "TEST_DYNAMIC_ACCOUNT_KEY", "max-assertion-seconds": 60},
            "provider-templates": [
                {
                    "name": "provider-template",
                    "plugin": "synthetic",
                    "credential-config-key": "credential-file",
                    "config": {"safe-setting": "configured-by-admin"},
                }
            ],
            "credential-templates": [
                {
                    "name": template,
                    "label": "Member account",
                    "enrollment-adapter": "approved-adapter",
                    "provider-template": "provider-template",
                },
                {
                    "name": "alternate",
                    "label": "Alternate account",
                    "enrollment-adapter": "alternate-adapter",
                    "provider-template": "provider-template",
                },
            ],
        }
    }
    if switching:
        value["dynamic-accounts"]["template-switching"] = {
            "enabled": True,
            "operator-hmac-key-env": "TEST_DYNAMIC_COORDINATION_KEY",
            "max-assertion-seconds": 60,
            "reservation-seconds": 30,
            "request-seconds": 120,
        }
    return value


class DynamicAccountsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "accounts"
        self.key = b"k" * 32
        self.coordination_key = b"c" * 32
        self.environment = mock.patch.dict(os.environ, {
            "TEST_DYNAMIC_ACCOUNT_KEY": self.key.decode(),
            "TEST_DYNAMIC_COORDINATION_KEY": self.coordination_key.decode(),
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.factory = FakeFactory()
        self.config = load_dynamic_accounts_config(configuration(self.root), self.factory.supported_plugins)

        eligibility_expires_at = int(time.time()) + 1800
        self.alice = Principal(
            "https://issuer.example", "alice-immutable",
            principal_id("https://issuer.example", "alice-immutable"), eligibility_expires_at,
        )
        self.bob = Principal(
            "https://issuer.example", "bob-immutable",
            principal_id("https://issuer.example", "bob-immutable"), eligibility_expires_at,
        )

    def manager(self, config=None, factory=None):
        manager = DynamicAccountManager(config or self.config, factory or self.factory, {"shared-static"})
        self.addCleanup(manager.close)
        return manager

    def test_disabled_is_inert_and_preserves_absent_configuration(self):
        self.assertFalse(load_dynamic_accounts_config({}, set()).enabled)
        with mock.patch.dict(os.environ, {}, clear=True):
            value = load_dynamic_accounts_config({"dynamic-accounts": {"enabled": False}}, set())
        self.assertFalse(value.enabled)

    def test_configuration_is_strict_and_provider_neutral(self):
        broken = configuration(self.root)
        broken["dynamic-accounts"]["credential-templates"][0]["provider-template"] = "missing"
        with self.assertRaisesRegex(BrokerConfigError, "unknown"):
            load_dynamic_accounts_config(broken, self.factory.supported_plugins)
        broken = configuration(self.root)
        broken["dynamic-accounts"]["provider-templates"][0]["config"]["credential-file"] = "/caller"
        with self.assertRaisesRegex(BrokerConfigError, "must not set"):
            load_dynamic_accounts_config(broken, self.factory.supported_plugins)
        broken = configuration(self.root)
        broken["dynamic-accounts"]["authentication"]["max-eligibility-lease-seconds"] = 299
        with self.assertRaisesRegex(BrokerConfigError, "eligibility"):
            load_dynamic_accounts_config(broken, self.factory.supported_plugins)

    def test_assertion_binds_exact_issuer_and_subject_and_fails_closed(self):
        authenticator = PrincipalAuthenticator(self.key, 60)
        assertion = sign_principal_assertion(self.key, self.alice.issuer, self.alice.subject, int(time.time()) + 30)
        self.assertEqual(
            authenticator.authenticate(assertion),
            Principal(self.alice.issuer, self.alice.subject, self.alice.principal_id),
        )
        for invalid in (
            assertion + "x",
            sign_principal_assertion(self.key, self.alice.issuer, self.alice.subject, int(time.time()) - 1),
            sign_principal_assertion(self.key, self.alice.issuer, self.alice.subject, int(time.time()) + 61),
            None,
        ):
            with self.assertRaisesRegex(ProviderError, "unauthorized"):
                authenticator.authenticate(invalid)
        self.assertNotEqual(
            principal_id("https://issuer-a", "same"),
            principal_id("https://issuer-b", "same"),
        )
        raw = json.dumps(
            {
                "audience": "nvt.broker.principal-accounts/v1",
                "expires_at": int(time.time()) + 30,
                "issuer": self.alice.issuer,
                "subject": self.alice.subject,
                "version": True,
            },
            separators=(",", ":"),
        ).encode()
        encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        signature = base64.urlsafe_b64encode(hmac.digest(self.key, raw, "sha256")).rstrip(b"=").decode()
        with self.assertRaisesRegex(ProviderError, "unauthorized"):
            authenticator.authenticate(f"NVT-Principal-v1 {encoded}.{signature}")

    def test_signed_eligibility_lease_expires_renews_revokes_and_survives_restart(self):
        now = [1_700_000_000]
        principal = Principal(
            self.alice.issuer, self.alice.subject, self.alice.principal_id, now[0] + 60,
        )
        manager = DynamicAccountManager(
            self.config, self.factory, {"shared-static"}, clock=lambda: now[0]
        )
        self.addCleanup(manager.close)
        manager.enroll(principal, "member", "lease-enroll", bytearray(b"usable"))
        provider_id = manager.resolve(principal)["provider_instance_id"]

        now[0] += 61
        for operation in (manager.readiness, manager.resolve):
            with self.assertRaisesRegex(ProviderError, "principal-not-eligible") as denied:
                operation(principal)
            self.assertEqual((denied.exception.reason, denied.exception.status), ("principal-not-eligible", 403))
        # Existing AgentRuns retain their frozen provider handle; lease expiry
        # gates only new resolution/admission.
        self.assertTrue(manager.provider(provider_id).ready)

        renewed = Principal(
            principal.issuer, principal.subject, principal.principal_id, now[0] + 120,
        )
        manager.renew_eligibility(renewed)
        self.assertEqual(manager.readiness(renewed)["state"], "ready")
        manager.close()

        restarted = DynamicAccountManager(
            self.config, FakeFactory(), {"shared-static"}, clock=lambda: now[0]
        )
        self.addCleanup(restarted.close)
        self.assertEqual(restarted.resolve(renewed)["provider_instance_id"], provider_id)
        restarted.revoke_eligibility(renewed)
        with self.assertRaisesRegex(ProviderError, "principal-not-eligible"):
            restarted.resolve(renewed)

        assertion = sign_principal_assertion(
            self.key, principal.issuer, principal.subject, now[0] + 30, now[0] + 120,
        )
        authenticated = PrincipalAuthenticator(
            self.key, 60, 120, clock=lambda: now[0]
        ).authenticate(assertion)
        self.assertEqual(authenticated.eligibility_expires_at, now[0] + 120)
        with self.assertRaisesRegex(ProviderError, "unauthorized"):
            PrincipalAuthenticator(self.key, 60, 120, clock=lambda: now[0]).authenticate(
                sign_principal_assertion(
                    self.key, principal.issuer, principal.subject, now[0] + 30, now[0] + 121,
                )
            )

    def test_coordination_assertion_binds_operation_body_and_expiry(self):
        now = 1_700_000_000
        body = b'{"operation_id":"one"}'
        assertion = sign_coordination_assertion(
            self.coordination_key, "begin-admission", body, now + 30
        )
        authenticator = CoordinationAuthenticator(self.coordination_key, 60, clock=lambda: now)
        self.assertIsNone(authenticator.authenticate(assertion, "begin-admission", body))
        for operation, candidate_body, expires in (
            ("end-admission", body, now + 30),
            ("begin-admission", b'{"operation_id":"two"}', now + 30),
            ("begin-admission", body, now - 1),
            ("begin-admission", body, now + 61),
        ):
            candidate = sign_coordination_assertion(
                self.coordination_key, "begin-admission", body, expires
            )
            with self.assertRaisesRegex(ProviderError, "unauthorized"):
                authenticator.authenticate(candidate, operation, candidate_body)

    def test_prelease_account_is_preserved_but_requires_current_renewal(self):
        manager = self.manager()
        manager.enroll(self.alice, "member", "legacy-enroll", bytearray(b"usable"))
        account_dir = next((self.root / "accounts").iterdir())
        metadata_path = account_dir / "metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata.pop("eligibility_expires_at")
        metadata_path.write_text(
            json.dumps(metadata, separators=(",", ":"), sort_keys=True), encoding="utf-8"
        )
        os.chmod(metadata_path, 0o600)
        manager.close()

        restarted = self.manager(factory=FakeFactory())
        self.assertTrue(restarted.system_ready())
        with self.assertRaisesRegex(ProviderError, "principal-not-eligible"):
            restarted.resolve(self.alice)
        restarted.renew_eligibility(self.alice)
        self.assertEqual(restarted.resolve(self.alice)["generation"], 1)

    def test_strict_request_codec_rejects_destinations_and_duplicate_fields(self):
        with self.assertRaisesRegex(ProviderError, "invalid-request"):
            decode_api_request(b'{"operation_id":"one","operation_id":"two"}', "revoke")
        with self.assertRaisesRegex(ProviderError, "invalid-request"):
            decode_api_request(b'{"operation_id":"one","provider":"shared-static"}', "revoke")
        payload, credential = decode_api_request(
            b'{"template":"member","operation_id":"one","credential_base64":"c2FmZQ=="}', "enroll"
        )
        self.assertEqual(payload["template"], "member")
        self.assertEqual(credential, b"safe")

    def test_request_and_credential_size_boundaries_are_reachable_and_strict(self):
        credential = b"x" * MAX_CREDENTIAL_BYTES
        raw = json.dumps(
            {
                "template": "member",
                "operation_id": "maximum-credential",
                "credential_base64": base64.b64encode(credential).decode(),
            },
            separators=(",", ":"),
        ).encode()
        self.assertLessEqual(len(raw), MAX_BODY_BYTES)
        _, decoded = decode_api_request(raw, "enroll")
        self.assertEqual(len(decoded), MAX_CREDENTIAL_BYTES)

        oversized_credential = base64.b64encode(b"x" * (MAX_CREDENTIAL_BYTES + 1)).decode()
        oversized_raw = json.dumps(
            {
                "template": "member",
                "operation_id": "oversized-credential",
                "credential_base64": oversized_credential,
            },
            separators=(",", ":"),
        ).encode()
        self.assertLessEqual(len(oversized_raw), MAX_BODY_BYTES)
        with self.assertRaisesRegex(ProviderError, "invalid-request"):
            decode_api_request(oversized_raw, "enroll")
        with self.assertRaisesRegex(ProviderError, "invalid-request"):
            decode_api_request(b" " * (MAX_BODY_BYTES + 1), "enroll")

    def test_enroll_resolve_reconnect_and_restart_recovery(self):
        manager = self.manager()
        first = manager.enroll(self.alice, "member", "enroll-1", bytearray(b"credential-one"))
        self.assertEqual(first["generation"], 1)
        resolved = manager.resolve(self.alice)
        self.assertTrue(resolved["provider_instance_id"].startswith("dpa_"))
        self.assertNotEqual(resolved["provider_instance_id"], "shared-static")
        first_file = self.factory.created[-1].path
        self.assertEqual(first_file.stat().st_mode & 0o777, 0o600)
        metadata_file = first_file.parent / "metadata.json"
        self.assertEqual(metadata_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / ".writer.lock").stat().st_mode & 0o777, 0o600)
        second = manager.reconnect(self.alice, "reconnect-1", bytearray(b"credential-two"))
        self.assertEqual(second["generation"], 2)
        self.assertFalse(first_file.exists())
        current_id = manager.resolve(self.alice)["provider_instance_id"]
        manager.close()

        recovered = self.manager(factory=FakeFactory())
        self.assertEqual(recovered.resolve(self.alice)["provider_instance_id"], current_id)
        self.assertEqual(recovered.readiness(self.alice)["state"], "ready")

    def test_first_enrollment_fsyncs_parent_directory_before_metadata_commit(self):
        manager = self.manager()
        with mock.patch(
            "broker.core.dynamic_accounts._fsync_dir",
            wraps=dynamic_accounts_module._fsync_dir,
        ) as fsync_dir:
            manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
        synced = [call.args[0] for call in fsync_dir.call_args_list]
        account_dir = self.root / "accounts" / self.alice.principal_id
        self.assertEqual(synced[0], self.root / "accounts")
        self.assertIn(account_dir, synced)

        with mock.patch(
            "broker.core.dynamic_accounts._fsync_dir",
            wraps=dynamic_accounts_module._fsync_dir,
        ) as reconnect_fsync:
            manager.reconnect(self.alice, "reconnect", bytearray(b"replacement"))
        self.assertNotIn(self.root / "accounts", [call.args[0] for call in reconnect_fsync.call_args_list])

    def test_parent_directory_fsync_failure_prevents_first_enrollment_commit(self):
        manager = self.manager()
        real_fsync = dynamic_accounts_module._fsync_dir

        def fail_parent(path):
            if path == self.root / "accounts":
                raise OSError("parent fsync failed")
            return real_fsync(path)

        with mock.patch("broker.core.dynamic_accounts._fsync_dir", side_effect=fail_parent):
            with self.assertRaisesRegex(ProviderError, "account-storage-unavailable"):
                manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
        account_dir = self.root / "accounts" / self.alice.principal_id
        self.assertFalse(manager.system_ready())
        self.assertFalse(account_dir.exists())
        self.assertFalse((account_dir / "metadata.json").exists())
        self.assertEqual(list(account_dir.glob("credential-*.bin")), [])

    def test_concurrent_idempotent_enrollment_creates_one_account(self):
        manager = self.manager()
        results = []
        failures = []
        barrier = threading.Barrier(8)

        def enroll():
            try:
                barrier.wait()
                results.append(manager.enroll(self.alice, "member", "same-operation", bytearray(b"same")))
            except Exception as error:  # pragma: no cover - asserted below
                failures.append(error)

        threads = [threading.Thread(target=enroll) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])
        self.assertEqual(results, [results[0]] * 8)
        self.assertEqual(len(list((self.root / "accounts").glob("p_*/credential-*.bin"))), 1)

    def test_reconnect_waits_for_old_provider_leases_before_retirement(self):
        manager = self.manager()
        manager.enroll(self.alice, "member", "enroll", bytearray(b"one"))
        resolved = manager.resolve(self.alice)
        handle = manager.provider(resolved["provider_instance_id"])
        old = self.factory.created[-1]
        old.validation_entered = threading.Event()
        old.validation_release = threading.Event()
        validation_results = []
        replacement_results = []

        validating = threading.Thread(target=lambda: validation_results.append(handle.validate_state()))
        validating.start()
        self.assertTrue(old.validation_entered.wait(timeout=2))
        replacing = threading.Thread(
            target=lambda: replacement_results.append(
                manager.reconnect(self.alice, "reconnect", bytearray(b"two"))
            )
        )
        replacing.start()
        time.sleep(0.05)
        self.assertTrue(replacing.is_alive())
        self.assertFalse(old.closed)
        old.validation_release.set()
        validating.join(timeout=2)
        replacing.join(timeout=2)
        self.assertFalse(validating.is_alive())
        self.assertFalse(replacing.is_alive())
        self.assertEqual(validation_results, [True])
        self.assertEqual(replacement_results[0]["generation"], 2)
        self.assertTrue(old.closed)
        self.assertTrue(handle.validate_state())

    def test_second_writer_is_rejected(self):
        manager = self.manager()
        with self.assertRaisesRegex(BrokerConfigError, "storage is unavailable"):
            DynamicAccountManager(self.config, FakeFactory())
        self.assertTrue(manager.healthy)

    def test_static_provider_cannot_overlap_dynamic_id_namespace(self):
        collision = "dpa_" + "A" * 32
        with self.assertRaisesRegex(BrokerConfigError, "collides"):
            DynamicAccountManager(self.config, FakeFactory(), {collision})

    def test_cross_principal_denial_does_not_reveal_account(self):
        manager = self.manager()
        manager.enroll(self.alice, "member", "enroll", bytearray(b"alice-only"))
        for method in (manager.resolve, manager.readiness):
            with self.assertRaises(ProviderError) as missing:
                method(self.bob)
            self.assertEqual((missing.exception.reason, missing.exception.status), ("account-not-found", 404))
        with self.assertRaises(ProviderError) as reconnect:
            manager.reconnect(self.bob, "operation", bytearray(b"bob"))
        self.assertEqual((reconnect.exception.reason, reconnect.exception.status), ("account-not-found", 404))

    def test_unknown_template_and_implicit_switch_fail_closed(self):
        manager = self.manager()
        with self.assertRaisesRegex(ProviderError, "unknown-template"):
            manager.enroll(self.alice, "not-approved", "unknown", bytearray(b"usable"))
        manager.enroll(self.alice, "member", "approved", bytearray(b"usable"))
        with self.assertRaisesRegex(ProviderError, "account-already-enrolled"):
            manager.enroll(self.alice, "not-approved", "switch", bytearray(b"other"))

    def test_provider_failure_preserves_last_usable_generation(self):
        manager = self.manager()
        manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
        before = manager.resolve(self.alice)
        before_files = list((self.root / "accounts" / self.alice.principal_id).glob("credential-*.bin"))
        with self.assertRaisesRegex(ProviderError, "provider-initialization-failed"):
            manager.reconnect(self.alice, "bad", bytearray(b"invalid SECRET-NEEDLE"))
        self.assertEqual(manager.resolve(self.alice), before)
        self.assertEqual(list((self.root / "accounts" / self.alice.principal_id).glob("credential-*.bin")), before_files)

    def test_missing_committed_credential_fails_only_account_readiness(self):
        manager = self.manager()
        manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
        provider_id = manager.resolve(self.alice)["provider_instance_id"]
        self.factory.created[-1].path.unlink()
        self.assertTrue(manager.system_ready())
        self.assertEqual(
            manager.readiness(self.alice),
            {"ok": True, "state": "unready", "template": "member", "generation": 1},
        )
        with self.assertRaisesRegex(ProviderError, "account-unready"):
            manager.resolve(self.alice)
        with self.assertRaisesRegex(ProviderError, "account-unready"):
            manager.provider(provider_id)

    def test_provider_validation_diagnostics_are_normalized_for_every_account_path(self):
        manager = self.manager()
        manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
        provider_id = manager.resolve(self.alice)["provider_instance_id"]
        self.factory.created[-1].validation_error = ProviderError(
            "auth-file-invalid",
            "provider diagnostic SECRET-VALIDATION-NEEDLE",
            502,
        )

        self.assertEqual(
            manager.readiness(self.alice),
            {"ok": True, "state": "unready", "template": "member", "generation": 1},
        )
        for operation in (lambda: manager.resolve(self.alice), lambda: manager.provider(provider_id)):
            with self.assertRaises(ProviderError) as denied:
                operation()
            self.assertEqual(denied.exception.reason, "account-unready")
            self.assertEqual(denied.exception.message, "account-unready")
            self.assertEqual(denied.exception.status, 503)
            self.assertNotIn("SECRET-VALIDATION-NEEDLE", str(denied.exception))

        self.assertTrue(manager.system_ready())

    def test_interrupted_replacement_orphan_is_removed_on_restart(self):
        manager = self.manager()
        manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
        account_dir = self.root / "accounts" / self.alice.principal_id
        orphan = account_dir / "credential-2-abcdefghijklmnop.bin"
        orphan.write_bytes(b"SECRET-ORPHAN")
        orphan.chmod(0o600)
        manager.close()
        recovered = self.manager(factory=FakeFactory())
        self.assertEqual(recovered.resolve(self.alice)["generation"], 1)
        self.assertFalse(orphan.exists())

    def test_provider_credential_lock_survives_restart_and_broker_is_ready(self):
        raw_config = configuration(self.root)
        provider_template = raw_config["dynamic-accounts"]["provider-templates"][0]
        provider_template["plugin"] = "claude-oauth"
        provider_template["credential-config-key"] = "credentials-file"
        provider_template["config"] = {}
        factory = ClaudeFactory()
        config = load_dynamic_accounts_config(raw_config, factory.supported_plugins)
        manager = self.manager(config=config, factory=factory)
        credential_payload = json.dumps({
            "claudeAiOauth": {
                "accessToken": "SECRET-ACCESS",
                "refreshToken": "SECRET-REFRESH",
            }
        }).encode()
        manager.enroll(self.alice, "member", "enroll", bytearray(credential_payload))
        provider = factory.created[-1]._provider
        credential = provider.credentials_file
        with provider._refresh_guard():
            pass
        lock = credential.with_name(f".{credential.name}.refresh.lock")
        self.assertTrue(lock.is_file())
        manager.close()

        restarted = self.manager(config=config, factory=ClaudeFactory())
        self.assertTrue(restarted.system_ready())
        self.assertEqual(restarted.readiness(self.alice)["state"], "ready")
        self.assertTrue(lock.is_file())

        broker = Broker.__new__(Broker)
        broker.dynamic_accounts = restarted
        broker.providers = {}
        self.assertEqual(Broker.readiness(broker), {"ok": True, "status": "ready"})

    def test_stale_credential_and_lock_are_removed_together_on_restart(self):
        manager = self.manager()
        manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
        account_dir = self.root / "accounts" / self.alice.principal_id
        stale = account_dir / "credential-2-abcdefghijklmnop.bin"
        stale.write_bytes(b"SECRET-STALE")
        stale.chmod(0o600)
        stale_lock = account_dir / f".{stale.name}.refresh.lock"
        stale_lock.touch(mode=0o600)
        stale_lock.chmod(0o600)
        manager.close()

        recovered = self.manager(factory=FakeFactory())
        self.assertTrue(recovered.system_ready())
        self.assertFalse(stale.exists())
        self.assertFalse(stale_lock.exists())

    def test_uncommitted_credential_and_lock_directory_is_recovered(self):
        account_dir = self.root / "accounts" / self.alice.principal_id
        account_dir.mkdir(parents=True, mode=0o700)
        credential = account_dir / "credential-1-abcdefghijklmnop.bin"
        credential.write_bytes(b"SECRET-UNCOMMITTED")
        credential.chmod(0o600)
        lock = account_dir / f".{credential.name}.refresh.lock"
        lock.touch(mode=0o600)
        lock.chmod(0o600)

        manager = self.manager(factory=FakeFactory())
        self.assertTrue(manager.system_ready())
        self.assertFalse(account_dir.exists())

    def test_unsafe_lock_artifacts_latch_storage_unhealthy_without_partial_cleanup(self):
        cases = ("unrelated", "orphan", "non-private", "non-empty", "directory", "symlink")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "accounts"
                config = load_dynamic_accounts_config(configuration(root), self.factory.supported_plugins)
                manager = DynamicAccountManager(config, FakeFactory(), {"shared-static"})
                manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
                account_dir = root / "accounts" / self.alice.principal_id
                stale = account_dir / "credential-2-abcdefghijklmnop.bin"
                stale.write_bytes(b"SECRET-STALE")
                stale.chmod(0o600)
                stale_lock = account_dir / f".{stale.name}.refresh.lock"
                stale_lock.touch(mode=0o600)
                stale_lock.chmod(0o600)
                current = manager._accounts[self.alice.principal_id]["credential_file"]
                unsafe = account_dir / f".{current}.refresh.lock"
                if case == "unrelated":
                    unsafe = account_dir / ".unrelated"
                    unsafe.touch(mode=0o600)
                elif case == "orphan":
                    unsafe = account_dir / ".credential-9-ponmlkjihgfedcba.bin.refresh.lock"
                    unsafe.touch(mode=0o600)
                elif case == "non-private":
                    unsafe.touch(mode=0o600)
                    unsafe.chmod(0o644)
                elif case == "non-empty":
                    unsafe.write_bytes(b"not-an-empty-lock")
                    unsafe.chmod(0o600)
                elif case == "directory":
                    unsafe.mkdir(mode=0o700)
                else:
                    unsafe.symlink_to(account_dir / current)
                manager.close()

                recovered = DynamicAccountManager(config, FakeFactory(), {"shared-static"})
                self.addCleanup(recovered.close)
                self.assertFalse(recovered.system_ready())
                self.assertTrue(stale.exists())
                self.assertTrue(stale_lock.exists())

    def test_interrupted_first_enrollment_directory_is_recovered(self):
        account_dir = self.root / "accounts" / self.alice.principal_id
        account_dir.mkdir(parents=True, mode=0o700)
        orphan = account_dir / "credential-1-abcdefghijklmnop.bin"
        orphan.write_bytes(b"SECRET-UNCOMMITTED")
        orphan.chmod(0o600)
        with mock.patch(
            "broker.core.dynamic_accounts._fsync_dir",
            wraps=dynamic_accounts_module._fsync_dir,
        ) as fsync_dir:
            manager = self.manager(factory=FakeFactory())
        self.assertTrue(manager.healthy)
        self.assertFalse(account_dir.exists())
        self.assertIn(self.root / "accounts", [call.args[0] for call in fsync_dir.call_args_list])
        self.assertEqual(manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))["generation"], 1)

    def test_corrupt_and_unknown_template_storage_latch_unready(self):
        manager = self.manager()
        manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
        manager.close()
        metadata = self.root / "accounts" / self.alice.principal_id / "metadata.json"
        metadata.write_text("{broken", encoding="utf-8")
        metadata.chmod(0o600)
        corrupt = self.manager(factory=FakeFactory())
        self.assertFalse(corrupt.healthy)
        with self.assertRaisesRegex(ProviderError, "dynamic-accounts-unavailable"):
            corrupt.resolve(self.alice)

        # A valid manifest that references a no-longer-approved template also
        # fails closed rather than selecting a static/shared provider.
        second_root = Path(self.temporary.name) / "unknown-template"
        second_config = load_dynamic_accounts_config(configuration(second_root), self.factory.supported_plugins)
        second = self.manager(config=second_config)
        second.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
        second.close()
        changed = load_dynamic_accounts_config(configuration(second_root, template="replacement"), self.factory.supported_plugins)
        unknown = self.manager(config=changed, factory=FakeFactory())
        self.assertFalse(unknown.healthy)

    def test_restart_provider_failure_is_account_local_and_reconnect_recovers(self):
        manager = self.manager()
        manager.enroll(self.alice, "member", "alice-enroll", bytearray(b"alice-usable"))
        manager.enroll(self.bob, "member", "bob-enroll", bytearray(b"bob-usable"))
        alice_resolution = manager.resolve(self.alice)
        bob_resolution = manager.resolve(self.bob)
        manager.close()
        failing = FakeFactory()
        failing.fail_provider_ids.add(alice_resolution["provider_instance_id"])
        recovered = self.manager(factory=failing)
        self.assertTrue(recovered.system_ready())
        self.assertEqual(recovered.resolve(self.bob), bob_resolution)
        self.assertEqual(
            recovered.readiness(self.alice),
            {"ok": True, "state": "unready", "template": "member", "generation": 1},
        )
        with self.assertRaisesRegex(ProviderError, "account-unready"):
            recovered.resolve(self.alice)
        with self.assertRaisesRegex(ProviderError, "account-unready"):
            recovered.provider(alice_resolution["provider_instance_id"])

        static = mock.Mock(ready=True)
        static.validate_state.return_value = True
        broker = Broker.__new__(Broker)
        broker.dynamic_accounts = recovered
        broker.providers = {"shared-static": static}
        self.assertEqual(Broker.readiness(broker), {"ok": True, "status": "ready"})
        self.assertIs(Broker.provider(broker, "shared-static"), static)

        failing.fail_provider_ids.clear()
        restored = recovered.reconnect(self.alice, "alice-reconnect", bytearray(b"alice-restored"))
        self.assertEqual(restored["generation"], 2)
        self.assertEqual(
            recovered.resolve(self.alice)["provider_instance_id"],
            alice_resolution["provider_instance_id"],
        )
        self.assertEqual(recovered.resolve(self.bob), bob_resolution)

        # A second degraded restart also keeps authenticated revoke available.
        recovered.close()
        degraded_again = FakeFactory()
        degraded_again.fail_provider_ids.add(alice_resolution["provider_instance_id"])
        revocable = self.manager(factory=degraded_again)
        self.assertTrue(revocable.system_ready())
        self.assertEqual(revocable.revoke(self.alice, "alice-revoke")["state"], "revoked")
        self.assertEqual(revocable.resolve(self.bob), bob_resolution)

    def test_restart_invalid_credential_is_account_local(self):
        manager = self.manager()
        manager.enroll(self.alice, "member", "alice-enroll", bytearray(b"alice-usable"))
        manager.enroll(self.bob, "member", "bob-enroll", bytearray(b"bob-usable"))
        alice_file = self.factory.created[0].path
        bob_resolution = manager.resolve(self.bob)
        manager.close()
        alice_file.write_bytes(b"invalid credential")
        alice_file.chmod(0o600)

        recovered = self.manager(factory=FakeFactory())
        self.assertTrue(recovered.system_ready())
        with self.assertRaisesRegex(ProviderError, "account-unready"):
            recovered.resolve(self.alice)
        self.assertEqual(recovered.resolve(self.bob), bob_resolution)
        recovered.reconnect(self.alice, "alice-reconnect", bytearray(b"restored"))
        self.assertEqual(recovered.readiness(self.alice)["state"], "ready")

    def test_account_capacity_counts_durable_revoked_tombstones(self):
        bounded = load_dynamic_accounts_config(configuration(self.root, maximum=1), self.factory.supported_plugins)
        manager = self.manager(config=bounded)
        manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
        manager.revoke(self.alice, "revoke")
        with self.assertRaisesRegex(ProviderError, "capacity-exceeded"):
            manager.enroll(self.bob, "member", "bob-enroll", bytearray(b"usable"))
        # The same principal can explicitly re-enroll without creating a
        # second durable account record.
        self.assertEqual(manager.enroll(self.alice, "member", "reenroll", bytearray(b"usable"))["generation"], 2)
        with self.assertRaisesRegex(ProviderError, "operation-conflict"):
            manager.revoke(self.alice, "revoke")

    def test_storage_failure_does_not_publish_new_provider(self):
        manager = self.manager()
        manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
        before = manager.resolve(self.alice)
        with mock.patch.object(manager, "_write_metadata", side_effect=OSError("disk SECRET-NEEDLE")):
            with self.assertRaisesRegex(ProviderError, "account-storage-unavailable"):
                manager.reconnect(self.alice, "replace", bytearray(b"new-secret"))
        self.assertEqual(manager.resolve(self.alice), before)

    def test_uncertain_metadata_fsync_preserves_recoverable_generation_and_fails_closed(self):
        manager = self.manager()
        manager.enroll(self.alice, "member", "enroll", bytearray(b"usable-one"))
        with mock.patch("broker.core.dynamic_accounts._fsync_dir", side_effect=OSError("fsync failed")):
            with self.assertRaisesRegex(ProviderError, "account-storage-unavailable"):
                manager.reconnect(self.alice, "replace", bytearray(b"usable-two"))
        self.assertFalse(manager.healthy)
        with self.assertRaisesRegex(ProviderError, "dynamic-accounts-unavailable"):
            manager.resolve(self.alice)
        manager.close()
        recovered = self.manager(factory=FakeFactory())
        self.assertTrue(recovered.healthy)
        self.assertEqual(recovered.resolve(self.alice)["generation"], 2)
        self.assertEqual(len(list((self.root / "accounts").glob("p_*/credential-*.bin"))), 1)

    def test_revoke_is_idempotent_durable_and_keeps_template_locked(self):
        manager = self.manager()
        manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
        first = manager.revoke(self.alice, "revoke-1")
        self.assertEqual(manager.revoke(self.alice, "revoke-1"), first)
        self.assertEqual(
            manager.readiness(self.alice),
            {"ok": True, "state": "revoked", "template": "member", "generation": 1},
        )
        with self.assertRaisesRegex(ProviderError, "account-not-found"):
            manager.resolve(self.alice)
        self.assertEqual(list((self.root / "accounts").glob("p_*/credential-*.bin")), [])
        manager.close()
        recovered = self.manager(factory=FakeFactory())
        with self.assertRaisesRegex(ProviderError, "account-not-found"):
            recovered.resolve(self.alice)
        self.assertEqual(recovered.readiness(self.alice)["template"], "member")
        with self.assertRaisesRegex(ProviderError, "template-switch-not-authorized"):
            recovered.enroll(self.alice, "alternate", "switch", bytearray(b"new"))
        self.assertEqual(recovered.enroll(self.alice, "member", "enroll-2", bytearray(b"new"))["generation"], 2)

    def test_operator_authorized_switch_is_target_free_durable_and_exact_principal(self):
        config = load_dynamic_accounts_config(
            configuration(self.root, switching=True), self.factory.supported_plugins
        )
        manager = self.manager(config=config)
        manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
        manager.revoke(self.alice, "revoke")
        pending = manager.request_template_switch(self.alice, "request")
        self.assertEqual(pending["state"], "pending")
        operation_id = "operator-proof"
        identity = manager.begin_template_switch(pending["request_id"], operation_id)
        self.assertEqual((identity["issuer"], identity["subject"]), (self.alice.issuer, self.alice.subject))
        with self.assertRaisesRegex(ProviderError, "account-not-found"):
            manager.commit_template_switch(self.bob, operation_id)
        self.assertEqual(manager.commit_template_switch(self.alice, operation_id)["state"], "authorized")
        # A lost operator response can retry the same target-free capability;
        # the committed proof remains durable and idempotent until enrollment.
        self.assertEqual(
            manager.begin_template_switch(pending["request_id"], operation_id)["subject"],
            self.alice.subject,
        )
        self.assertEqual(manager.commit_template_switch(self.alice, operation_id)["state"], "authorized")
        manager.close()
        manager = DynamicAccountManager(config, FakeFactory(), {"shared-static"})
        self.addCleanup(manager.close)
        self.assertEqual(
            manager.begin_template_switch(pending["request_id"], operation_id)["subject"],
            self.alice.subject,
        )
        self.assertEqual(manager.commit_template_switch(self.alice, operation_id)["state"], "authorized")
        switched = manager.enroll(self.alice, "alternate", "switch-enroll", bytearray(b"usable-new"))
        self.assertEqual((switched["template"], switched["generation"]), ("alternate", 2))
        metadata = (self.root / "accounts" / self.alice.principal_id / "metadata.json").read_bytes()
        self.assertNotIn(b"usable", metadata)
        self.assertNotIn(b"operator-proof", metadata)

    def test_disabling_switching_ignores_persisted_unlock_after_restart(self):
        enabled_config = load_dynamic_accounts_config(
            configuration(self.root, switching=True), self.factory.supported_plugins
        )
        manager = self.manager(config=enabled_config)
        manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
        manager.revoke(self.alice, "revoke")
        pending = manager.request_template_switch(self.alice, "request")
        manager.begin_template_switch(pending["request_id"], "operator-proof")
        manager.commit_template_switch(self.alice, "operator-proof")
        manager.close()

        disabled_config = load_dynamic_accounts_config(
            configuration(self.root, switching=False), self.factory.supported_plugins
        )
        recovered = self.manager(config=disabled_config, factory=FakeFactory())
        with self.assertRaisesRegex(ProviderError, "template-switch-not-authorized"):
            recovered.enroll(self.alice, "alternate", "alternate-enroll", bytearray(b"alternate"))
        same_template = recovered.enroll(
            self.alice, "member", "same-template-enroll", bytearray(b"replacement")
        )
        self.assertEqual(
            (same_template["template"], same_template["generation"]),
            ("member", 2),
        )

    def test_admission_reservation_serializes_switch_and_reclaims_after_release_or_expiry(self):
        now = [1_700_000_000]
        principal = Principal(
            self.alice.issuer, self.alice.subject, self.alice.principal_id, now[0] + 1800,
        )
        config = load_dynamic_accounts_config(
            configuration(self.root, switching=True), self.factory.supported_plugins
        )
        manager = DynamicAccountManager(config, self.factory, {"shared-static"}, clock=lambda: now[0])
        self.addCleanup(manager.close)
        manager.enroll(principal, "member", "enroll", bytearray(b"usable"))
        admission_reserved = threading.Event()
        release_admission = threading.Event()
        admission_errors = []

        def admit():
            try:
                self.assertEqual(manager.begin_admission(principal, "admit-1")["state"], "reserved")
                admission_reserved.set()
                if not release_admission.wait(timeout=5):
                    raise TimeoutError("test admission release timed out")
                manager.end_admission(principal, "admit-1")
            except Exception as error:  # pragma: no cover - asserted on the parent thread
                admission_errors.append(error)

        admission_thread = threading.Thread(target=admit)
        admission_thread.start()
        self.addCleanup(release_admission.set)
        self.addCleanup(admission_thread.join, 5)
        self.assertTrue(admission_reserved.wait(timeout=5))
        # Reconnect is always owner-available, but it must preserve the
        # reservation protecting an admission already creating a run.
        manager.reconnect(principal, "reconnect-during-admission", bytearray(b"usable-new"))
        manager.revoke(principal, "revoke")
        pending = manager.request_template_switch(principal, "request")
        with self.assertRaisesRegex(ProviderError, "coordination-conflict"):
            manager.begin_template_switch(pending["request_id"], "switch-1")
        release_admission.set()
        admission_thread.join(timeout=5)
        self.assertFalse(admission_thread.is_alive())
        self.assertEqual(admission_errors, [])
        manager.begin_template_switch(pending["request_id"], "switch-1")
        manager.abort_template_switch(principal, "switch-1")

        manager.begin_template_switch(pending["request_id"], "switch-expiring")
        now[0] += config.coordination_reservation_seconds + 1
        with self.assertRaisesRegex(ProviderError, "coordination-not-held"):
            manager.commit_template_switch(principal, "switch-expiring")
        manager.begin_template_switch(pending["request_id"], "switch-retry")
        manager.commit_template_switch(principal, "switch-retry")
        self.assertEqual(
            manager.enroll(principal, "alternate", "replace", bytearray(b"usable-two"))["template"],
            "alternate",
        )

    def test_coordination_reservation_survives_restart_and_is_idempotent(self):
        config = load_dynamic_accounts_config(
            configuration(self.root, switching=True), self.factory.supported_plugins
        )
        manager = DynamicAccountManager(config, self.factory, {"shared-static"})
        manager.enroll(self.alice, "member", "enroll", bytearray(b"usable"))
        manager.begin_admission(self.alice, "admit-retry")
        manager.close()
        recovered = DynamicAccountManager(config, FakeFactory(), {"shared-static"})
        self.addCleanup(recovered.close)
        self.assertEqual(recovered.begin_admission(self.alice, "admit-retry")["state"], "reserved")
        self.assertEqual(recovered.end_admission(self.alice, "admit-retry")["state"], "released")
        self.assertEqual(recovered.end_admission(self.alice, "admit-retry")["state"], "released")

    def test_secret_needle_never_enters_metadata_or_sanitized_errors(self):
        manager = self.manager()
        needle = b"SUPER-SECRET-NEEDLE"
        manager.enroll(self.alice, "member", "enroll", bytearray(needle))
        metadata = (self.root / "accounts" / self.alice.principal_id / "metadata.json").read_bytes()
        self.assertNotIn(needle, metadata)
        self.assertNotIn(b"credential_base64", metadata)
        with self.assertRaises(ProviderError) as failure:
            manager.reconnect(self.alice, "bad", bytearray(b"invalid " + needle))
        self.assertNotIn("SECRET", str(failure.exception))


if __name__ == "__main__":
    unittest.main()
