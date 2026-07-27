import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from broker.core.guest_enrollment import (
    EnrollmentConfigError,
    EnrollmentFailure,
    EnrollmentFaults,
    GuestEnrollmentIssuer,
    OrchestratorAuthenticator,
    TOMBSTONE_RETENTION,
    VERSION,
    load_guest_enrollment_from_environment,
)


START = datetime(2026, 7, 27, 12, 0, 0, tzinfo=timezone.utc)
EXCHANGE_URL = "https://broker.example/v1/guest-enrollment/exchange"


class Clock:
    def __init__(self):
        self.value = START

    def __call__(self):
        return self.value


class DeterministicRandom:
    def __init__(self, start=1):
        self.value = start

    def __call__(self, size):
        value = bytes([self.value]) * size
        self.value = (self.value + 1) % 256
        return value


class BeforeCommitFailure(EnrollmentFaults):
    def before_exchange_commit(self):
        raise sqlite3.OperationalError("sqlite-secret-canary")


class ResponseLostFailure(EnrollmentFaults):
    def after_exchange_commit(self):
        raise ConnectionAbortedError("response-lost")


class GuestEnrollmentIssuerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = str(Path(self.temporary.name) / "enrollment.sqlite3")
        self.clock = Clock()
        self.random = DeterministicRandom()

    def issuer(self, **overrides):
        arguments = {
            "now": self.clock,
            "random_bytes": self.random,
            "maintenance_interval": None,
        }
        arguments.update(overrides)
        issuer = GuestEnrollmentIssuer(self.database, EXCHANGE_URL, **arguments)
        self.addCleanup(issuer.close)
        return issuer

    def test_valid_exchange_restart_replay_and_non_disclosure(self):
        issuer = self.issuer()
        request = issue_request()
        envelope = issuer.issue(request)
        token = envelope["token"]
        self.assertEqual(Path(self.database).stat().st_mode & 0o777, 0o600)
        snapshot = json.dumps(issuer.snapshot(), sort_keys=True)
        self.assertNotIn(token, snapshot)

        issuer.close()
        restarted = self.issuer()
        result = restarted.exchange(exchange_request(envelope))
        identity = result["runtime_identity"]["opaque"]
        self.assertEqual(result["binding"], request["binding"])
        snapshot = json.dumps(restarted.snapshot(), sort_keys=True)
        self.assertNotIn(token, snapshot)
        self.assertNotIn(identity, snapshot)
        self.assertEqual(snapshot.count('"runtime_identity_active": 1'), 1)
        self.assertFailure("already-consumed", lambda: restarted.exchange(exchange_request(envelope)))

    def test_binding_mismatch_does_not_consume(self):
        issuer = self.issuer()
        envelope = issuer.issue(issue_request())
        wrong = exchange_request(envelope)
        wrong["binding"] = dict(wrong["binding"], guest_instance_id="wrong-guest")
        self.assertFailure("binding-mismatch", lambda: issuer.exchange(wrong))
        result = issuer.exchange(exchange_request(envelope))
        self.assertEqual(result["binding"], envelope["binding"])

    def test_concurrent_exchange_is_single_use(self):
        issuer = self.issuer()
        envelope = issuer.issue(issue_request())

        def exchange_once(_index):
            try:
                return "success", issuer.exchange(exchange_request(envelope))
            except EnrollmentFailure as error:
                return error.reason, None

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(exchange_once, range(16)))
        reasons = [reason for reason, _result in results]
        self.assertEqual(reasons.count("success"), 1)
        self.assertEqual(reasons.count("already-consumed"), 15)
        record = issuer.snapshot()["records"][0]
        self.assertEqual(record["state"], "consumed")
        self.assertEqual(record["runtime_identity_active"], 1)

    def test_execution_revocation_covers_replacements_and_preserves_unrelated(self):
        issuer = self.issuer()
        first_request = issue_request(generation=1, guest="guest-first")
        first = issuer.issue(first_request)
        issuer.exchange(exchange_request(first))
        second = issuer.issue(issue_request(generation=2, guest="guest-replacement"))
        unrelated = issuer.issue(issue_request(uid="uid-unrelated", execution="execution-unrelated", guest="guest-unrelated"))
        issuer.exchange(exchange_request(unrelated))

        issuer.close()
        restarted = self.issuer()
        restarted.revoke_execution(revoke_execution_request(first["binding"]))
        snapshot = restarted.snapshot()
        scopes = {
            (record["agent_run_uid"], record["execution_id"], record["driver_registration"])
            for record in snapshot["records"]
        }
        self.assertNotIn((first["binding"]["agent_run_uid"], first["binding"]["execution_id"], first["binding"]["driver_registration"]), scopes)
        self.assertIn((unrelated["binding"]["agent_run_uid"], unrelated["binding"]["execution_id"], unrelated["binding"]["driver_registration"]), scopes)
        for envelope in (first, second):
            self.assertFailure("revoked", lambda value=envelope: restarted.exchange(exchange_request(value)))
        self.assertFailure("revoked", lambda: restarted.issue(issue_request(generation=3, guest="guest-third")))
        self.assertFailure("already-consumed", lambda: restarted.exchange(exchange_request(unrelated)))

    def test_exact_revoke_is_durable_and_idempotent(self):
        issuer = self.issuer()
        request = issue_request(guest="revoked-guest")
        envelope = issuer.issue(request)
        for _ in range(2):
            issuer.revoke_binding(revoke_binding_request(request["binding"]))
        self.assertFailure("revoked", lambda: issuer.exchange(exchange_request(envelope)))
        self.assertFailure("revoked", lambda: issuer.issue(request))
        self.clock.value += TOMBSTONE_RETENTION
        issuer.maintain()
        self.assertEqual(len(issuer.snapshot()["binding_tombstones"]), 1)
        issuer.garbage_collect_completed([execution_scope(request["binding"])])
        self.assertEqual(issuer.snapshot()["binding_tombstones"], [])

    def test_expiry_capacity_and_tombstone_gc(self):
        issuer = self.issuer(max_entries=2)
        expiring = issuer.issue(issue_request(ttl=1, guest="expiring"))
        other = issuer.issue(issue_request(uid="uid-other", execution="execution-other", guest="other"))
        self.assertFailure("capacity-exceeded", lambda: issuer.issue(issue_request(guest="overflow")))

        self.clock.value = START + timedelta(seconds=2)
        issuer.maintain()
        records = {record["guest_instance_id"]: record for record in issuer.snapshot()["records"]}
        self.assertEqual(records["expiring"]["state"], "expired")
        self.assertEqual(records["expiring"]["terminal_at"], expiring["expires_at"])
        self.assertEqual(records["other"]["state"], "issued")

        issuer.revoke_execution(revoke_execution_request(expiring["binding"]))
        self.assertEqual(sum(len(value) for value in issuer.snapshot().values()), 2)
        self.clock.value = START + timedelta(seconds=2) + TOMBSTONE_RETENTION
        issuer.maintain()
        self.assertEqual(sum(len(value) for value in issuer.snapshot().values()), 2)
        issuer.garbage_collect_completed([execution_scope(expiring["binding"])])
        self.assertEqual(sum(len(value) for value in issuer.snapshot().values()), 1)
        replacement = issuer.issue(issue_request(guest="after-gc"))
        self.assertTrue(replacement["token"])

    def test_late_expiry_uses_original_deadline_and_completed_scope_gc(self):
        issuer = self.issuer()
        expired = issuer.issue(issue_request(uid="expired-uid", execution="expired-execution", guest="expired-guest", ttl=1))
        self.clock.value = START + TOMBSTONE_RETENTION + timedelta(hours=1)
        live = issuer.issue(issue_request(uid="live-uid", execution="live-execution", guest="live-guest"))
        self.assertFailure("expired", lambda: issuer.exchange(exchange_request(expired)))
        records = {record["agent_run_uid"]: record for record in issuer.snapshot()["records"]}
        self.assertEqual(records["expired-uid"]["terminal_at"], expired["expires_at"])

        issuer.garbage_collect_completed([execution_scope(expired["binding"])])
        records = {record["agent_run_uid"]: record for record in issuer.snapshot()["records"]}
        self.assertNotIn("expired-uid", records)
        self.assertEqual(records["live-uid"]["state"], "issued")
        self.assertTrue(live["token"])

    def test_exchange_abuse_bounds_and_runtime_identity_expiry(self):
        issuer = self.issuer()
        envelope = issuer.issue(issue_request())

        class DenyRate:
            def allow(self):
                return False

        original_rate = issuer.exchange_rate
        issuer.exchange_rate = DenyRate()
        self.assertFailure("capacity-exceeded", lambda: issuer.exchange(exchange_request(envelope)))
        issuer.exchange_rate = original_rate

        acquired = []
        for _ in range(32):
            acquired.append(issuer.exchange_slots.acquire(blocking=False))
        self.assertTrue(all(acquired))
        self.assertFailure("capacity-exceeded", lambda: issuer.exchange(exchange_request(envelope)))
        for _ in acquired:
            issuer.exchange_slots.release()

        result = issuer.exchange(exchange_request(envelope))
        self.assertTrue(result["runtime_identity"]["opaque"])
        record = issuer.snapshot()["records"][0]
        self.assertEqual(record["runtime_identity_active"], 1)
        self.assertEqual(record["runtime_identity_expires_at"], result["runtime_identity"]["expires_at"])
        self.clock.value += timedelta(hours=1)
        issuer.maintain()
        self.assertEqual(issuer.snapshot()["records"][0]["runtime_identity_active"], 0)

    def test_precommit_failure_and_postcommit_response_loss(self):
        before = self.issuer(faults=BeforeCommitFailure())
        envelope = before.issue(issue_request())
        self.assertFailure("issuer-storage-failed", lambda: before.exchange(exchange_request(envelope)))
        record = before.snapshot()["records"][0]
        self.assertEqual(record["state"], "issued")
        self.assertEqual(record["runtime_identity_active"], 0)
        before.close()
        recovered = self.issuer()
        recovered.exchange(exchange_request(envelope))

        second_database = str(Path(self.temporary.name) / "response-lost.sqlite3")
        lost = GuestEnrollmentIssuer(
            second_database,
            EXCHANGE_URL,
            now=self.clock,
            random_bytes=DeterministicRandom(20),
            faults=ResponseLostFailure(),
            maintenance_interval=None,
        )
        self.addCleanup(lost.close)
        lost_envelope = lost.issue(issue_request(uid="uid-lost", execution="execution-lost"))
        with self.assertRaises(ConnectionAbortedError):
            lost.exchange(exchange_request(lost_envelope))
        lost.close()
        lost_restarted = GuestEnrollmentIssuer(second_database, EXCHANGE_URL, now=self.clock, random_bytes=DeterministicRandom(30), maintenance_interval=None)
        self.addCleanup(lost_restarted.close)
        record = lost_restarted.snapshot()["records"][0]
        self.assertEqual(record["state"], "consumed")
        self.assertEqual(record["runtime_identity_active"], 1)
        self.assertFailure("already-consumed", lambda: lost_restarted.exchange(exchange_request(lost_envelope)))
        lost_restarted.revoke_execution(revoke_execution_request(lost_envelope["binding"]))
        self.assertEqual(lost_restarted.snapshot()["records"], [])

    def test_corrupt_store_and_errors_are_sanitized(self):
        Path(self.database).write_bytes(b"not-a-sqlite-database\nsecret-canary")
        with self.assertRaisesRegex(EnrollmentConfigError, "database initialization failed") as caught:
            self.issuer()
        self.assertNotIn("secret-canary", str(caught.exception))

        database = str(Path(self.temporary.name) / "runtime-corrupt.sqlite3")
        issuer = GuestEnrollmentIssuer(database, EXCHANGE_URL, now=self.clock, random_bytes=self.random, maintenance_interval=None)
        issuer.close()
        Path(database).write_bytes(b"corrupt-runtime-store\nsecret-canary")
        self.assertFalse(issuer.ready())
        self.assertFailure("issuer-storage-failed", lambda: issuer.issue(issue_request()))

        incomplete = str(Path(self.temporary.name) / "incomplete.sqlite3")
        connection = sqlite3.connect(incomplete)
        connection.execute("CREATE TABLE enrollment_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("INSERT INTO enrollment_meta VALUES ('schema_version', '1')")
        connection.execute("CREATE TABLE enrollments (token_digest TEXT)")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(EnrollmentConfigError, "database initialization failed"):
            GuestEnrollmentIssuer(incomplete, EXCHANGE_URL, maintenance_interval=None)

    def test_semantically_corrupt_rows_fail_startup_and_readiness(self):
        malformed_timestamp_database = str(Path(self.temporary.name) / "malformed-timestamp.sqlite3")
        issuer = GuestEnrollmentIssuer(
            malformed_timestamp_database,
            EXCHANGE_URL,
            now=self.clock,
            random_bytes=DeterministicRandom(40),
            maintenance_interval=None,
        )
        issuer.issue(issue_request(uid="semantic-uid", execution="semantic-execution"))
        issuer.close()
        update_database(malformed_timestamp_database, "UPDATE enrollments SET expires_at = ?", ("not-a-timestamp",))
        with self.assertRaisesRegex(EnrollmentConfigError, "database initialization failed"):
            GuestEnrollmentIssuer(malformed_timestamp_database, EXCHANGE_URL, maintenance_interval=None)

        live_corruption_database = str(Path(self.temporary.name) / "live-corruption.sqlite3")
        live = GuestEnrollmentIssuer(
            live_corruption_database,
            EXCHANGE_URL,
            now=self.clock,
            random_bytes=DeterministicRandom(50),
            maintenance_interval=None,
        )
        self.addCleanup(live.close)
        live.issue(issue_request(uid="live-corrupt-uid", execution="live-corrupt-execution"))
        update_database(live_corruption_database, "UPDATE enrollments SET token_digest = ?", ("sha256:not-a-digest",))
        self.assertFalse(live.ready())
        self.assertFailure("issuer-storage-failed", live.maintain)

        binding_tombstone_database = str(Path(self.temporary.name) / "binding-tombstone.sqlite3")
        binding_issuer = GuestEnrollmentIssuer(binding_tombstone_database, EXCHANGE_URL, now=self.clock, maintenance_interval=None)
        request = issue_request(uid="binding-tombstone-uid", execution="binding-tombstone-execution")
        binding_issuer.revoke_binding(revoke_binding_request(request["binding"]))
        binding_issuer.close()
        update_database(binding_tombstone_database, "UPDATE binding_tombstones SET delete_after = ?", ("invalid",))
        with self.assertRaisesRegex(EnrollmentConfigError, "database initialization failed"):
            GuestEnrollmentIssuer(binding_tombstone_database, EXCHANGE_URL, maintenance_interval=None)

        execution_tombstone_database = str(Path(self.temporary.name) / "execution-tombstone.sqlite3")
        execution_issuer = GuestEnrollmentIssuer(execution_tombstone_database, EXCHANGE_URL, now=self.clock, maintenance_interval=None)
        execution_issuer.revoke_execution(revoke_execution_request(request["binding"]))
        execution_issuer.close()
        update_database(execution_tombstone_database, "UPDATE execution_tombstones SET delete_after = ?", ("2026-07-29T12:00:00Z",))
        with self.assertRaisesRegex(EnrollmentConfigError, "database initialization failed"):
            GuestEnrollmentIssuer(execution_tombstone_database, EXCHANGE_URL, maintenance_interval=None)

        identity_database = str(Path(self.temporary.name) / "runtime-identity.sqlite3")
        identity_issuer = GuestEnrollmentIssuer(
            identity_database,
            EXCHANGE_URL,
            now=self.clock,
            random_bytes=DeterministicRandom(60),
            maintenance_interval=None,
        )
        envelope = identity_issuer.issue(issue_request(uid="identity-uid", execution="identity-execution"))
        identity_issuer.exchange(exchange_request(envelope))
        identity_issuer.close()
        update_database(identity_database, "UPDATE enrollments SET runtime_identity_expires_at = ?", ("invalid",))
        with self.assertRaisesRegex(EnrollmentConfigError, "database initialization failed"):
            GuestEnrollmentIssuer(identity_database, EXCHANGE_URL, maintenance_interval=None)

    def test_orchestrator_auth_stores_only_digest(self):
        token = b"orchestrator-auth-token-0123456789abcdef"
        token_file = Path(self.temporary.name) / "orchestrator-token"
        token_file.write_bytes(token)
        authenticator = OrchestratorAuthenticator(token_file)
        self.assertEqual(authenticator.authenticate("Bearer " + token.decode()), "guest-enrollment-orchestrator")
        self.assertFailure("unauthorized", lambda: authenticator.authenticate("Bearer frontend-token-not-authorized-000000"))
        self.assertNotIn(token, vars(authenticator).values())

    def test_startup_configuration_fails_closed(self):
        for invalid_url in (
            "http://broker.example/v1/guest-enrollment/exchange",
            "https://user@broker.example/v1/guest-enrollment/exchange",
            "https://broker.example/v1/guest-enrollment/exchange?redirect=attacker",
            "https://broker.example/v1/guest-enrollment/exchange?",
            "https://broker.example/v1/guest-enrollment/../exchange",
            "https://broker.example/v1/guest-enrollment/other",
            "https://broker.example/prefix/v1/guest-enrollment/exchange",
        ):
            with self.subTest(url=invalid_url):
                with self.assertRaises(EnrollmentConfigError):
                    GuestEnrollmentIssuer(self.database, invalid_url, maintenance_interval=None)

        token_file = Path(self.temporary.name) / "invalid-orchestrator-token"
        token_file.write_text("short", encoding="utf-8")
        with self.assertRaisesRegex(EnrollmentConfigError, "token file is invalid"):
            OrchestratorAuthenticator(token_file)

        with patch.dict("os.environ", {"NVT_BROKER_GUEST_ENROLLMENT_ENABLED": "false"}, clear=True):
            self.assertEqual(load_guest_enrollment_from_environment(), (None, None))
        with patch.dict("os.environ", {"NVT_BROKER_GUEST_ENROLLMENT_ENABLED": "true"}, clear=True):
            with self.assertRaisesRegex(EnrollmentConfigError, "requires database"):
                load_guest_enrollment_from_environment()

    def assertFailure(self, reason, operation):
        with self.assertRaises(EnrollmentFailure) as caught:
            operation()
        self.assertEqual(caught.exception.reason, reason)
        self.assertNotIn("secret", str(caught.exception))


def binding(uid="uid-run", execution="execution-1", generation=1, guest="guest-1"):
    return {
        "agent_run_uid": uid,
        "execution_id": execution,
        "driver_registration": "qemu-lab",
        "desired_generation": generation,
        "guest_instance_id": guest,
    }


def issue_request(uid="uid-run", execution="execution-1", generation=1, guest="guest-1", ttl=300):
    return {"contract_version": VERSION, "binding": binding(uid, execution, generation, guest), "ttl_seconds": ttl}


def exchange_request(envelope):
    return {"contract_version": VERSION, "binding": dict(envelope["binding"]), "token": envelope["token"]}


def revoke_binding_request(value):
    return {"contract_version": VERSION, "binding": dict(value)}


def revoke_execution_request(value):
    return {
        "contract_version": VERSION,
        "execution_scope": {
            "agent_run_uid": value["agent_run_uid"],
            "execution_id": value["execution_id"],
            "driver_registration": value["driver_registration"],
        },
    }


def execution_scope(value):
    return {
        "agent_run_uid": value["agent_run_uid"],
        "execution_id": value["execution_id"],
        "driver_registration": value["driver_registration"],
    }


def update_database(database, statement, parameters):
    connection = sqlite3.connect(database)
    try:
        connection.execute(statement, parameters)
        connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    unittest.main()
