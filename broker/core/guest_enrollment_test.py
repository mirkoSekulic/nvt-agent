import json
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler
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
from broker.core.server import BoundedThreadingHTTPServer


class QuietHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return


class ReadyHTTPHandler(QuietHTTPHandler):
    def do_GET(self):
        if self.path != "/ready":
            self.send_error(404)
            return
        payload = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class BrokerHTTPAdmissionTest(unittest.TestCase):
    def test_incomplete_headers_are_thread_bounded_and_time_bounded(self):
        server = BoundedThreadingHTTPServer(
            ("127.0.0.1", 0),
            QuietHTTPHandler,
            max_connections=2,
            header_timeout=1.0,
        )
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        sockets = []

        def cleanup():
            for connection in sockets:
                connection.close()
            server.shutdown()
            thread.join(timeout=2.0)
            server.server_close()

        self.addCleanup(cleanup)

        def incomplete_request():
            connection = socket.create_connection(server.server_address, timeout=1.0)
            connection.sendall(b"GET /ready HTTP/1.1\r\nHost: broker.test\r\n")
            sockets.append(connection)
            return connection

        first = incomplete_request()
        incomplete_request()
        time.sleep(0.1)
        overflow = incomplete_request()
        overflow.settimeout(1.0)
        try:
            overflow_result = overflow.recv(1)
        except ConnectionResetError:
            overflow_result = b""
        self.assertEqual(overflow_result, b"")

        first.settimeout(2.0)
        started = time.monotonic()
        try:
            header_result = first.recv(1)
        except ConnectionResetError:
            header_result = b""
        self.assertEqual(header_result, b"")
        self.assertLess(time.monotonic() - started, 1.5)

    def test_tls_handshake_is_admitted_and_time_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            certificate = str(Path(temporary) / "server.crt")
            private_key = str(Path(temporary) / "server.key")
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                    "-keyout",
                    private_key,
                    "-out",
                    certificate,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(certificate, private_key)

            server = BoundedThreadingHTTPServer(
                ("127.0.0.1", 0),
                ReadyHTTPHandler,
                max_connections=2,
                header_timeout=0.5,
                tls_context=server_context,
            )
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.01},
                daemon=True,
            )
            thread.start()
            stalled = socket.create_connection(server.server_address, timeout=1.0)

            def cleanup():
                stalled.close()
                server.shutdown()
                thread.join(timeout=2.0)
                server.server_close()

            self.addCleanup(cleanup)

            # The first TCP client never sends a ClientHello. Its admitted
            # handshake must run outside the accept loop so a second client
            # can complete TLS and reach the broker concurrently.
            time.sleep(0.1)
            client_context = ssl.create_default_context()
            client_context.check_hostname = False
            client_context.verify_mode = ssl.CERT_NONE
            started = time.monotonic()
            with socket.create_connection(server.server_address, timeout=1.0) as connection:
                with client_context.wrap_socket(connection, server_hostname="localhost") as tls_connection:
                    tls_connection.sendall(
                        b"GET /ready HTTP/1.1\r\nHost: broker.test\r\nConnection: close\r\n\r\n"
                    )
                    response = b""
                    while True:
                        chunk = tls_connection.recv(4096)
                        if not chunk:
                            break
                        response += chunk
            self.assertIn(b"HTTP/1.0 200 OK", response)
            self.assertIn(b'{"ok":true}', response)
            self.assertLess(time.monotonic() - started, 0.5)

            stalled.settimeout(1.5)
            try:
                stalled_result = stalled.recv(1)
            except ConnectionResetError:
                stalled_result = b""
            self.assertEqual(stalled_result, b"")


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

    def test_unrelated_semantic_corruption_blocks_exchange(self):
        issuer = self.issuer()
        bad = issuer.issue(issue_request(uid="bad-uid", execution="bad-execution", guest="bad-guest"))
        good = issuer.issue(issue_request(uid="good-uid", execution="good-execution", guest="good-guest"))
        update_database(
            self.database,
            "UPDATE enrollments SET expires_at = ? WHERE guest_instance_id = ?",
            ("not-a-timestamp", bad["binding"]["guest_instance_id"]),
        )
        self.assertFalse(issuer.ready())
        self.assertFailure("issuer-storage-failed", lambda: issuer.exchange(exchange_request(good)))
        rows = query_database(
            self.database,
            "SELECT state, runtime_identity_digest, runtime_identity_active FROM enrollments ORDER BY guest_instance_id",
        )
        self.assertEqual(
            rows,
            [
                ("issued", None, 0),
                ("issued", None, 0),
            ],
        )

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

    def test_tombstone_retention_survives_clock_rollback_and_v1_migration(self):
        rollback_database = str(Path(self.temporary.name) / "rollback.sqlite3")
        issuer = GuestEnrollmentIssuer(rollback_database, EXCHANGE_URL, now=self.clock, maintenance_interval=None)
        request = issue_request(uid="rollback-uid", execution="rollback-execution", guest="rollback-guest")
        issuer.revoke_binding(revoke_binding_request(request["binding"]))
        before = issuer.snapshot()["binding_tombstones"][0]
        issuer.close()

        self.clock.value = START - timedelta(seconds=1)
        restarted = GuestEnrollmentIssuer(rollback_database, EXCHANGE_URL, now=self.clock, maintenance_interval=None)
        self.addCleanup(restarted.close)
        after = restarted.snapshot()["binding_tombstones"][0]
        self.assertTrue(restarted.ready())
        self.assertEqual((after["created_at"], after["delete_after"]), (before["created_at"], before["delete_after"]))

        migration_database = str(Path(self.temporary.name) / "schema-v1.sqlite3")
        self.clock.value = START
        old = GuestEnrollmentIssuer(migration_database, EXCHANGE_URL, now=self.clock, maintenance_interval=None)
        old.revoke_binding(revoke_binding_request(issue_request(uid="v1-uid", execution="v1-execution")["binding"]))
        old.close()
        connection = sqlite3.connect(migration_database)
        try:
            connection.execute("ALTER TABLE binding_tombstones DROP COLUMN created_at")
            connection.execute("ALTER TABLE execution_tombstones DROP COLUMN created_at")
            connection.execute("UPDATE enrollment_meta SET value = '1' WHERE key = 'schema_version'")
            connection.commit()
        finally:
            connection.close()
        migrated = GuestEnrollmentIssuer(migration_database, EXCHANGE_URL, now=self.clock, maintenance_interval=None)
        self.addCleanup(migrated.close)
        migrated_tombstone = migrated.snapshot()["binding_tombstones"][0]
        created_at = datetime.strptime(migrated_tombstone["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        delete_after = datetime.strptime(migrated_tombstone["delete_after"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        self.assertEqual(delete_after - created_at, TOMBSTONE_RETENTION)
        self.assertEqual(query_database(migration_database, "SELECT value FROM enrollment_meta"), [("2",)])

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


def query_database(database, statement):
    connection = sqlite3.connect(database)
    try:
        return connection.execute(statement).fetchall()
    finally:
        connection.close()


if __name__ == "__main__":
    unittest.main()
