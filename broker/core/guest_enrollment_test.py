import base64
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
    DEFAULT_RUNTIME_IDENTITY_HISTORY_CAPACITY,
    MAX_RUNTIME_IDENTITY_HISTORY_PER_ENROLLMENT,
    MAX_RUNTIME_IDENTITY_HISTORY_CAPACITY,
    OrchestratorAuthenticator,
    RUNTIME_IDENTITY_CAPACITY_PLANNING_INTERVAL,
    RUNTIME_IDENTITY_PLANNING_HORIZON,
    RUNTIME_IDENTITY_VERSION,
    TOMBSTONE_RETENTION,
    VERSION,
    _validate_persisted_runtime_identity_history,
    format_timestamp,
    load_guest_enrollment_from_environment,
)
from broker.core.server import BoundedThreadingHTTPServer, make_handler


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


class EnrollmentHTTPBroker:
    guest_enrollment = object()

    def _require_guest_enrollment(self):
        return None

    def guest_enrollment_exchange(self, _request_id, _payload):
        return {"ok": True}

    def guest_enrollment_complete_execution_cleanup(self, _request_id, _payload, _authorization):
        return {"ok": True}

    def readiness(self):
        return {"ok": True, "status": "ready"}

    def denied(self, _request_id, _payload, reason, _message, _authorization, _operation):
        return {"ok": False, "error": reason}


def wait_for_plain_ready(test, address):
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(address, timeout=0.2) as connection:
                connection.sendall(b"GET /ready HTTP/1.0\r\nHost: broker.test\r\n\r\n")
                response = connection.recv(4096)
            if b"HTTP/1.0 200 OK" in response:
                return
        except OSError:
            pass
        time.sleep(0.02)
    test.fail("connection capacity was not released after the absolute deadline")


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
                max_connections=1,
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
            incoming = ssl.MemoryBIO()
            outgoing = ssl.MemoryBIO()
            client_hello_context = ssl.create_default_context()
            client_hello_context.check_hostname = False
            client_hello_context.verify_mode = ssl.CERT_NONE
            client_ssl = client_hello_context.wrap_bio(incoming, outgoing, server_hostname="localhost")
            with self.assertRaises(ssl.SSLWantReadError):
                client_ssl.do_handshake()
            client_hello = outgoing.read()
            drip_stopped = threading.Event()

            def drip_client_hello():
                try:
                    for value in client_hello:
                        stalled.sendall(bytes([value]))
                        time.sleep(0.05)
                except OSError:
                    pass
                finally:
                    drip_stopped.set()

            drip_thread = threading.Thread(target=drip_client_hello, daemon=True)
            drip_thread.start()

            def cleanup():
                stalled.close()
                drip_thread.join(timeout=2.0)
                server.shutdown()
                thread.join(timeout=2.0)
                server.server_close()

            self.addCleanup(cleanup)

            # The first client drip-feeds a valid ClientHello slowly enough to
            # exceed the absolute handshake deadline. The accept loop must
            # still promptly reject overflow rather than blocking in TLS.
            time.sleep(0.1)
            overflow = socket.create_connection(server.server_address, timeout=1.0)
            overflow.settimeout(0.3)
            try:
                overflow_result = overflow.recv(1)
            except ConnectionResetError:
                overflow_result = b""
            overflow.close()
            self.assertEqual(overflow_result, b"")

            self.assertTrue(drip_stopped.wait(1.0))
            stalled.settimeout(1.0)
            try:
                stalled_result = stalled.recv(1)
            except ConnectionResetError:
                stalled_result = b""
            self.assertEqual(stalled_result, b"")

            # Once the absolute deadline expires, the handshake slot is
            # released and a complete HTTPS request can use it.
            client_context = ssl.create_default_context()
            client_context.check_hostname = False
            client_context.verify_mode = ssl.CERT_NONE
            response = b""
            ready_deadline = time.monotonic() + 1.0
            while time.monotonic() < ready_deadline and b"HTTP/1.0 200 OK" not in response:
                try:
                    with socket.create_connection(server.server_address, timeout=0.2) as connection:
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
                except OSError:
                    time.sleep(0.02)
            self.assertIn(b"HTTP/1.0 200 OK", response)
            self.assertIn(b'{"ok":true}', response)

    def test_slow_drip_headers_hit_absolute_deadline_and_release_capacity(self):
        server = BoundedThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(EnrollmentHTTPBroker()),
            max_connections=1,
            header_timeout=0.2,
        )
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        stalled = socket.create_connection(server.server_address, timeout=1.0)

        def drip_headers():
            try:
                for value in b"GET /ready HTTP/1.1\r\nHost: broker.test\r\nX-Slow: value\r\n\r\n":
                    stalled.sendall(bytes([value]))
                    time.sleep(0.05)
            except OSError:
                pass

        drip_thread = threading.Thread(target=drip_headers, daemon=True)
        drip_thread.start()

        def cleanup():
            stalled.close()
            drip_thread.join(timeout=2.0)
            server.shutdown()
            thread.join(timeout=2.0)
            server.server_close()

        self.addCleanup(cleanup)
        time.sleep(0.1)
        overflow = socket.create_connection(server.server_address, timeout=1.0)
        overflow.settimeout(1.0)
        try:
            overflow_result = overflow.recv(1)
        except ConnectionResetError:
            overflow_result = b""
        overflow.close()
        self.assertEqual(overflow_result, b"")

        wait_for_plain_ready(self, server.server_address)

    def test_slow_drip_enrollment_body_hits_absolute_deadline_and_releases_capacity(self):
        server = BoundedThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(EnrollmentHTTPBroker()),
            max_connections=1,
            header_timeout=1.0,
            body_timeout=0.2,
        )
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        stalled = socket.create_connection(server.server_address, timeout=1.0)
        stalled.sendall(
            b"POST /v1/guest-enrollment/exchange HTTP/1.1\r\n"
            b"Host: broker.test\r\nContent-Type: application/json\r\n"
            b"Content-Length: 100\r\n\r\n"
        )

        def drip_body():
            try:
                for value in b"{" + (b" " * 99):
                    stalled.sendall(bytes([value]))
                    time.sleep(0.05)
            except OSError:
                pass

        drip_thread = threading.Thread(target=drip_body, daemon=True)
        drip_thread.start()

        def cleanup():
            stalled.close()
            drip_thread.join(timeout=2.0)
            server.shutdown()
            thread.join(timeout=2.0)
            server.server_close()

        self.addCleanup(cleanup)
        time.sleep(0.1)
        overflow = socket.create_connection(server.server_address, timeout=1.0)
        overflow.settimeout(1.0)
        try:
            overflow_result = overflow.recv(1)
        except ConnectionResetError:
            overflow_result = b""
        overflow.close()
        self.assertEqual(overflow_result, b"")

        wait_for_plain_ready(self, server.server_address)


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


class RotationBeforeCommitFailure(EnrollmentFaults):
    def before_rotation_commit(self):
        raise sqlite3.OperationalError("rotation-storage-secret-canary")


class RotationResponseLostFailure(EnrollmentFaults):
    def after_rotation_commit(self):
        raise ConnectionAbortedError("rotation-response-lost")


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

    def test_runtime_identity_status_rotation_restart_and_revocation(self):
        issuer = self.issuer()
        envelope = issuer.issue(issue_request())
        identity = issuer.exchange(exchange_request(envelope))["runtime_identity"]["opaque"]
        status = issuer.runtime_identity_status(identity, runtime_status_request(envelope["binding"]))
        self.assertEqual(status["binding"], envelope["binding"])
        self.assertNotIn("opaque", status)
        self.assertFailure(
            "unauthorized",
            lambda: issuer.runtime_identity_status(opaque_canary(69), runtime_status_request(envelope["binding"])),
        )

        # Rotation is a runtime operation and remains valid after the one-time
        # enrollment token's independent TTL has elapsed.
        self.clock.value += timedelta(minutes=30)
        first_successor = opaque_canary(70)
        self.assertFailure(
            "invalid-request",
            lambda: issuer.rotate_runtime_identity(identity, runtime_rotate_request(envelope["binding"], identity)),
        )
        rotated = issuer.rotate_runtime_identity(identity, runtime_rotate_request(envelope["binding"], first_successor))
        self.assertEqual(rotated["identity_type"], "nvt.runtime-identity/v1")
        self.assertFailure(
            "invalid-request",
            lambda: issuer.rotate_runtime_identity(
                first_successor,
                runtime_rotate_request(envelope["binding"], identity),
            ),
        )
        self.assertFailure("unauthorized", lambda: issuer.runtime_identity_status(identity, runtime_status_request(envelope["binding"])))
        self.assertEqual(issuer.runtime_identity_status(first_successor, runtime_status_request(envelope["binding"])), rotated)
        self.assertTrue(issuer.ready())

        second_successor = opaque_canary(71)
        issuer.rotate_runtime_identity(first_successor, runtime_rotate_request(envelope["binding"], second_successor))
        issuer.close()
        restarted = self.issuer()
        self.assertEqual(
            restarted.runtime_identity_status(second_successor, runtime_status_request(envelope["binding"]))["binding"],
            envelope["binding"],
        )
        self.assertFailure(
            "invalid-request",
            lambda: restarted.rotate_runtime_identity(
                second_successor,
                runtime_rotate_request(envelope["binding"], first_successor),
            ),
        )
        durable_with_history = json.dumps(restarted.snapshot(), sort_keys=True)
        self.assertEqual(len(restarted.snapshot()["runtime_identity_history"]), 2)
        for secret in (identity, first_successor, second_successor):
            self.assertNotIn(secret, durable_with_history)
        self.clock.value += timedelta(hours=1)
        restarted.maintain()
        self.assertFailure(
            "unauthorized",
            lambda: restarted.runtime_identity_status(second_successor, runtime_status_request(envelope["binding"])),
        )
        restarted.revoke_execution(revoke_execution_request(envelope["binding"]))
        self.assertFailure(
            "unauthorized",
            lambda: restarted.runtime_identity_status(second_successor, runtime_status_request(envelope["binding"])),
        )

        durable = json.dumps(restarted.snapshot(), sort_keys=True)
        self.assertEqual(restarted.snapshot()["runtime_identity_history"], [])
        for secret in (identity, first_successor, second_successor):
            self.assertNotIn(secret, durable)

    def test_runtime_identity_rotation_is_single_cas_and_exact_binding(self):
        issuer = self.issuer()
        envelope = issuer.issue(issue_request())
        identity = issuer.exchange(exchange_request(envelope))["runtime_identity"]["opaque"]
        wrong = runtime_status_request(dict(envelope["binding"], guest_instance_id="other-guest"))
        self.assertFailure("unauthorized", lambda: issuer.runtime_identity_status(identity, wrong))
        wrong_rotation = runtime_rotate_request(
            dict(envelope["binding"], desired_generation=2),
            opaque_canary(78),
        )
        self.assertFailure("unauthorized", lambda: issuer.rotate_runtime_identity(identity, wrong_rotation))
        self.assertTrue(runtime_identity_is_active(issuer, identity, envelope["binding"]))

        barrier = threading.Barrier(3)
        successors = (opaque_canary(72), opaque_canary(73))

        def rotate(successor):
            barrier.wait()
            try:
                issuer.rotate_runtime_identity(identity, runtime_rotate_request(envelope["binding"], successor))
                return "success"
            except EnrollmentFailure as error:
                return error.reason

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(rotate, successor) for successor in successors]
            barrier.wait()
            outcomes = [future.result(timeout=2) for future in futures]
        self.assertEqual(outcomes.count("success"), 1)
        self.assertEqual(outcomes.count("unauthorized"), 1)
        active = [
            successor
            for successor in successors
            if runtime_identity_is_active(issuer, successor, envelope["binding"])
        ]
        self.assertEqual(len(active), 1)

    def test_runtime_identity_rotation_commit_boundaries_and_recovery(self):
        before = self.issuer(faults=RotationBeforeCommitFailure())
        envelope = before.issue(issue_request())
        identity = before.exchange(exchange_request(envelope))["runtime_identity"]["opaque"]
        successor = opaque_canary(74)
        self.assertFailure(
            "issuer-storage-failed",
            lambda: before.rotate_runtime_identity(identity, runtime_rotate_request(envelope["binding"], successor)),
        )
        self.assertFalse(before.store_healthy)
        before.maintain()
        self.assertTrue(before.ready())
        self.assertTrue(runtime_identity_is_active(before, identity, envelope["binding"]))
        self.assertFalse(runtime_identity_is_active(before, successor, envelope["binding"]))
        self.assertEqual(before.snapshot()["runtime_identity_history"], [])
        before.close()
        before_recovered = self.issuer()
        before_recovered.rotate_runtime_identity(
            identity,
            runtime_rotate_request(envelope["binding"], successor),
        )
        self.assertTrue(runtime_identity_is_active(before_recovered, successor, envelope["binding"]))

        lost_database = str(Path(self.temporary.name) / "rotation-response-lost.sqlite3")
        lost = GuestEnrollmentIssuer(
            lost_database,
            EXCHANGE_URL,
            now=self.clock,
            random_bytes=DeterministicRandom(80),
            faults=RotationResponseLostFailure(),
            maintenance_interval=None,
        )
        self.addCleanup(lost.close)
        lost_envelope = lost.issue(issue_request(uid="lost-uid", execution="lost-execution"))
        old_identity = lost.exchange(exchange_request(lost_envelope))["runtime_identity"]["opaque"]
        proposed = opaque_canary(75)
        with self.assertRaises(ConnectionAbortedError):
            lost.rotate_runtime_identity(old_identity, runtime_rotate_request(lost_envelope["binding"], proposed))
        lost.close()
        recovered = GuestEnrollmentIssuer(lost_database, EXCHANGE_URL, now=self.clock, maintenance_interval=None)
        self.addCleanup(recovered.close)
        self.assertFalse(runtime_identity_is_active(recovered, old_identity, lost_envelope["binding"]))
        self.assertTrue(runtime_identity_is_active(recovered, proposed, lost_envelope["binding"]))
        self.assertEqual(len(recovered.snapshot()["runtime_identity_history"]), 1)

    def test_runtime_identity_history_is_bounded_restart_safe_and_cleaned(self):
        issuer = self.issuer(
            max_entries=3,
            max_runtime_identity_history_per_enrollment=2,
            max_runtime_identity_history_entries=4,
        )
        envelope = issuer.issue(issue_request())
        initial = issuer.exchange(exchange_request(envelope))["runtime_identity"]["opaque"]
        unrelated = issuer.issue(issue_request(uid="unrelated-uid", execution="unrelated-execution", guest="unrelated-guest"))
        unrelated_identity = issuer.exchange(exchange_request(unrelated))["runtime_identity"]["opaque"]
        self.assertFailure(
            "capacity-exceeded",
            lambda: issuer.issue(issue_request(uid="unreserved", execution="unreserved", guest="unreserved")),
        )
        self.assertEqual(
            query_database(
                self.database,
                "SELECT value FROM enrollment_meta WHERE key = 'runtime_identity_history_reserved'",
            ),
            [("4",)],
        )
        first = opaque_canary(90)
        second = opaque_canary(91)
        third = opaque_canary(92)
        issuer.rotate_runtime_identity(initial, runtime_rotate_request(envelope["binding"], first))
        issuer.rotate_runtime_identity(first, runtime_rotate_request(envelope["binding"], second))
        self.assertFailure(
            "capacity-exceeded",
            lambda: issuer.rotate_runtime_identity(second, runtime_rotate_request(envelope["binding"], third)),
        )
        issuer.close()

        with self.assertRaisesRegex(EnrollmentConfigError, "database initialization failed"):
            GuestEnrollmentIssuer(
                self.database,
                EXCHANGE_URL,
                now=self.clock,
                maintenance_interval=None,
                max_entries=3,
                max_runtime_identity_history_per_enrollment=2,
                max_runtime_identity_history_entries=3,
            )

        restarted = self.issuer(
            max_entries=3,
            max_runtime_identity_history_per_enrollment=2,
            max_runtime_identity_history_entries=4,
        )
        self.assertTrue(runtime_identity_is_active(restarted, second, envelope["binding"]))
        self.assertFailure(
            "invalid-request",
            lambda: restarted.rotate_runtime_identity(second, runtime_rotate_request(envelope["binding"], initial)),
        )
        # The unrelated lifecycle owns its own complete allowance even though
        # the first lifecycle has exhausted its quota.
        unrelated_successor = opaque_canary(98)
        restarted.rotate_runtime_identity(
            unrelated_identity,
            runtime_rotate_request(unrelated["binding"], unrelated_successor),
        )
        self.assertEqual(len(restarted.snapshot()["runtime_identity_history"]), 3)
        restarted.revoke_binding(revoke_binding_request(envelope["binding"]))
        self.assertEqual(len(restarted.snapshot()["runtime_identity_history"]), 1)
        self.assertEqual(
            query_database(
                self.database,
                "SELECT value FROM enrollment_meta WHERE key = 'runtime_identity_history_reserved'",
            ),
            [("2",)],
        )
        replacement = restarted.issue(
            issue_request(uid="replacement-uid", execution="replacement-execution", guest="replacement-guest")
        )
        replacement_identity = restarted.exchange(exchange_request(replacement))["runtime_identity"]["opaque"]
        restarted.rotate_runtime_identity(
            replacement_identity,
            runtime_rotate_request(replacement["binding"], opaque_canary(96)),
        )

    def test_runtime_identity_history_capacity_supports_documented_lifecycle(self):
        self.assertGreaterEqual(
            MAX_RUNTIME_IDENTITY_HISTORY_PER_ENROLLMENT * RUNTIME_IDENTITY_CAPACITY_PLANNING_INTERVAL,
            RUNTIME_IDENTITY_PLANNING_HORIZON,
        )
        self.assertEqual(DEFAULT_RUNTIME_IDENTITY_HISTORY_CAPACITY // MAX_RUNTIME_IDENTITY_HISTORY_PER_ENROLLMENT, 100)
        self.assertGreaterEqual(MAX_RUNTIME_IDENTITY_HISTORY_CAPACITY, DEFAULT_RUNTIME_IDENTITY_HISTORY_CAPACITY)
        issuer = self.issuer()
        self.assertEqual(issuer.max_runtime_identity_history_entries, DEFAULT_RUNTIME_IDENTITY_HISTORY_CAPACITY)

    def test_runtime_detected_corruption_latches_until_complete_validation(self):
        issuer = self.issuer()
        damaged = issuer.issue(issue_request())
        damaged_identity = issuer.exchange(exchange_request(damaged))["runtime_identity"]["opaque"]
        damaged_successor = opaque_canary(99)
        issuer.rotate_runtime_identity(
            damaged_identity,
            runtime_rotate_request(damaged["binding"], damaged_successor),
        )
        healthy = issuer.issue(issue_request(uid="healthy-uid", execution="healthy-execution", guest="healthy-guest"))
        healthy_identity = issuer.exchange(exchange_request(healthy))["runtime_identity"]["opaque"]
        update_database(
            self.database,
            "UPDATE enrollments SET runtime_identity_history_complete = 0 WHERE agent_run_uid = ?",
            (damaged["binding"]["agent_run_uid"],),
        )
        self.assertFailure(
            "issuer-storage-failed",
            lambda: issuer.runtime_identity_status(
                damaged_successor,
                runtime_status_request(damaged["binding"]),
            ),
        )
        self.assertFalse(issuer.store_healthy)
        self.assertFailure(
            "issuer-storage-failed",
            lambda: issuer.runtime_identity_status(
                healthy_identity,
                runtime_status_request(healthy["binding"]),
            ),
        )

        # Repair alone cannot let a fast readiness probe or unrelated
        # record-local request declare the store healthy. Recovery is a
        # deliberate complete maintenance scan.
        update_database(
            self.database,
            "UPDATE enrollments SET runtime_identity_history_complete = 1 WHERE agent_run_uid = ?",
            (damaged["binding"]["agent_run_uid"],),
        )
        self.assertFailure(
            "issuer-storage-failed",
            lambda: issuer.runtime_identity_status(
                healthy_identity,
                runtime_status_request(healthy["binding"]),
            ),
        )
        self.assertFalse(issuer.ready())
        with patch(
            "broker.core.guest_enrollment._validate_persisted_runtime_identity_history",
            wraps=_validate_persisted_runtime_identity_history,
        ) as history_validator:
            issuer.maintain()
            self.assertGreaterEqual(history_validator.call_count, 1)
        self.assertTrue(issuer.ready())
        self.assertEqual(
            issuer.runtime_identity_status(healthy_identity, runtime_status_request(healthy["binding"]))["binding"],
            healthy["binding"],
        )

    def test_runtime_identity_successor_cannot_be_owned_by_another_lifecycle(self):
        issuer = self.issuer()
        first = issuer.issue(issue_request())
        first_identity = issuer.exchange(exchange_request(first))["runtime_identity"]["opaque"]
        second = issuer.issue(issue_request(uid="owner-uid", execution="owner-execution", guest="owner-guest"))
        second_identity = issuer.exchange(exchange_request(second))["runtime_identity"]["opaque"]
        self.assertFailure(
            "invalid-request",
            lambda: issuer.rotate_runtime_identity(
                first_identity,
                runtime_rotate_request(first["binding"], second_identity),
            ),
        )
        second_successor = opaque_canary(94)
        issuer.rotate_runtime_identity(second_identity, runtime_rotate_request(second["binding"], second_successor))
        self.assertFailure(
            "invalid-request",
            lambda: issuer.rotate_runtime_identity(
                first_identity,
                runtime_rotate_request(first["binding"], second_identity),
            ),
        )

    def test_v3_consumed_identity_is_status_only_until_reenrollment(self):
        issuer = self.issuer()
        envelope = issuer.issue(issue_request())
        identity = issuer.exchange(exchange_request(envelope))["runtime_identity"]["opaque"]
        issuer.close()
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("DROP TABLE runtime_identity_history")
            connection.execute("ALTER TABLE enrollments DROP COLUMN runtime_identity_history_complete")
            connection.execute("UPDATE enrollment_meta SET value = '3' WHERE key = 'schema_version'")
            connection.commit()
        finally:
            connection.close()

        migrated = self.issuer()
        self.assertTrue(runtime_identity_is_active(migrated, identity, envelope["binding"]))
        self.assertFailure(
            "unauthorized",
            lambda: migrated.rotate_runtime_identity(
                identity,
                runtime_rotate_request(envelope["binding"], opaque_canary(93)),
            ),
        )
        self.assertEqual(migrated.snapshot()["records"][0]["runtime_identity_history_complete"], 0)

    def test_v4_history_migration_reserves_existing_lifecycle_without_eviction(self):
        issuer = self.issuer(
            max_runtime_identity_history_per_enrollment=2,
            max_runtime_identity_history_entries=2,
        )
        expired = issuer.issue(
            issue_request(uid="expired-uid", execution="expired-execution", guest="expired-guest", ttl=1)
        )
        self.clock.value += timedelta(seconds=2)
        issuer.maintain()
        envelope = issuer.issue(issue_request())
        identity = issuer.exchange(exchange_request(envelope))["runtime_identity"]["opaque"]
        successor = opaque_canary(89)
        issuer.rotate_runtime_identity(identity, runtime_rotate_request(envelope["binding"], successor))
        issuer.close()
        connection = sqlite3.connect(self.database)
        try:
            connection.execute(
                "UPDATE enrollments SET runtime_identity_history_count = 0, runtime_identity_history_capacity = 0"
            )
            connection.execute(
                "DELETE FROM enrollment_meta WHERE key IN ('runtime_identity_history_capacity', 'runtime_identity_history_reserved')"
            )
            connection.execute(
                "INSERT INTO enrollment_meta (key, value) VALUES ('runtime_identity_history_count', '1')"
            )
            connection.execute("UPDATE enrollment_meta SET value = '4' WHERE key = 'schema_version'")
            connection.commit()
        finally:
            connection.close()

        migrated = self.issuer(
            max_runtime_identity_history_per_enrollment=2,
            max_runtime_identity_history_entries=2,
        )
        records = {record["agent_run_uid"]: record for record in migrated.snapshot()["records"]}
        self.assertEqual(records[expired["binding"]["agent_run_uid"]]["state"], "expired")
        self.assertEqual(records[expired["binding"]["agent_run_uid"]]["runtime_identity_history_count"], 0)
        self.assertEqual(records[expired["binding"]["agent_run_uid"]]["runtime_identity_history_capacity"], 0)
        self.assertEqual(records[envelope["binding"]["agent_run_uid"]]["runtime_identity_history_count"], 1)
        self.assertEqual(records[envelope["binding"]["agent_run_uid"]]["runtime_identity_history_capacity"], 2)
        self.assertTrue(runtime_identity_is_active(migrated, successor, envelope["binding"]))
        self.assertEqual(
            query_database(
                self.database,
                "SELECT key, value FROM enrollment_meta WHERE key LIKE 'runtime_identity_history%' ORDER BY key",
            ),
            [
                ("runtime_identity_history_capacity", "2"),
                ("runtime_identity_history_reserved", "2"),
            ],
        )

    def test_early_v5_expired_reservation_is_normalized_on_restart(self):
        issuer = self.issuer(
            max_runtime_identity_history_per_enrollment=2,
            max_runtime_identity_history_entries=2,
        )
        expired = issuer.issue(
            issue_request(uid="expired-uid", execution="expired-execution", guest="expired-guest", ttl=1)
        )
        issuer.close()
        connection = sqlite3.connect(self.database)
        try:
            # The first schema-v5 review implementation transitioned the row
            # but retained this never-consumed lifecycle's complete allowance.
            token_digest = connection.execute("SELECT token_digest FROM enrollments").fetchone()[0]
            connection.execute(
                "UPDATE enrollments SET state = 'expired', terminal_at = expires_at WHERE token_digest = ?",
                (token_digest,),
            )
            connection.commit()
        finally:
            connection.close()

        restarted = self.issuer(
            max_runtime_identity_history_per_enrollment=2,
            max_runtime_identity_history_entries=2,
        )
        record = restarted.snapshot()["records"][0]
        self.assertEqual(record["state"], "expired")
        self.assertEqual(record["terminal_at"], expired["expires_at"])
        self.assertEqual(record["runtime_identity_history_count"], 0)
        self.assertEqual(record["runtime_identity_history_capacity"], 0)
        self.assertEqual(
            query_database(
                self.database,
                "SELECT value FROM enrollment_meta WHERE key = 'runtime_identity_history_reserved'",
            ),
            [("0",)],
        )
        replacement = restarted.issue(
            issue_request(uid="replacement-uid", execution="replacement-execution", guest="replacement-guest")
        )
        self.assertTrue(replacement["token"])

    def test_runtime_identity_admission_is_per_identity_and_unknown_safe(self):
        issuer = self.issuer(runtime_identity_rate=0.001, runtime_identity_burst=2, runtime_identity_concurrency=2)
        first = issuer.issue(issue_request())
        first_identity = issuer.exchange(exchange_request(first))["runtime_identity"]["opaque"]
        second = issuer.issue(issue_request(uid="second-uid", execution="second-execution", guest="second-guest"))
        second_identity = issuer.exchange(exchange_request(second))["runtime_identity"]["opaque"]

        for value in (100, 101, 102):
            self.assertFailure("unauthorized", lambda value=value: issuer.admit_runtime_identity(opaque_canary(value)))
        self.assertEqual(issuer.runtime_identity_admissions, {})
        first_admissions = [issuer.admit_runtime_identity(first_identity) for _ in range(2)]
        self.assertFailure("capacity-exceeded", lambda: issuer.admit_runtime_identity(first_identity))
        second_admission = issuer.admit_runtime_identity(second_identity)
        second_admission.release()
        for admission in first_admissions:
            admission.release()

        # The first lifecycle exhausted only its own token bucket. The second
        # still authenticates and completes status normally.
        self.assertEqual(
            issuer.runtime_identity_status(second_identity, runtime_status_request(second["binding"]))["binding"],
            second["binding"],
        )

    def test_runtime_identity_requests_are_record_local_and_do_not_delay_revocation(self):
        issuer = self.issuer(max_runtime_identity_history_entries=MAX_RUNTIME_IDENTITY_HISTORY_CAPACITY)
        target = issuer.issue(issue_request())
        identity = issuer.exchange(exchange_request(target))["runtime_identity"]["opaque"]
        for index in range(200):
            issuer.issue(
                issue_request(
                    uid=f"unrelated-{index}",
                    execution=f"unrelated-execution-{index}",
                    guest=f"unrelated-guest-{index}",
                )
            )

        connection = sqlite3.connect(self.database)
        try:
            token_digest = connection.execute(
                "SELECT token_digest FROM enrollments WHERE agent_run_uid = ?",
                (target["binding"]["agent_run_uid"],),
            ).fetchone()[0]
            connection.executemany(
                "INSERT INTO runtime_identity_history (runtime_identity_digest, token_digest, retired_at) VALUES (?, ?, ?)",
                ((f"sha256:{index:064x}", token_digest, format_timestamp(START)) for index in range(1, 1001)),
            )
            connection.execute(
                "UPDATE enrollments SET runtime_identity_history_count = 1000 WHERE token_digest = ?",
                (token_digest,),
            )
            connection.commit()
        finally:
            connection.close()

        statements = []
        original_connect = issuer._connect

        def traced_connect():
            connection = original_connect()
            connection.set_trace_callback(statements.append)
            return connection

        issuer._connect = traced_connect

        original_validate_store = issuer._validate_store
        full_scans = 0
        full_scan_lock = threading.Lock()

        def tracked_validate_store(connection, full=False):
            nonlocal full_scans
            if threading.current_thread().name.startswith("runtime-load"):
                with full_scan_lock:
                    full_scans += 1
                time.sleep(0.2)
            return original_validate_store(connection, full=full)

        issuer._validate_store = tracked_validate_store
        rotated_identity = opaque_canary(97)
        with patch(
            "broker.core.guest_enrollment._validate_persisted_runtime_identity_history",
            wraps=_validate_persisted_runtime_identity_history,
        ) as history_validator:
            self.assertEqual(
                issuer.runtime_identity_status(identity, runtime_status_request(target["binding"]))["binding"],
                target["binding"],
            )
            with ThreadPoolExecutor(max_workers=1, thread_name_prefix="runtime-load-rotation") as pool:
                pool.submit(
                    issuer.rotate_runtime_identity,
                    identity,
                    runtime_rotate_request(target["binding"], rotated_identity),
                ).result(timeout=2.0)
            self.assertTrue(issuer.ready())
            issuer.maintain()
            self.assertEqual(history_validator.call_count, 0)
        identity = rotated_identity
        self.assertEqual(full_scans, 0)
        self.assertFalse(
            any(
                "COUNT(*) FROM RUNTIME_IDENTITY_HISTORY" in statement.upper()
                or "ORDER BY HISTORY.RETIRED_AT" in statement.upper()
                for statement in statements
            ),
            statements,
        )

        entered = threading.Barrier(5)
        release = threading.Event()
        original_validate_lifecycle = issuer._validate_runtime_identity_lifecycle
        held_threads = set()
        held_threads_lock = threading.Lock()

        def held_validate_lifecycle(connection, row):
            result = original_validate_lifecycle(connection, row)
            if threading.current_thread().name.startswith("runtime-load"):
                with held_threads_lock:
                    first_call = threading.get_ident() not in held_threads
                    held_threads.add(threading.get_ident())
                if first_call:
                    entered.wait(timeout=2.0)
                    release.wait(timeout=2.0)
            return result

        issuer._validate_runtime_identity_lifecycle = held_validate_lifecycle

        def status_call():
            return issuer.runtime_identity_status(identity, runtime_status_request(target["binding"]))

        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="runtime-load") as pool:
            futures = [pool.submit(status_call) for _ in range(4)]
            entered.wait(timeout=2.0)
            started = time.monotonic()
            issuer.revoke_execution(
                revoke_execution_request(issue_request(uid="missing-uid", execution="missing-execution")["binding"])
            )
            elapsed = time.monotonic() - started
            release.set()
            for future in futures:
                future.result(timeout=2.0)

        self.assertEqual(full_scans, 0)
        self.assertLess(elapsed, 0.5)

    def test_runtime_identity_expiry_and_malformed_state_fail_closed(self):
        issuer = self.issuer()
        first = issuer.issue(issue_request())
        identity = issuer.exchange(exchange_request(first))["runtime_identity"]["opaque"]
        self.clock.value += timedelta(hours=1)
        self.assertFailure("unauthorized", lambda: issuer.runtime_identity_status(identity, runtime_status_request(first["binding"])))
        self.assertFailure(
            "unauthorized",
            lambda: issuer.rotate_runtime_identity(identity, runtime_rotate_request(first["binding"], opaque_canary(76))),
        )

        second = issuer.issue(issue_request(uid="corrupt-uid", execution="corrupt-execution", guest="corrupt-guest"))
        second_identity = issuer.exchange(exchange_request(second))["runtime_identity"]["opaque"]
        update_database(self.database, "UPDATE enrollments SET expires_at = ? WHERE agent_run_uid = ?", ("invalid", "uid-run"))
        self.assertFailure("issuer-storage-failed", issuer.validate_integrity)
        self.assertFalse(issuer.ready())
        self.assertFailure(
            "issuer-storage-failed",
            lambda: issuer.runtime_identity_status(second_identity, runtime_status_request(second["binding"])),
        )
        self.assertFailure(
            "issuer-storage-failed",
            lambda: issuer.rotate_runtime_identity(
                second_identity,
                runtime_rotate_request(second["binding"], opaque_canary(77)),
            ),
        )

    def test_unknown_runtime_identities_do_not_scan_or_block_revocation(self):
        issuer = self.issuer()
        original_validate_store = issuer._validate_store
        unknown_validation_calls = 0
        validation_lock = threading.Lock()

        def tracked_validate_store(connection, full=False):
            nonlocal unknown_validation_calls
            if threading.current_thread().name.startswith("unknown-runtime"):
                with validation_lock:
                    unknown_validation_calls += 1
                time.sleep(0.05)
            return original_validate_store(connection, full=full)

        issuer._validate_store = tracked_validate_store
        request = runtime_status_request(issue_request()["binding"])
        barrier = threading.Barrier(17)

        def unknown_status(index):
            barrier.wait()
            try:
                issuer.runtime_identity_status(opaque_canary(100 + index), request)
            except EnrollmentFailure as error:
                return error.reason
            return "unexpected-success"

        with ThreadPoolExecutor(max_workers=16, thread_name_prefix="unknown-runtime") as pool:
            futures = [pool.submit(unknown_status, index) for index in range(16)]
            barrier.wait()
            started = time.monotonic()
            issuer.revoke_execution(revoke_execution_request(issue_request()["binding"]))
            elapsed = time.monotonic() - started
            reasons = [future.result(timeout=2.0) for future in futures]

        self.assertEqual(reasons, ["unauthorized"] * 16)
        self.assertEqual(unknown_validation_calls, 0)
        self.assertLess(elapsed, 0.5)

    def test_binding_mismatch_does_not_consume(self):
        issuer = self.issuer()
        envelope = issuer.issue(issue_request())
        wrong = exchange_request(envelope)
        wrong["binding"] = dict(wrong["binding"], guest_instance_id="wrong-guest")
        self.assertFailure("binding-mismatch", lambda: issuer.exchange(wrong))
        result = issuer.exchange(exchange_request(envelope))
        self.assertEqual(result["binding"], envelope["binding"])

    def test_clock_rollback_cannot_commit_invalid_identity_timestamps(self):
        issuer = self.issuer()
        envelope = issuer.issue(issue_request())
        self.clock.value = START - timedelta(seconds=1)
        result = issuer.exchange(exchange_request(envelope))
        record = issuer.snapshot()["records"][0]
        self.assertEqual(result["runtime_identity"]["issued_at"], envelope["issued_at"])
        self.assertEqual(record["runtime_identity_issued_at"], envelope["issued_at"])
        self.assertTrue(issuer.ready())

    def test_unrelated_semantic_corruption_blocks_exchange(self):
        issuer = self.issuer()
        bad = issuer.issue(issue_request(uid="bad-uid", execution="bad-execution", guest="bad-guest"))
        good = issuer.issue(issue_request(uid="good-uid", execution="good-execution", guest="good-guest"))
        update_database(
            self.database,
            "UPDATE enrollments SET expires_at = ? WHERE guest_instance_id = ?",
            ("not-a-timestamp", bad["binding"]["guest_instance_id"]),
        )
        self.assertFailure("issuer-storage-failed", issuer.validate_integrity)
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

    def test_concurrent_invalid_exchange_does_not_take_writer_validation_path(self):
        issuer = self.issuer()
        original_validate_store = issuer._validate_store
        invalid_validation_calls = 0
        validation_lock = threading.Lock()

        def tracked_validate_store(connection, full=False):
            nonlocal invalid_validation_calls
            if threading.current_thread().name.startswith("invalid-exchange"):
                with validation_lock:
                    invalid_validation_calls += 1
                # If an invalid public request reaches full validation while
                # holding BEGIN IMMEDIATE, concurrent requests serialize here.
                time.sleep(0.05)
            return original_validate_store(connection, full=full)

        issuer._validate_store = tracked_validate_store
        invalid = exchange_request(
            {
                "contract_version": VERSION,
                "binding": issue_request(uid="invalid-uid", execution="invalid-execution")["binding"],
                "token": "A" * 43,
            }
        )
        barrier = threading.Barrier(17)

        def invalid_exchange(_index):
            barrier.wait()
            try:
                issuer.exchange(invalid)
            except EnrollmentFailure as error:
                return error.reason
            return "unexpected-success"

        with ThreadPoolExecutor(max_workers=16, thread_name_prefix="invalid-exchange") as pool:
            futures = [pool.submit(invalid_exchange, index) for index in range(16)]
            barrier.wait()
            started = time.monotonic()
            issuer.revoke_execution(revoke_execution_request(issue_request()["binding"]))
            elapsed = time.monotonic() - started
            reasons = [future.result(timeout=2.0) for future in futures]

        self.assertEqual(reasons, ["invalid-token"] * 16)
        self.assertEqual(invalid_validation_calls, 0)
        self.assertLess(elapsed, 0.5)

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
        issuer.revoke_execution(revoke_execution_request(request["binding"]))
        issuer.complete_execution_cleanup(complete_execution_cleanup_request(request["binding"]))
        self.clock.value += TOMBSTONE_RETENTION
        issuer.maintain()
        self.assertEqual(issuer.snapshot()["binding_tombstones"], [])
        self.assertEqual(issuer.snapshot()["execution_tombstones"], [])

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
        issuer.complete_execution_cleanup(complete_execution_cleanup_request(expiring["binding"]))
        self.clock.value = START + timedelta(seconds=2) + TOMBSTONE_RETENTION
        issuer.maintain()
        self.assertEqual(sum(len(value) for value in issuer.snapshot().values()), 1)
        replacement = issuer.issue(issue_request(guest="after-gc"))
        self.assertTrue(replacement["token"])

    def test_unexchanged_expiry_releases_reserved_rotation_capacity(self):
        issuer = self.issuer(
            max_runtime_identity_history_per_enrollment=2,
            max_runtime_identity_history_entries=2,
        )
        maintained = issuer.issue(
            issue_request(uid="maintained-uid", execution="maintained-execution", guest="maintained-guest", ttl=1)
        )
        self.assertEqual(
            query_database(
                self.database,
                "SELECT value FROM enrollment_meta WHERE key = 'runtime_identity_history_reserved'",
            ),
            [("2",)],
        )

        self.clock.value += timedelta(seconds=2)
        issuer.maintain()
        records = {record["agent_run_uid"]: record for record in issuer.snapshot()["records"]}
        self.assertEqual(records["maintained-uid"]["state"], "expired")
        self.assertEqual(records["maintained-uid"]["terminal_at"], maintained["expires_at"])
        self.assertEqual(records["maintained-uid"]["runtime_identity_history_count"], 0)
        self.assertEqual(records["maintained-uid"]["runtime_identity_history_capacity"], 0)
        self.assertEqual(
            query_database(
                self.database,
                "SELECT value FROM enrollment_meta WHERE key = 'runtime_identity_history_reserved'",
            ),
            [("0",)],
        )

        replacement = issuer.issue(
            issue_request(uid="replacement-uid", execution="replacement-execution", guest="replacement-guest")
        )
        self.assertTrue(replacement["token"])
        issuer.revoke_binding(revoke_binding_request(replacement["binding"]))

        issue_time = issuer.issue(
            issue_request(uid="issue-time-uid", execution="issue-time-execution", guest="issue-time-guest", ttl=1)
        )
        self.clock.value += timedelta(seconds=2)
        after_issue_time_expiry = issuer.issue(
            issue_request(uid="after-issue-uid", execution="after-issue-execution", guest="after-issue-guest")
        )
        records = {record["agent_run_uid"]: record for record in issuer.snapshot()["records"]}
        self.assertEqual(records["issue-time-uid"]["state"], "expired")
        self.assertEqual(records["issue-time-uid"]["terminal_at"], issue_time["expires_at"])
        self.assertEqual(records["issue-time-uid"]["runtime_identity_history_capacity"], 0)
        self.assertTrue(after_issue_time_expiry["token"])
        issuer.revoke_binding(revoke_binding_request(after_issue_time_expiry["binding"]))

        late = issuer.issue(
            issue_request(uid="late-uid", execution="late-execution", guest="late-guest", ttl=1)
        )
        self.clock.value += timedelta(seconds=2)
        self.assertFailure("expired", lambda: issuer.exchange(exchange_request(late)))
        records = {record["agent_run_uid"]: record for record in issuer.snapshot()["records"]}
        self.assertEqual(records["late-uid"]["state"], "expired")
        self.assertEqual(records["late-uid"]["terminal_at"], late["expires_at"])
        self.assertEqual(records["late-uid"]["runtime_identity_history_count"], 0)
        self.assertEqual(records["late-uid"]["runtime_identity_history_capacity"], 0)
        self.assertEqual(
            query_database(
                self.database,
                "SELECT value FROM enrollment_meta WHERE key = 'runtime_identity_history_reserved'",
            ),
            [("0",)],
        )
        unrelated = issuer.issue(
            issue_request(uid="unrelated-uid", execution="unrelated-execution", guest="unrelated-guest")
        )
        self.assertTrue(unrelated["token"])

    def test_late_expiry_uses_original_deadline_and_completed_scope_gc(self):
        issuer = self.issuer()
        expired = issuer.issue(issue_request(uid="expired-uid", execution="expired-execution", guest="expired-guest", ttl=1))
        self.clock.value = START + TOMBSTONE_RETENTION + timedelta(hours=1)
        self.assertFailure("expired", lambda: issuer.exchange(exchange_request(expired)))
        records = {record["agent_run_uid"]: record for record in issuer.snapshot()["records"]}
        self.assertEqual(records["expired-uid"]["terminal_at"], expired["expires_at"])

        issuer.revoke_execution(revoke_execution_request(expired["binding"]))
        issuer.complete_execution_cleanup(complete_execution_cleanup_request(expired["binding"]))
        self.clock.value += TOMBSTONE_RETENTION
        live = issuer.issue(issue_request(uid="live-uid", execution="live-execution", guest="live-guest"))
        issuer.maintain()
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
        identity = result["runtime_identity"]["opaque"]
        runtime_acquired = [issuer.runtime_identity_slots.acquire(blocking=False) for _ in range(32)]
        self.assertTrue(all(runtime_acquired))
        self.assertFailure(
            "capacity-exceeded",
            lambda: issuer.runtime_identity_status(identity, runtime_status_request(envelope["binding"])),
        )
        for _ in runtime_acquired:
            issuer.runtime_identity_slots.release()
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
        lost_restarted.complete_execution_cleanup(complete_execution_cleanup_request(lost_envelope["binding"]))
        self.assertEqual(lost_restarted.snapshot()["records"], [])

    def test_cleanup_completion_is_durable_idempotent_and_reuses_capacity_after_retention(self):
        database = str(Path(self.temporary.name) / "completion.sqlite3")
        issuer = GuestEnrollmentIssuer(database, EXCHANGE_URL, now=self.clock, max_entries=1, maintenance_interval=None)
        self.addCleanup(issuer.close)
        request = issue_request(uid="completed-uid", execution="completed-execution", guest="completed-guest")
        issuer.revoke_execution(revoke_execution_request(request["binding"]))
        self.assertFailure("capacity-exceeded", lambda: issuer.issue(issue_request(uid="blocked", execution="blocked")))
        issuer.complete_execution_cleanup(complete_execution_cleanup_request(request["binding"]))
        # Simulate a response lost after the durable transaction and an issuer restart.
        issuer.close()
        restarted = GuestEnrollmentIssuer(database, EXCHANGE_URL, now=self.clock, max_entries=1, maintenance_interval=None)
        self.addCleanup(restarted.close)
        restarted.complete_execution_cleanup(complete_execution_cleanup_request(request["binding"]))
        tombstone = restarted.snapshot()["execution_tombstones"][0]
        self.assertEqual(tombstone["cleanup_completed_at"], format_timestamp(self.clock.value))
        self.assertFailure("capacity-exceeded", lambda: restarted.issue(issue_request(uid="still-blocked", execution="still-blocked")))
        self.clock.value += TOMBSTONE_RETENTION
        restarted.maintain()
        self.assertEqual(restarted.snapshot()["execution_tombstones"], [])
        self.assertTrue(restarted.issue(issue_request(uid="reused", execution="reused"))["token"])

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
        self.assertFailure("issuer-storage-failed", live.validate_integrity)
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

        cleanup_tombstone_database = str(Path(self.temporary.name) / "cleanup-tombstone.sqlite3")
        cleanup_issuer = GuestEnrollmentIssuer(cleanup_tombstone_database, EXCHANGE_URL, now=self.clock, maintenance_interval=None)
        cleanup_issuer.revoke_execution(revoke_execution_request(request["binding"]))
        cleanup_issuer.complete_execution_cleanup(complete_execution_cleanup_request(request["binding"]))
        cleanup_issuer.close()
        update_database(cleanup_tombstone_database, "UPDATE execution_tombstones SET cleanup_completed_at = ?", ("invalid",))
        with self.assertRaisesRegex(EnrollmentConfigError, "database initialization failed"):
            GuestEnrollmentIssuer(cleanup_tombstone_database, EXCHANGE_URL, maintenance_interval=None)

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

        history_database = str(Path(self.temporary.name) / "runtime-identity-history.sqlite3")
        history_issuer = GuestEnrollmentIssuer(
            history_database,
            EXCHANGE_URL,
            now=self.clock,
            random_bytes=DeterministicRandom(61),
            maintenance_interval=None,
        )
        history_envelope = history_issuer.issue(issue_request(uid="history-uid", execution="history-execution"))
        history_identity = history_issuer.exchange(exchange_request(history_envelope))["runtime_identity"]["opaque"]
        history_issuer.rotate_runtime_identity(
            history_identity,
            runtime_rotate_request(history_envelope["binding"], opaque_canary(95)),
        )
        history_issuer.close()
        update_database(history_database, "UPDATE runtime_identity_history SET retired_at = ?", ("invalid",))
        with self.assertRaisesRegex(EnrollmentConfigError, "database initialization failed"):
            GuestEnrollmentIssuer(history_database, EXCHANGE_URL, maintenance_interval=None)

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
        self.assertEqual(
            query_database(migration_database, "SELECT value FROM enrollment_meta WHERE key = 'schema_version'"),
            [("5",)],
        )

        schema_v2_database = str(Path(self.temporary.name) / "schema-v2.sqlite3")
        schema_v2 = GuestEnrollmentIssuer(schema_v2_database, EXCHANGE_URL, now=self.clock, maintenance_interval=None)
        schema_v2.revoke_execution(revoke_execution_request(issue_request(uid="v2-uid", execution="v2-execution")["binding"]))
        schema_v2.close()
        connection = sqlite3.connect(schema_v2_database)
        try:
            connection.execute("ALTER TABLE execution_tombstones DROP COLUMN cleanup_completed_at")
            connection.execute("UPDATE enrollment_meta SET value = '2' WHERE key = 'schema_version'")
            connection.commit()
        finally:
            connection.close()
        migrated_v2 = GuestEnrollmentIssuer(schema_v2_database, EXCHANGE_URL, now=self.clock, maintenance_interval=None)
        self.addCleanup(migrated_v2.close)
        self.assertIsNone(migrated_v2.snapshot()["execution_tombstones"][0]["cleanup_completed_at"])
        self.assertEqual(
            query_database(schema_v2_database, "SELECT value FROM enrollment_meta WHERE key = 'schema_version'"),
            [("5",)],
        )

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
        valid_token_file = Path(self.temporary.name) / "valid-orchestrator-token"
        valid_token_file.write_text("orchestrator-token-0123456789abcdef", encoding="utf-8")
        environment = {
            "NVT_BROKER_GUEST_ENROLLMENT_ENABLED": "true",
            "NVT_BROKER_GUEST_ENROLLMENT_DB": str(Path(self.temporary.name) / "configured.sqlite3"),
            "NVT_BROKER_GUEST_ENROLLMENT_EXCHANGE_URL": EXCHANGE_URL,
            "NVT_BROKER_GUEST_ENROLLMENT_ORCHESTRATOR_TOKEN_FILE": str(valid_token_file),
            "NVT_BROKER_GUEST_ENROLLMENT_RUNTIME_IDENTITY_HISTORY_CAPACITY": "20000",
        }
        with patch.dict("os.environ", environment, clear=True):
            configured, _ = load_guest_enrollment_from_environment()
            self.addCleanup(configured.close)
            self.assertEqual(configured.max_runtime_identity_history_entries, 20000)
        for invalid_capacity in ("0", "19999", "10000001", "not-a-count"):
            with self.subTest(history_capacity=invalid_capacity):
                environment["NVT_BROKER_GUEST_ENROLLMENT_RUNTIME_IDENTITY_HISTORY_CAPACITY"] = invalid_capacity
                with patch.dict("os.environ", environment, clear=True):
                    with self.assertRaisesRegex(EnrollmentConfigError, "history capacity"):
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


def runtime_status_request(value):
    return {"contract_version": RUNTIME_IDENTITY_VERSION, "binding": dict(value)}


def runtime_rotate_request(value, successor):
    return {
        "contract_version": RUNTIME_IDENTITY_VERSION,
        "binding": dict(value),
        "successor": successor,
    }


def opaque_canary(value):
    return base64.urlsafe_b64encode(bytes([value]) * 32).rstrip(b"=").decode("ascii")


def runtime_identity_is_active(issuer, identity, value):
    try:
        issuer.runtime_identity_status(identity, runtime_status_request(value))
        return True
    except EnrollmentFailure as error:
        if error.reason != "unauthorized":
            raise
        return False


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


def complete_execution_cleanup_request(value):
    return {
        "contract_version": VERSION,
        "execution_scope": execution_scope(value),
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
