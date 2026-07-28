import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit


VERSION = "nvt.guest-enrollment/v1"
RUNTIME_IDENTITY_TYPE = "nvt.runtime-identity/v1"
RUNTIME_IDENTITY_VERSION = "nvt.guest-runtime-identity/v1"
STORE_SCHEMA_VERSION = "3"
TOKEN_BYTES = 32
MAX_ISSUE_REQUEST_BYTES = 4 << 10
MAX_EXCHANGE_REQUEST_BYTES = 16 << 10
MAX_REVOCATION_REQUEST_BYTES = 4 << 10
MAX_RUNTIME_IDENTITY_STATUS_REQUEST_BYTES = 4 << 10
MAX_RUNTIME_IDENTITY_ROTATE_REQUEST_BYTES = 16 << 10
MAX_AGENT_RUN_UID_BYTES = 128
MAX_EXECUTION_ID_BYTES = 256
MAX_DRIVER_NAME_BYTES = 63
MAX_GUEST_INSTANCE_ID_BYTES = 256
MAX_EXCHANGE_URL_BYTES = 2048
MAX_ENROLLMENT_TTL_SECONDS = 900
MAX_RUNTIME_IDENTITY_LIFETIME = timedelta(hours=24)
MAX_DURABLE_ENTRIES = 10_000
TOMBSTONE_RETENTION = timedelta(hours=24)
MAX_CONCURRENT_EXCHANGES = 32
EXCHANGE_RATE_PER_SECOND = 128.0
EXCHANGE_RATE_BURST = 256.0
MAX_CONCURRENT_RUNTIME_IDENTITY_REQUESTS = 32
RUNTIME_IDENTITY_RATE_PER_SECOND = 128.0
RUNTIME_IDENTITY_RATE_BURST = 256.0

ISSUE_PATH = "/v1/guest-enrollment/issue"
EXCHANGE_PATH = "/v1/guest-enrollment/exchange"
REVOKE_BINDING_PATH = "/v1/guest-enrollment/revoke-binding"
REVOKE_EXECUTION_PATH = "/v1/guest-enrollment/revoke-execution"
COMPLETE_EXECUTION_CLEANUP_PATH = "/v1/guest-enrollment/complete-execution-cleanup"
RUNTIME_IDENTITY_STATUS_PATH = "/v1/guest-runtime-identity/status"
RUNTIME_IDENTITY_ROTATE_PATH = "/v1/guest-runtime-identity/rotate"
ENDPOINT_LIMITS = {
    ISSUE_PATH: MAX_ISSUE_REQUEST_BYTES,
    EXCHANGE_PATH: MAX_EXCHANGE_REQUEST_BYTES,
    REVOKE_BINDING_PATH: MAX_REVOCATION_REQUEST_BYTES,
    REVOKE_EXECUTION_PATH: MAX_REVOCATION_REQUEST_BYTES,
    COMPLETE_EXECUTION_CLEANUP_PATH: MAX_REVOCATION_REQUEST_BYTES,
    RUNTIME_IDENTITY_STATUS_PATH: MAX_RUNTIME_IDENTITY_STATUS_REQUEST_BYTES,
    RUNTIME_IDENTITY_ROTATE_PATH: MAX_RUNTIME_IDENTITY_ROTATE_REQUEST_BYTES,
}

DRIVER_NAME_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ORCHESTRATOR_TOKEN_RE = re.compile(rb"^[A-Za-z0-9._~-]{32,4096}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class EnrollmentConfigError(Exception):
    pass


class EnrollmentFailure(Exception):
    def __init__(self, reason, status=400):
        super().__init__(f"guest enrollment rejected: {reason}")
        self.reason = reason
        self.status = status


class EnrollmentFaults:
    """Injectable transaction boundaries used only by direct conformance tests."""

    def before_exchange_commit(self):
        return None

    def after_exchange_commit(self):
        return None

    def before_rotation_commit(self):
        return None

    def after_rotation_commit(self):
        return None


class _RateLimiter:
    def __init__(self, rate, burst, monotonic=time.monotonic):
        self.rate = rate
        self.burst = burst
        self.monotonic = monotonic
        self.tokens = burst
        self.updated = monotonic()
        self.lock = threading.Lock()

    def allow(self):
        with self.lock:
            now = self.monotonic()
            elapsed = max(0.0, now - self.updated)
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.updated = now
            if self.tokens < 1.0:
                return False
            self.tokens -= 1.0
            return True


class OrchestratorAuthenticator:
    def __init__(self, token_file):
        path = Path(token_file)
        try:
            value = path.read_bytes()
        except OSError as error:
            raise EnrollmentConfigError("guest enrollment orchestrator token file is unreadable") from error
        if not ORCHESTRATOR_TOKEN_RE.fullmatch(value):
            raise EnrollmentConfigError("guest enrollment orchestrator token file is invalid")
        self._digest = hashlib.sha256(value).digest()

    def authenticate(self, authorization):
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            raise EnrollmentFailure("unauthorized", 401)
        supplied = authorization.removeprefix("Bearer ").encode("utf-8", "strict")
        if not ORCHESTRATOR_TOKEN_RE.fullmatch(supplied):
            raise EnrollmentFailure("unauthorized", 401)
        if not hmac.compare_digest(hashlib.sha256(supplied).digest(), self._digest):
            raise EnrollmentFailure("unauthorized", 401)
        return "guest-enrollment-orchestrator"


class GuestEnrollmentIssuer:
    def __init__(
        self,
        database_path,
        exchange_url,
        *,
        now=None,
        random_bytes=None,
        faults=None,
        max_entries=MAX_DURABLE_ENTRIES,
        maintenance_interval=60.0,
    ):
        self.database_path = _validate_database_path(database_path)
        self.exchange_url = validate_exchange_url(exchange_url)
        if not isinstance(max_entries, int) or isinstance(max_entries, bool) or max_entries < 1 or max_entries > MAX_DURABLE_ENTRIES:
            raise EnrollmentConfigError("guest enrollment durable entry limit is invalid")
        self.max_entries = max_entries
        self.now = now or (lambda: datetime.now(timezone.utc).replace(microsecond=0))
        self.random_bytes = random_bytes or secrets.token_bytes
        self.faults = faults or EnrollmentFaults()
        self.exchange_slots = threading.BoundedSemaphore(MAX_CONCURRENT_EXCHANGES)
        self.exchange_rate = _RateLimiter(EXCHANGE_RATE_PER_SECOND, EXCHANGE_RATE_BURST)
        self.runtime_identity_slots = threading.BoundedSemaphore(MAX_CONCURRENT_RUNTIME_IDENTITY_REQUESTS)
        self.runtime_identity_rate = _RateLimiter(RUNTIME_IDENTITY_RATE_PER_SECOND, RUNTIME_IDENTITY_RATE_BURST)
        self.stop_event = threading.Event()
        self.maintenance_thread = None
        self._initialize()
        try:
            self.maintain()
        except EnrollmentFailure as error:
            raise EnrollmentConfigError("guest enrollment database maintenance failed") from error
        if maintenance_interval is not None:
            if not isinstance(maintenance_interval, (int, float)) or isinstance(maintenance_interval, bool) or maintenance_interval <= 0:
                raise EnrollmentConfigError("guest enrollment maintenance interval is invalid")
            self.maintenance_thread = threading.Thread(
                target=self._maintenance_loop,
                args=(float(maintenance_interval),),
                name="guest-enrollment-maintenance",
                daemon=True,
            )
            self.maintenance_thread.start()

    def close(self):
        self.stop_event.set()
        if self.maintenance_thread is not None:
            self.maintenance_thread.join(timeout=2.0)

    def ready(self):
        try:
            with self._connect() as connection:
                self._validate_store(connection)
                return True
        except sqlite3.Error:
            return False

    def issue(self, request):
        binding, ttl_seconds = validate_issue_request(request)
        now = self._now()
        try:
            token = _opaque_random(self.random_bytes, TOKEN_BYTES)
        except Exception as error:
            raise EnrollmentFailure("identity-issuance-failed", 503) from error
        token_digest = _digest(token)
        issued_at = format_timestamp(now)
        expires_at = format_timestamp(now + timedelta(seconds=ttl_seconds))
        connection = self._connect_or_failure()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_store(connection)
            self._expire_issued(connection, now)
            if self._scope_tombstoned(connection, binding):
                raise EnrollmentFailure("revoked", 409)
            if self._binding_tombstoned(connection, binding):
                raise EnrollmentFailure("revoked", 409)
            if self._binding_record(connection, binding) is not None:
                raise EnrollmentFailure("already-issued", 409)
            if self._entry_count(connection) >= self.max_entries:
                raise EnrollmentFailure("capacity-exceeded", 429)
            connection.execute(
                """
                INSERT INTO enrollments (
                    token_digest, agent_run_uid, execution_id, driver_registration,
                    desired_generation, guest_instance_id, issued_at, expires_at,
                    state, terminal_at, runtime_identity_digest, runtime_identity_active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'issued', NULL, NULL, 0)
                """,
                (token_digest, *_binding_values(binding), issued_at, expires_at),
            )
            connection.commit()
        except EnrollmentFailure:
            _rollback(connection)
            raise
        except sqlite3.Error as error:
            _rollback(connection)
            raise EnrollmentFailure("issuer-storage-failed", 503) from error
        finally:
            connection.close()
        return {
            "contract_version": VERSION,
            "binding": binding,
            "exchange_url": self.exchange_url,
            "token": token,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }

    def exchange(self, request):
        binding, token = validate_exchange_request(request)
        if not self.exchange_rate.allow() or not self.exchange_slots.acquire(blocking=False):
            raise EnrollmentFailure("capacity-exceeded", 429)
        try:
            return self._exchange_locked(binding, token)
        finally:
            self.exchange_slots.release()

    def _exchange_locked(self, binding, token):
        now = self._now()
        token_digest = _digest(token)
        self._preflight_exchange_candidate(binding, token_digest)
        connection = self._connect_or_failure()
        committed = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_store(connection)
            if self._scope_tombstoned(connection, binding) or self._binding_tombstoned(connection, binding):
                raise EnrollmentFailure("revoked", 409)
            row = connection.execute("SELECT * FROM enrollments WHERE token_digest = ?", (token_digest,)).fetchone()
            if row is None:
                raise EnrollmentFailure("invalid-token", 401)
            _validate_persisted_enrollment(row)
            if row["state"] == "consumed":
                raise EnrollmentFailure("already-consumed", 409)
            if row["state"] == "revoked":
                raise EnrollmentFailure("revoked", 409)
            if row["state"] == "expired":
                raise EnrollmentFailure("expired", 409)
            if row["state"] != "issued":
                raise EnrollmentFailure("invalid-token", 401)
            expires_at = parse_timestamp(row["expires_at"])
            if now >= expires_at:
                connection.execute(
                    "UPDATE enrollments SET state = 'expired', terminal_at = expires_at WHERE token_digest = ?",
                    (token_digest,),
                )
                connection.commit()
                committed = True
                raise EnrollmentFailure("expired", 409)
            if _row_binding(row) != binding:
                raise EnrollmentFailure("binding-mismatch", 403)

            try:
                identity = _opaque_random(self.random_bytes, TOKEN_BYTES)
            except Exception as error:
                raise EnrollmentFailure("identity-issuance-failed", 503) from error
            identity_digest = _digest(identity)
            enrollment_issued_at = parse_timestamp(row["issued_at"])
            identity_issued_time = max(now, enrollment_issued_at)
            identity_issued_at = format_timestamp(identity_issued_time)
            identity_expires_at = format_timestamp(identity_issued_time + timedelta(hours=1))
            connection.execute(
                """
                UPDATE enrollments
                   SET state = 'consumed', runtime_identity_digest = ?,
                       runtime_identity_issued_at = ?, runtime_identity_expires_at = ?,
                       runtime_identity_active = 1
                 WHERE token_digest = ? AND state = 'issued'
                """,
                (identity_digest, identity_issued_at, identity_expires_at, token_digest),
            )
            try:
                self.faults.before_exchange_commit()
            except Exception as error:
                raise EnrollmentFailure("issuer-storage-failed", 503) from error
            connection.commit()
            committed = True
            self.faults.after_exchange_commit()
            return {
                "contract_version": VERSION,
                "binding": binding,
                "runtime_identity": {
                    "type": RUNTIME_IDENTITY_TYPE,
                    "opaque": identity,
                    "issued_at": identity_issued_at,
                    "expires_at": identity_expires_at,
                },
            }
        except EnrollmentFailure:
            if not committed:
                _rollback(connection)
            raise
        except sqlite3.Error as error:
            if not committed:
                _rollback(connection)
            raise EnrollmentFailure("issuer-storage-failed", 503) from error
        finally:
            connection.close()

    def _preflight_exchange_candidate(self, binding, token_digest):
        """Reject absent tokens through indexed reads without a writer lock."""
        connection = self._connect_or_failure()
        try:
            connection.execute("BEGIN")
            if self._scope_tombstoned(connection, binding) or self._binding_tombstoned(connection, binding):
                raise EnrollmentFailure("revoked", 409)
            row = connection.execute(
                "SELECT 1 FROM enrollments WHERE token_digest = ?",
                (token_digest,),
            ).fetchone()
            if row is None:
                raise EnrollmentFailure("invalid-token", 401)
        except EnrollmentFailure:
            _rollback(connection)
            raise
        except sqlite3.Error as error:
            _rollback(connection)
            raise EnrollmentFailure("issuer-storage-failed", 503) from error
        finally:
            connection.close()

    def runtime_identity_status(self, identity, request):
        binding = validate_runtime_identity_status_request(request)
        identity_digest = _runtime_identity_digest(identity)
        if not self.runtime_identity_rate.allow() or not self.runtime_identity_slots.acquire(blocking=False):
            raise EnrollmentFailure("capacity-exceeded", 429)
        try:
            self._preflight_runtime_identity_candidate(identity_digest)
            now = self._now()
            connection = self._connect_or_failure()
            try:
                connection.execute("BEGIN")
                self._validate_store(connection)
                row = connection.execute(
                    "SELECT * FROM enrollments WHERE runtime_identity_digest = ?",
                    (identity_digest,),
                ).fetchone()
                return self._authenticated_runtime_identity_status(row, binding, now)
            except EnrollmentFailure:
                _rollback(connection)
                raise
            except sqlite3.Error as error:
                _rollback(connection)
                raise EnrollmentFailure("issuer-storage-failed", 503) from error
            finally:
                connection.close()
        finally:
            self.runtime_identity_slots.release()

    def rotate_runtime_identity(self, identity, request):
        binding, successor = validate_runtime_identity_rotate_request(request)
        identity_digest = _runtime_identity_digest(identity)
        successor_digest = _runtime_identity_digest(successor)
        if hmac.compare_digest(identity_digest, successor_digest):
            raise EnrollmentFailure("invalid-request", 400)
        if not self.runtime_identity_rate.allow() or not self.runtime_identity_slots.acquire(blocking=False):
            raise EnrollmentFailure("capacity-exceeded", 429)
        try:
            self._preflight_runtime_identity_candidate(identity_digest)
            return self._rotate_runtime_identity_locked(binding, identity_digest, successor_digest)
        finally:
            self.runtime_identity_slots.release()

    def _rotate_runtime_identity_locked(self, binding, identity_digest, successor_digest):
        now = self._now()
        connection = self._connect_or_failure()
        committed = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_store(connection)
            if self._scope_tombstoned(connection, binding) or self._binding_tombstoned(connection, binding):
                raise EnrollmentFailure("unauthorized", 401)
            row = connection.execute(
                "SELECT * FROM enrollments WHERE runtime_identity_digest = ?",
                (identity_digest,),
            ).fetchone()
            self._authenticated_runtime_identity_status(row, binding, now)
            if connection.execute(
                "SELECT 1 FROM enrollments WHERE runtime_identity_digest = ?",
                (successor_digest,),
            ).fetchone() is not None:
                raise EnrollmentFailure("invalid-request", 400)

            previous_issued_at = parse_timestamp(row["runtime_identity_issued_at"])
            successor_issued_time = max(now, previous_issued_at)
            successor_issued_at = format_timestamp(successor_issued_time)
            successor_expires_at = format_timestamp(successor_issued_time + timedelta(hours=1))
            updated = connection.execute(
                """
                UPDATE enrollments
                   SET runtime_identity_digest = ?, runtime_identity_issued_at = ?,
                       runtime_identity_expires_at = ?, runtime_identity_active = 1,
                       terminal_at = NULL
                 WHERE token_digest = ? AND runtime_identity_digest = ?
                   AND state = 'consumed' AND runtime_identity_active = 1
                """,
                (
                    successor_digest,
                    successor_issued_at,
                    successor_expires_at,
                    row["token_digest"],
                    identity_digest,
                ),
            ).rowcount
            if updated != 1:
                raise EnrollmentFailure("unauthorized", 401)
            try:
                self.faults.before_rotation_commit()
            except Exception as error:
                raise EnrollmentFailure("issuer-storage-failed", 503) from error
            connection.commit()
            committed = True
            self.faults.after_rotation_commit()
            return _runtime_identity_status(binding, successor_issued_at, successor_expires_at)
        except EnrollmentFailure:
            if not committed:
                _rollback(connection)
            raise
        except sqlite3.Error as error:
            if not committed:
                _rollback(connection)
            raise EnrollmentFailure("issuer-storage-failed", 503) from error
        finally:
            connection.close()

    def _authenticated_runtime_identity_status(self, row, binding, now):
        if row is None:
            raise EnrollmentFailure("unauthorized", 401)
        _validate_persisted_enrollment(row)
        if (
            row["state"] != "consumed"
            or row["runtime_identity_active"] != 1
            or _row_binding(row) != binding
            or now >= parse_timestamp(row["runtime_identity_expires_at"])
        ):
            raise EnrollmentFailure("unauthorized", 401)
        return _runtime_identity_status(
            binding,
            row["runtime_identity_issued_at"],
            row["runtime_identity_expires_at"],
        )

    def _preflight_runtime_identity_candidate(self, identity_digest):
        """Reject absent bearer digests without a full scan or writer lock."""
        connection = self._connect_or_failure()
        try:
            connection.execute("BEGIN")
            row = connection.execute(
                "SELECT 1 FROM enrollments WHERE runtime_identity_digest = ?",
                (identity_digest,),
            ).fetchone()
            if row is None:
                raise EnrollmentFailure("unauthorized", 401)
        except EnrollmentFailure:
            _rollback(connection)
            raise
        except sqlite3.Error as error:
            _rollback(connection)
            raise EnrollmentFailure("issuer-storage-failed", 503) from error
        finally:
            connection.close()

    def revoke_binding(self, request):
        binding = validate_revoke_binding_request(request)
        now = self._now()
        connection = self._connect_or_failure()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_store(connection)
            if self._scope_tombstoned(connection, binding):
                connection.commit()
                return
            matching = self._binding_record_count(connection, binding)
            tombstone_present = self._binding_tombstoned(connection, binding)
            if not tombstone_present and self._entry_count(connection) + 1 - matching > self.max_entries:
                raise EnrollmentFailure("capacity-exceeded", 429)
            if not tombstone_present:
                connection.execute(
                    """
                    INSERT INTO binding_tombstones (
                        agent_run_uid, execution_id, driver_registration,
                        desired_generation, guest_instance_id, created_at, delete_after
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (*_binding_values(binding), format_timestamp(now), format_timestamp(now + TOMBSTONE_RETENTION)),
                )
            connection.execute(
                """
                DELETE FROM enrollments
                 WHERE agent_run_uid = ? AND execution_id = ? AND driver_registration = ?
                   AND desired_generation = ? AND guest_instance_id = ?
                """,
                _binding_values(binding),
            )
            connection.commit()
        except EnrollmentFailure:
            _rollback(connection)
            raise
        except sqlite3.Error as error:
            _rollback(connection)
            raise EnrollmentFailure("issuer-storage-failed", 503) from error
        finally:
            connection.close()

    def revoke_execution(self, request):
        scope = validate_revoke_execution_request(request)
        now = self._now()
        connection = self._connect_or_failure()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_store(connection)
            scope_values = _scope_values(scope)
            scope_present = connection.execute(
                """
                SELECT 1 FROM execution_tombstones
                 WHERE agent_run_uid = ? AND execution_id = ? AND driver_registration = ?
                """,
                scope_values,
            ).fetchone() is not None
            matching_records = connection.execute(
                """
                SELECT COUNT(*) FROM enrollments
                 WHERE agent_run_uid = ? AND execution_id = ? AND driver_registration = ?
                """,
                scope_values,
            ).fetchone()[0]
            matching_tombstones = connection.execute(
                """
                SELECT COUNT(*) FROM binding_tombstones
                 WHERE agent_run_uid = ? AND execution_id = ? AND driver_registration = ?
                """,
                scope_values,
            ).fetchone()[0]
            if not scope_present and self._entry_count(connection) + 1 - matching_records - matching_tombstones > self.max_entries:
                raise EnrollmentFailure("capacity-exceeded", 429)
            if not scope_present:
                connection.execute(
                    """
                    INSERT INTO execution_tombstones (
                        agent_run_uid, execution_id, driver_registration, created_at, delete_after
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (*scope_values, format_timestamp(now), format_timestamp(now + TOMBSTONE_RETENTION)),
                )
            connection.execute(
                """
                DELETE FROM binding_tombstones
                 WHERE agent_run_uid = ? AND execution_id = ? AND driver_registration = ?
                """,
                scope_values,
            )
            connection.execute(
                """
                DELETE FROM enrollments
                 WHERE agent_run_uid = ? AND execution_id = ? AND driver_registration = ?
                """,
                scope_values,
            )
            connection.commit()
        except EnrollmentFailure:
            _rollback(connection)
            raise
        except sqlite3.Error as error:
            _rollback(connection)
            raise EnrollmentFailure("issuer-storage-failed", 503) from error
        finally:
            connection.close()

    def complete_execution_cleanup(self, request):
        scope = validate_complete_execution_cleanup_request(request)
        now = self._now()
        connection = self._connect_or_failure()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_store(connection)
            values = _scope_values(scope)
            row = connection.execute(
                """
                SELECT created_at, cleanup_completed_at
                  FROM execution_tombstones
                 WHERE agent_run_uid = ? AND execution_id = ? AND driver_registration = ?
                """,
                values,
            ).fetchone()
            # Absence is an idempotent success after eligible maintenance has
            # already reclaimed a previously completed scope. The trusted
            # orchestrator contract still requires revoke-before-complete.
            if row is not None and row["cleanup_completed_at"] is None:
                created_at = parse_timestamp(row["created_at"])
                completed_at = format_timestamp(max(now, created_at))
                connection.execute(
                    """
                    UPDATE execution_tombstones
                       SET cleanup_completed_at = ?
                     WHERE agent_run_uid = ? AND execution_id = ? AND driver_registration = ?
                    """,
                    (completed_at, *values),
                )
            self._collect_completed(connection, now)
            connection.commit()
        except EnrollmentFailure:
            _rollback(connection)
            raise
        except sqlite3.Error as error:
            _rollback(connection)
            raise EnrollmentFailure("issuer-storage-failed", 503) from error
        finally:
            connection.close()

    def maintain(self):
        now = self._now()
        connection = self._connect_or_failure()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_store(connection)
            self._expire_issued(connection, now)
            connection.execute(
                """
                UPDATE enrollments
                   SET runtime_identity_active = 0,
                       terminal_at = runtime_identity_expires_at
                 WHERE runtime_identity_active = 1 AND runtime_identity_expires_at <= ?
                """,
                (format_timestamp(now),),
            )
            self._collect_completed(connection, now)
            connection.commit()
        except sqlite3.Error as error:
            _rollback(connection)
            raise EnrollmentFailure("issuer-storage-failed", 503) from error
        finally:
            connection.close()

    def garbage_collect_completed(self, scopes):
        """Test helper using the same durable completion and maintenance path."""
        if not isinstance(scopes, (list, tuple)) or len(scopes) > self.max_entries:
            raise EnrollmentFailure("invalid-request", 400)
        for scope in scopes:
            self.complete_execution_cleanup({"contract_version": VERSION, "execution_scope": scope})
        self.maintain()

    def snapshot(self):
        """Return non-secret durable state for tests and bounded diagnostics."""
        connection = self._connect_or_failure()
        try:
            records = [dict(row) for row in connection.execute("SELECT * FROM enrollments ORDER BY token_digest")]
            bindings = [dict(row) for row in connection.execute("SELECT * FROM binding_tombstones ORDER BY agent_run_uid, execution_id")]
            executions = [dict(row) for row in connection.execute("SELECT * FROM execution_tombstones ORDER BY agent_run_uid, execution_id")]
            return {"records": records, "binding_tombstones": bindings, "execution_tombstones": executions}
        except sqlite3.Error as error:
            raise EnrollmentFailure("issuer-storage-failed", 503) from error
        finally:
            connection.close()

    def _initialize(self):
        connection = None
        created = False
        try:
            if not Path(self.database_path).exists():
                descriptor = os.open(self.database_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                os.close(descriptor)
                created = True
            connection = self._connect()
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS enrollment_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS enrollments (
                    token_digest TEXT PRIMARY KEY,
                    agent_run_uid TEXT NOT NULL,
                    execution_id TEXT NOT NULL,
                    driver_registration TEXT NOT NULL,
                    desired_generation INTEGER NOT NULL,
                    guest_instance_id TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('issued','consumed','expired','revoked')),
                    terminal_at TEXT,
                    runtime_identity_digest TEXT UNIQUE,
                    runtime_identity_issued_at TEXT,
                    runtime_identity_expires_at TEXT,
                    runtime_identity_active INTEGER NOT NULL CHECK (runtime_identity_active IN (0,1)),
                    CHECK (
                        (state = 'consumed' AND runtime_identity_digest IS NOT NULL
                         AND runtime_identity_issued_at IS NOT NULL AND runtime_identity_expires_at IS NOT NULL)
                        OR
                        (state != 'consumed' AND runtime_identity_digest IS NULL
                         AND runtime_identity_issued_at IS NULL AND runtime_identity_expires_at IS NULL
                         AND runtime_identity_active = 0)
                    ),
                    UNIQUE (agent_run_uid, execution_id, driver_registration, desired_generation, guest_instance_id)
                );
                CREATE INDEX IF NOT EXISTS enrollments_scope
                    ON enrollments (agent_run_uid, execution_id, driver_registration);
                CREATE TABLE IF NOT EXISTS binding_tombstones (
                    agent_run_uid TEXT NOT NULL,
                    execution_id TEXT NOT NULL,
                    driver_registration TEXT NOT NULL,
                    desired_generation INTEGER NOT NULL,
                    guest_instance_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    delete_after TEXT NOT NULL,
                    PRIMARY KEY (agent_run_uid, execution_id, driver_registration, desired_generation, guest_instance_id)
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS execution_tombstones (
                    agent_run_uid TEXT NOT NULL,
                    execution_id TEXT NOT NULL,
                    driver_registration TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    delete_after TEXT NOT NULL,
                    cleanup_completed_at TEXT,
                    PRIMARY KEY (agent_run_uid, execution_id, driver_registration)
                ) WITHOUT ROWID;
                """
            )
            row = connection.execute("SELECT value FROM enrollment_meta WHERE key = 'schema_version'").fetchone()
            if row is None:
                connection.execute("INSERT INTO enrollment_meta (key, value) VALUES ('schema_version', ?)", (STORE_SCHEMA_VERSION,))
            elif row[0] in ("1", "2"):
                connection.execute("BEGIN IMMEDIATE")
                try:
                    if row[0] == "1":
                        self._migrate_schema_v1(connection)
                    self._migrate_schema_v2(connection)
                    connection.execute(
                        "UPDATE enrollment_meta SET value = ? WHERE key = 'schema_version'",
                        (STORE_SCHEMA_VERSION,),
                    )
                    connection.commit()
                except Exception:
                    _rollback(connection)
                    raise
            elif row[0] != STORE_SCHEMA_VERSION:
                raise EnrollmentConfigError("guest enrollment database schema is unsupported")
            connection.commit()
            self._validate_store(connection, full=True)
            os.chmod(self.database_path, 0o600)
        except EnrollmentConfigError:
            raise
        except (OSError, sqlite3.Error) as error:
            if created:
                try:
                    Path(self.database_path).unlink()
                except OSError:
                    pass
            raise EnrollmentConfigError("guest enrollment database initialization failed") from error
        finally:
            if connection is not None:
                connection.close()

    def _migrate_schema_v1(self, connection):
        for table, key_columns in (
            (
                "binding_tombstones",
                ("agent_run_uid", "execution_id", "driver_registration", "desired_generation", "guest_instance_id"),
            ),
            ("execution_tombstones", ("agent_run_uid", "execution_id", "driver_registration")),
        ):
            columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
            if "created_at" not in columns:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN created_at TEXT")
            selected_columns = ", ".join((*key_columns, "created_at", "delete_after"))
            for row in connection.execute(f"SELECT {selected_columns} FROM {table}").fetchall():
                try:
                    delete_after = parse_timestamp(row["delete_after"])
                    created_at = row["created_at"]
                    if created_at is None:
                        created_at = format_timestamp(delete_after - TOMBSTONE_RETENTION)
                    else:
                        created_at = format_timestamp(parse_timestamp(created_at))
                except (EnrollmentFailure, OverflowError) as error:
                    raise sqlite3.DatabaseError("guest enrollment database contains an invalid tombstone") from error
                predicate = " AND ".join(f"{column} = ?" for column in key_columns)
                connection.execute(
                    f"UPDATE {table} SET created_at = ? WHERE {predicate}",
                    (created_at, *(row[column] for column in key_columns)),
                )

    def _migrate_schema_v2(self, connection):
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(execution_tombstones)")}
        if "cleanup_completed_at" not in columns:
            connection.execute("ALTER TABLE execution_tombstones ADD COLUMN cleanup_completed_at TEXT")

    def _connect(self):
        connection = sqlite3.connect(self.database_path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA trusted_schema = OFF")
        return connection

    def _connect_or_failure(self):
        try:
            return self._connect()
        except sqlite3.Error as error:
            raise EnrollmentFailure("issuer-storage-failed", 503) from error

    def _validate_store(self, connection, full=False):
        if full:
            row = connection.execute("PRAGMA quick_check").fetchone()
            if row is None or row[0] != "ok":
                raise sqlite3.DatabaseError("guest enrollment database integrity check failed")
        version = connection.execute("SELECT value FROM enrollment_meta WHERE key = 'schema_version'").fetchone()
        if version is None or version[0] != STORE_SCHEMA_VERSION:
            raise sqlite3.DatabaseError("guest enrollment database schema is unsupported")
        if self._entry_count(connection) > self.max_entries:
            raise sqlite3.DatabaseError("guest enrollment database exceeds its durable entry bound")
        enrollment_rows = connection.execute(
            """
            SELECT token_digest, agent_run_uid, execution_id, driver_registration,
                   desired_generation, guest_instance_id, issued_at, expires_at,
                   state, terminal_at, runtime_identity_digest,
                   runtime_identity_issued_at, runtime_identity_expires_at,
                   runtime_identity_active
              FROM enrollments
            """
        ).fetchall()
        binding_tombstones = connection.execute(
            """
            SELECT agent_run_uid, execution_id, driver_registration,
                   desired_generation, guest_instance_id, created_at, delete_after
              FROM binding_tombstones
            """
        ).fetchall()
        execution_tombstones = connection.execute(
            """
            SELECT agent_run_uid, execution_id, driver_registration, created_at,
                   delete_after, cleanup_completed_at
              FROM execution_tombstones
            """
        ).fetchall()
        for row in enrollment_rows:
            _validate_persisted_enrollment(row)
        for row in binding_tombstones:
            _validate_persisted_binding_tombstone(row)
        for row in execution_tombstones:
            _validate_persisted_execution_tombstone(row)

    def _now(self):
        value = self.now()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise EnrollmentFailure("issuer-storage-failed", 503)
        return value.astimezone(timezone.utc).replace(microsecond=0)

    def _expire_issued(self, connection, now):
        now_value = format_timestamp(now)
        connection.execute(
            """
            UPDATE enrollments
               SET state = 'expired', terminal_at = expires_at
             WHERE state = 'issued' AND expires_at <= ?
            """,
            (now_value,),
        )

    def _entry_count(self, connection):
        return sum(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("enrollments", "binding_tombstones", "execution_tombstones")
        )

    def _collect_completed(self, connection, now):
        connection.execute(
            """
            DELETE FROM execution_tombstones
             WHERE cleanup_completed_at IS NOT NULL AND delete_after <= ?
            """,
            (format_timestamp(now),),
        )

    def _binding_record(self, connection, binding):
        return connection.execute(
            """
            SELECT 1 FROM enrollments
             WHERE agent_run_uid = ? AND execution_id = ? AND driver_registration = ?
               AND desired_generation = ? AND guest_instance_id = ?
            """,
            _binding_values(binding),
        ).fetchone()

    def _binding_record_count(self, connection, binding):
        return connection.execute(
            """
            SELECT COUNT(*) FROM enrollments
             WHERE agent_run_uid = ? AND execution_id = ? AND driver_registration = ?
               AND desired_generation = ? AND guest_instance_id = ?
            """,
            _binding_values(binding),
        ).fetchone()[0]

    def _binding_tombstoned(self, connection, binding):
        return connection.execute(
            """
            SELECT 1 FROM binding_tombstones
             WHERE agent_run_uid = ? AND execution_id = ? AND driver_registration = ?
               AND desired_generation = ? AND guest_instance_id = ?
            """,
            _binding_values(binding),
        ).fetchone() is not None

    def _scope_tombstoned(self, connection, binding):
        return connection.execute(
            """
            SELECT 1 FROM execution_tombstones
             WHERE agent_run_uid = ? AND execution_id = ? AND driver_registration = ?
            """,
            _scope_values(binding),
        ).fetchone() is not None

    def _maintenance_loop(self, interval):
        while not self.stop_event.wait(interval):
            try:
                self.maintain()
            except EnrollmentFailure:
                print("broker guest enrollment maintenance failed", file=sys.stderr)


def load_guest_enrollment_from_environment():
    enabled = os.environ.get("NVT_BROKER_GUEST_ENROLLMENT_ENABLED", "false")
    if enabled not in ("true", "false"):
        raise EnrollmentConfigError("NVT_BROKER_GUEST_ENROLLMENT_ENABLED must be true or false")
    if enabled == "false":
        return None, None
    required = {
        "database": os.environ.get("NVT_BROKER_GUEST_ENROLLMENT_DB"),
        "exchange URL": os.environ.get("NVT_BROKER_GUEST_ENROLLMENT_EXCHANGE_URL"),
        "orchestrator token file": os.environ.get("NVT_BROKER_GUEST_ENROLLMENT_ORCHESTRATOR_TOKEN_FILE"),
    }
    if any(not value for value in required.values()):
        raise EnrollmentConfigError("guest enrollment requires database, exchange URL, and orchestrator token file")
    issuer = GuestEnrollmentIssuer(required["database"], required["exchange URL"])
    try:
        authenticator = OrchestratorAuthenticator(required["orchestrator token file"])
    except Exception:
        issuer.close()
        raise
    return issuer, authenticator


def strict_decode(data, maximum):
    if not isinstance(data, bytes) or not data or len(data) > maximum:
        raise EnrollmentFailure("invalid-request", 400)
    try:
        text = data.decode("utf-8", "strict")
        value = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_json_constant)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise EnrollmentFailure("invalid-request", 400) from error
    if not isinstance(value, dict):
        raise EnrollmentFailure("invalid-request", 400)
    return value


def decode_issue_request(data):
    return strict_decode(data, MAX_ISSUE_REQUEST_BYTES)


def decode_exchange_request(data):
    return strict_decode(data, MAX_EXCHANGE_REQUEST_BYTES)


def decode_revoke_request(data):
    return strict_decode(data, MAX_REVOCATION_REQUEST_BYTES)


def decode_runtime_identity_status_request(data):
    return strict_decode(data, MAX_RUNTIME_IDENTITY_STATUS_REQUEST_BYTES)


def decode_runtime_identity_rotate_request(data):
    return strict_decode(data, MAX_RUNTIME_IDENTITY_ROTATE_REQUEST_BYTES)


def runtime_identity_from_authorization(authorization):
    if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
        raise EnrollmentFailure("unauthorized", 401)
    identity = authorization.removeprefix("Bearer ")
    _runtime_identity_digest(identity)
    return identity


def validate_issue_request(value):
    _exact_keys(value, {"contract_version", "binding", "ttl_seconds"})
    if value["contract_version"] != VERSION:
        _invalid()
    binding = validate_binding(value["binding"])
    ttl = value["ttl_seconds"]
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 1 or ttl > MAX_ENROLLMENT_TTL_SECONDS:
        _invalid()
    return binding, ttl


def validate_exchange_request(value):
    _exact_keys(value, {"contract_version", "binding", "token"})
    if value["contract_version"] != VERSION:
        _invalid()
    binding = validate_binding(value["binding"])
    token = value["token"]
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token) or not _canonical_opaque(token, TOKEN_BYTES, TOKEN_BYTES):
        _invalid()
    return binding, token


def validate_revoke_binding_request(value):
    _exact_keys(value, {"contract_version", "binding"})
    if value["contract_version"] != VERSION:
        _invalid()
    return validate_binding(value["binding"])


def validate_revoke_execution_request(value):
    _exact_keys(value, {"contract_version", "execution_scope"})
    if value["contract_version"] != VERSION:
        _invalid()
    return validate_scope(value["execution_scope"], exact=True)


def validate_complete_execution_cleanup_request(value):
    _exact_keys(value, {"contract_version", "execution_scope"})
    if value["contract_version"] != VERSION:
        _invalid()
    return validate_scope(value["execution_scope"], exact=True)


def validate_runtime_identity_status_request(value):
    _exact_keys(value, {"contract_version", "binding"})
    if value["contract_version"] != RUNTIME_IDENTITY_VERSION:
        _invalid()
    return validate_binding(value["binding"])


def validate_runtime_identity_rotate_request(value):
    _exact_keys(value, {"contract_version", "binding", "successor"})
    if value["contract_version"] != RUNTIME_IDENTITY_VERSION:
        _invalid()
    binding = validate_binding(value["binding"])
    successor = value["successor"]
    if not isinstance(successor, str) or not TOKEN_RE.fullmatch(successor) or not _canonical_opaque(successor, TOKEN_BYTES, TOKEN_BYTES):
        _invalid()
    return binding, successor


def validate_binding(value):
    _exact_keys(
        value,
        {"agent_run_uid", "execution_id", "driver_registration", "desired_generation", "guest_instance_id"},
    )
    scope = validate_scope(value)
    generation = value["desired_generation"]
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1 or generation > (1 << 63) - 1:
        _invalid()
    if not _valid_text(value["guest_instance_id"], MAX_GUEST_INSTANCE_ID_BYTES):
        _invalid()
    return {
        **scope,
        "desired_generation": generation,
        "guest_instance_id": value["guest_instance_id"],
    }


def validate_scope(value, exact=False):
    required = {"agent_run_uid", "execution_id", "driver_registration"}
    if not isinstance(value, dict) or not required.issubset(value) or (exact and set(value) != required):
        _invalid()
    if not _valid_text(value["agent_run_uid"], MAX_AGENT_RUN_UID_BYTES):
        _invalid()
    if not _valid_text(value["execution_id"], MAX_EXECUTION_ID_BYTES):
        _invalid()
    driver = value["driver_registration"]
    if not isinstance(driver, str) or len(driver.encode("utf-8")) > MAX_DRIVER_NAME_BYTES or not DRIVER_NAME_RE.fullmatch(driver):
        _invalid()
    return {
        "agent_run_uid": value["agent_run_uid"],
        "execution_id": value["execution_id"],
        "driver_registration": driver,
    }


def validate_exchange_url(value):
    if not _valid_text(value, MAX_EXCHANGE_URL_BYTES) or not value.isascii() or not value.startswith("https://"):
        raise EnrollmentConfigError("guest enrollment exchange URL is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise EnrollmentConfigError("guest enrollment exchange URL is invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
        or parsed.path != EXCHANGE_PATH
        or "\\" in parsed.path
        or "//" in parsed.path
        or "%" in parsed.path
        or "/./" in parsed.path
        or "/../" in parsed.path
        or parsed.path.endswith("/.")
        or parsed.path.endswith("/..")
        or (port is not None and (port < 1 or port > 65535))
    ):
        raise EnrollmentConfigError("guest enrollment exchange URL is invalid")
    return value


def format_timestamp(value):
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(value):
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        raise EnrollmentFailure("issuer-storage-failed", 503)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise EnrollmentFailure("issuer-storage-failed", 503) from error
    if format_timestamp(parsed) != value:
        raise EnrollmentFailure("issuer-storage-failed", 503)
    return parsed


def _validate_persisted_enrollment(row):
    try:
        if not isinstance(row["token_digest"], str) or not DIGEST_RE.fullmatch(row["token_digest"]):
            raise ValueError
        validate_binding(_row_binding(row))
        issued_at = parse_timestamp(row["issued_at"])
        expires_at = parse_timestamp(row["expires_at"])
        if not issued_at < expires_at or expires_at - issued_at > timedelta(seconds=MAX_ENROLLMENT_TTL_SECONDS):
            raise ValueError

        state = row["state"]
        terminal_at = row["terminal_at"]
        identity_digest = row["runtime_identity_digest"]
        identity_issued_value = row["runtime_identity_issued_at"]
        identity_expires_value = row["runtime_identity_expires_at"]
        identity_active = row["runtime_identity_active"]
        if identity_active not in (0, 1):
            raise ValueError

        if state == "consumed":
            if not isinstance(identity_digest, str) or not DIGEST_RE.fullmatch(identity_digest):
                raise ValueError
            identity_issued_at = parse_timestamp(identity_issued_value)
            identity_expires_at = parse_timestamp(identity_expires_value)
            # The first identity is issued during enrollment, but later
            # authenticated rotations legitimately occur after the one-time
            # enrollment token has expired. The broker-owned identity window
            # remains independently bounded below.
            if identity_issued_at < issued_at:
                raise ValueError
            if not identity_issued_at < identity_expires_at or identity_expires_at - identity_issued_at > MAX_RUNTIME_IDENTITY_LIFETIME:
                raise ValueError
            if identity_active == 1:
                if terminal_at is not None:
                    raise ValueError
            elif terminal_at != identity_expires_value:
                raise ValueError
            return

        if any(value is not None for value in (identity_digest, identity_issued_value, identity_expires_value)) or identity_active != 0:
            raise ValueError
        if state == "issued":
            if terminal_at is not None:
                raise ValueError
        elif state == "expired":
            if terminal_at != row["expires_at"]:
                raise ValueError
        elif state == "revoked":
            revoked_at = parse_timestamp(terminal_at)
            if revoked_at < issued_at:
                raise ValueError
        else:
            raise ValueError
    except (EnrollmentFailure, KeyError, TypeError, ValueError) as error:
        raise sqlite3.DatabaseError("guest enrollment database contains an invalid enrollment record") from error


def _validate_persisted_binding_tombstone(row):
    try:
        validate_binding(_row_binding(row))
        created_at = parse_timestamp(row["created_at"])
        delete_after = parse_timestamp(row["delete_after"])
        if not created_at <= delete_after or delete_after - created_at > TOMBSTONE_RETENTION:
            raise ValueError
    except (EnrollmentFailure, KeyError, TypeError, ValueError) as error:
        raise sqlite3.DatabaseError("guest enrollment database contains an invalid binding tombstone") from error


def _validate_persisted_execution_tombstone(row):
    try:
        validate_scope(
            {
                "agent_run_uid": row["agent_run_uid"],
                "execution_id": row["execution_id"],
                "driver_registration": row["driver_registration"],
            },
            exact=True,
        )
        created_at = parse_timestamp(row["created_at"])
        delete_after = parse_timestamp(row["delete_after"])
        if not created_at <= delete_after or delete_after - created_at > TOMBSTONE_RETENTION:
            raise ValueError
        cleanup_completed = row["cleanup_completed_at"]
        if cleanup_completed is not None and parse_timestamp(cleanup_completed) < created_at:
            raise ValueError
    except (EnrollmentFailure, KeyError, TypeError, ValueError) as error:
        raise sqlite3.DatabaseError("guest enrollment database contains an invalid execution tombstone") from error


def _validate_database_path(value):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise EnrollmentConfigError("guest enrollment database path is invalid")
    path = Path(value)
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise EnrollmentConfigError("guest enrollment database path is invalid")
    try:
        parent = path.parent
        parent_stat = parent.stat()
        if not stat.S_ISDIR(parent_stat.st_mode) or not os.access(parent, os.W_OK | os.X_OK):
            raise EnrollmentConfigError("guest enrollment database parent is not writable")
        if path.exists() or path.is_symlink():
            path_stat = path.lstat()
            if not stat.S_ISREG(path_stat.st_mode) or path.is_symlink():
                raise EnrollmentConfigError("guest enrollment database must be a regular file")
    except OSError as error:
        raise EnrollmentConfigError("guest enrollment database path is unavailable") from error
    return str(path)


def _unique_object(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output


def _reject_json_constant(_value):
    raise ValueError("invalid JSON number")


def _exact_keys(value, expected):
    if not isinstance(value, dict) or set(value) != expected:
        _invalid()


def _valid_text(value, maximum):
    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        return False
    return len(encoded) <= maximum and all(ord(character) >= 0x20 and ord(character) != 0x7F for character in value)


def _canonical_opaque(value, minimum, maximum):
    if not isinstance(value, str) or not value or "=" in value:
        return False
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, TypeError):
        return False
    return minimum <= len(decoded) <= maximum and base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == value


def _opaque_random(source, size):
    value = source(size)
    if not isinstance(value, bytes) or len(value) != size:
        raise EnrollmentFailure("identity-issuance-failed", 503)
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _runtime_identity_digest(value):
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value) or not _canonical_opaque(value, TOKEN_BYTES, TOKEN_BYTES):
        raise EnrollmentFailure("unauthorized", 401)
    return _digest(value)


def _runtime_identity_status(binding, issued_at, expires_at):
    return {
        "contract_version": RUNTIME_IDENTITY_VERSION,
        "identity_type": RUNTIME_IDENTITY_TYPE,
        "binding": binding,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }


def _digest(value):
    return "sha256:" + hashlib.sha256(value.encode("ascii")).hexdigest()


def _binding_values(binding):
    return (
        binding["agent_run_uid"],
        binding["execution_id"],
        binding["driver_registration"],
        binding["desired_generation"],
        binding["guest_instance_id"],
    )


def _scope_values(value):
    return value["agent_run_uid"], value["execution_id"], value["driver_registration"]


def _row_binding(row):
    return {
        "agent_run_uid": row["agent_run_uid"],
        "execution_id": row["execution_id"],
        "driver_registration": row["driver_registration"],
        "desired_generation": row["desired_generation"],
        "guest_instance_id": row["guest_instance_id"],
    }


def _rollback(connection):
    try:
        if connection.in_transaction:
            connection.rollback()
    except sqlite3.Error:
        pass


def _invalid():
    raise EnrollmentFailure("invalid-request", 400)
