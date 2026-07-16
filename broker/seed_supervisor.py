#!/usr/bin/env python3
"""Reconcile a read-only credential seed into broker-owned persistent state."""

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time


MAX_SEED_BYTES = 1024 * 1024
MAX_CANONICAL_RECOVERY_BYTES = 16 * 1024 * 1024
MARKER_VERSION = 1
PROJECTED_VERSION_RE = re.compile(r"^\.\.[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9_]+(?:\.[0-9]+)?$")


class SeedError(Exception):
    """A sanitized seed-boundary failure."""


def _safe_name(name):
    return (
        isinstance(name, str)
        and 0 < len(name.encode("utf-8")) <= 255
        and name not in (".", "..")
        and "/" not in name
        and "\\" not in name
        and not any(ord(char) < 32 or ord(char) == 127 for char in name)
    )


def _safe_relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise SeedError("seed-target-invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or str(path) != value
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise SeedError("seed-target-invalid")
    if path.parts[0] in (".nvt-seed-imports", ".nvt-seed-recovery"):
        raise SeedError("seed-target-invalid")
    return path.parts


def _is_within(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path, content, mode=0o600):
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.seed.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _read_regular(path, limit, error_code):
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode):
            raise SeedError(error_code)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > limit:
                raise SeedError(error_code)
            chunks = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(65536, limit + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    raise SeedError(error_code)
            content = b"".join(chunks)
            after = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise SeedError(error_code)
            if len(content) != after.st_size:
                raise SeedError(error_code)
            return content
        finally:
            os.close(descriptor)
    except SeedError:
        raise
    except OSError as error:
        raise SeedError(error_code) from error


def _chmod_regular(path, mode, error_code):
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise SeedError(error_code)
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(path.parent)
    except SeedError:
        raise
    except OSError as error:
        raise SeedError(error_code) from error


class SeedReconciler:
    def __init__(self, seed_dir, state_dir, target_dir):
        self.seed_dir = Path(seed_dir)
        self.state_dir = Path(state_dir)
        self.target_parts = _safe_relative(target_dir)
        self.target_dir = self._safe_directory(self.state_dir, self.target_parts, create=True)
        self.marker_dir = self._safe_directory(
            self.state_dir, (".nvt-seed-imports", *self.target_parts), create=True
        )
        self.recovery_dir = self._safe_directory(
            self.state_dir, (".nvt-seed-recovery", *self.target_parts), create=True
        )

    @staticmethod
    def _safe_directory(root, parts, create):
        try:
            root_status = os.lstat(root)
        except OSError as error:
            raise SeedError("seed-state-invalid") from error
        if not stat.S_ISDIR(root_status.st_mode) or stat.S_ISLNK(root_status.st_mode):
            raise SeedError("seed-state-invalid")
        current = root
        for part in parts:
            current = current / part
            try:
                current_status = os.lstat(current)
            except FileNotFoundError:
                if not create:
                    raise SeedError("seed-state-invalid")
                try:
                    current.mkdir(mode=0o700)
                    _fsync_directory(current.parent)
                    current_status = os.lstat(current)
                except OSError as error:
                    raise SeedError("seed-state-invalid") from error
            except OSError as error:
                raise SeedError("seed-state-invalid") from error
            if not stat.S_ISDIR(current_status.st_mode) or stat.S_ISLNK(current_status.st_mode):
                raise SeedError("seed-state-invalid")
        return current

    def _source_files(self):
        try:
            seed_status = os.lstat(self.seed_dir)
            if not stat.S_ISDIR(seed_status.st_mode) or stat.S_ISLNK(seed_status.st_mode):
                raise SeedError("seed-directory-invalid")
            root = self.seed_dir.resolve(strict=True)
            entries = list(os.scandir(self.seed_dir))
        except SeedError:
            raise
        except OSError as error:
            raise SeedError("seed-directory-invalid") from error

        files = {}
        for entry in entries:
            if entry.name.startswith(".."):
                # Kubernetes projected volumes manage ..data, a brief
                # ..data_tmp link, and timestamped directories. Validate those
                # structures rather than treating arbitrary hidden entries as
                # ignorable source keys.
                internal = self.seed_dir / entry.name
                try:
                    internal_status = os.lstat(internal)
                    if entry.name in ("..data", "..data_tmp"):
                        if not stat.S_ISLNK(internal_status.st_mode):
                            raise SeedError("seed-directory-invalid")
                        resolved = internal.resolve(strict=True)
                        if not _is_within(resolved, root) or not resolved.is_dir():
                            raise SeedError("seed-directory-invalid")
                    elif PROJECTED_VERSION_RE.fullmatch(entry.name):
                        if not stat.S_ISDIR(internal_status.st_mode) or stat.S_ISLNK(internal_status.st_mode):
                            raise SeedError("seed-directory-invalid")
                    else:
                        raise SeedError("seed-file-invalid")
                except SeedError:
                    raise
                except OSError as error:
                    raise SeedError("seed-directory-invalid") from error
                continue
            if not _safe_name(entry.name):
                raise SeedError("seed-file-invalid")
            path = self.seed_dir / entry.name
            try:
                status = os.lstat(path)
                if stat.S_ISLNK(status.st_mode):
                    # A projected Secret key is exactly key -> ..data/key.
                    if os.readlink(path) != f"..data/{entry.name}":
                        raise SeedError("seed-symlink-invalid")
                    readable = path.resolve(strict=True)
                    if not _is_within(readable, root):
                        raise SeedError("seed-symlink-invalid")
                elif stat.S_ISREG(status.st_mode):
                    readable = path
                else:
                    raise SeedError("seed-file-invalid")
                content = _read_regular(readable, MAX_SEED_BYTES, "seed-file-invalid")
            except SeedError:
                raise
            except OSError as error:
                raise SeedError("seed-file-invalid") from error
            files[entry.name] = {
                "content": content,
                "digest": hashlib.sha256(content).hexdigest(),
            }
        return files

    def _regular_or_missing(self, path, limit, error_code):
        try:
            status = os.lstat(path)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise SeedError(error_code) from error
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise SeedError(error_code)
        return _read_regular(path, limit, error_code)

    def _marker_digest(self, path):
        raw = self._regular_or_missing(path, 4096, "seed-marker-invalid")
        if raw is None:
            return None
        try:
            marker = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SeedError("seed-marker-invalid") from error
        if (
            not isinstance(marker, dict)
            or set(marker) != {"version", "sourceDigest"}
            or marker.get("version") != MARKER_VERSION
            or not isinstance(marker.get("sourceDigest"), str)
            or len(marker["sourceDigest"]) != 64
            or any(char not in "0123456789abcdef" for char in marker["sourceDigest"])
        ):
            raise SeedError("seed-marker-invalid")
        return marker["sourceDigest"]

    def plan(self):
        sources = self._source_files()
        actions = []
        for name, source in sorted(sources.items()):
            canonical = self.target_dir / name
            marker = self.marker_dir / name
            canonical_content = self._regular_or_missing(
                canonical, MAX_CANONICAL_RECOVERY_BYTES, "seed-canonical-invalid"
            )
            imported_digest = self._marker_digest(marker)
            if imported_digest is None and canonical_content is not None:
                action = "adopt"
            elif imported_digest != source["digest"] or canonical_content is None:
                action = "import"
            else:
                continue
            actions.append(
                {
                    "name": name,
                    "action": action,
                    "content": source["content"],
                    "digest": source["digest"],
                    "canonical": canonical,
                    "marker": marker,
                }
            )
        fingerprint = tuple((name, source["digest"]) for name, source in sorted(sources.items()))
        return actions, fingerprint

    @staticmethod
    def _marker_content(digest):
        return json.dumps(
            {"version": MARKER_VERSION, "sourceDigest": digest}, separators=(",", ":")
        ).encode("utf-8")

    def _recovery_path(self, name):
        return self.recovery_dir / name

    def _write_recovery(self, action):
        canonical = None
        if action["action"] == "import":
            canonical = self._regular_or_missing(
                action["canonical"], MAX_CANONICAL_RECOVERY_BYTES, "seed-canonical-invalid"
            )
        marker = self._regular_or_missing(action["marker"], 4096, "seed-marker-invalid")
        record = {
            "version": MARKER_VERSION,
            "restoreCanonical": action["action"] == "import",
            "canonicalExists": canonical is not None,
            "canonical": base64.b64encode(canonical or b"").decode("ascii"),
            "markerExists": marker is not None,
            "marker": base64.b64encode(marker or b"").decode("ascii"),
        }
        _atomic_write(
            self._recovery_path(action["name"]),
            json.dumps(record, separators=(",", ":")).encode("utf-8"),
        )

    def apply(self, actions):
        if not actions:
            return []
        try:
            for action in actions:
                self._write_recovery(action)
            for action in actions:
                if action["action"] == "import":
                    _atomic_write(action["canonical"], action["content"])
                else:
                    _chmod_regular(action["canonical"], 0o600, "seed-canonical-invalid")
                _atomic_write(action["marker"], self._marker_content(action["digest"]))
        except (OSError, SeedError) as error:
            self.recover_incomplete()
            if isinstance(error, SeedError):
                raise
            raise SeedError("seed-import-failed") from error
        return [self._recovery_path(action["name"]) for action in actions]

    def accept(self, recovery_paths):
        try:
            for path in recovery_paths:
                path.unlink(missing_ok=True)
            if recovery_paths:
                _fsync_directory(self.recovery_dir)
        except OSError as error:
            raise SeedError("seed-recovery-cleanup-failed") from error

    def recover_incomplete(self):
        try:
            entries = list(os.scandir(self.recovery_dir))
        except OSError as error:
            raise SeedError("seed-recovery-invalid") from error
        for entry in entries:
            if not _safe_name(entry.name):
                raise SeedError("seed-recovery-invalid")
            recovery_path = self.recovery_dir / entry.name
            raw = self._regular_or_missing(
                recovery_path, 24 * 1024 * 1024, "seed-recovery-invalid"
            )
            try:
                record = json.loads(raw.decode("utf-8"))
                expected = {
                    "version",
                    "restoreCanonical",
                    "canonicalExists",
                    "canonical",
                    "markerExists",
                    "marker",
                }
                if (
                    not isinstance(record, dict)
                    or set(record) != expected
                    or record["version"] != MARKER_VERSION
                    or not isinstance(record["restoreCanonical"], bool)
                    or not isinstance(record["canonicalExists"], bool)
                    or not isinstance(record["markerExists"], bool)
                    or not isinstance(record["canonical"], str)
                    or not isinstance(record["marker"], str)
                ):
                    raise ValueError
                canonical = base64.b64decode(record["canonical"], validate=True)
                marker = base64.b64decode(record["marker"], validate=True)
                if (
                    len(canonical) > MAX_CANONICAL_RECOVERY_BYTES
                    or len(marker) > 4096
                    or (not record["canonicalExists"] and canonical)
                    or (not record["markerExists"] and marker)
                ):
                    raise ValueError
            except (AttributeError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                raise SeedError("seed-recovery-invalid") from error

            try:
                canonical_path = self.target_dir / entry.name
                marker_path = self.marker_dir / entry.name
                if record["restoreCanonical"]:
                    if record["canonicalExists"]:
                        _atomic_write(canonical_path, canonical)
                    else:
                        canonical_path.unlink(missing_ok=True)
                if record["markerExists"]:
                    _atomic_write(marker_path, marker)
                else:
                    marker_path.unlink(missing_ok=True)
                recovery_path.unlink()
            except OSError as error:
                raise SeedError("seed-recovery-failed") from error
        try:
            if entries:
                _fsync_directory(self.recovery_dir)
        except OSError as error:
            raise SeedError("seed-recovery-failed") from error


class BrokerSupervisor:
    def __init__(self, reconciler, command, poll_seconds=1.0, ready_seconds=15.0):
        self.reconciler = reconciler
        self.command = command
        self.poll_seconds = poll_seconds
        self.ready_seconds = ready_seconds
        self.child = None
        self.stopping = False
        self.blocked_fingerprint = None
        self.last_notice = None

    def _notice(self, message):
        if message != self.last_notice:
            print(f"broker-seed-supervisor: {message}", file=sys.stderr, flush=True)
            self.last_notice = message

    def _start(self):
        self.child = subprocess.Popen(self.command)

    def _stop(self):
        child = self.child
        self.child = None
        if child is None or child.poll() is not None:
            return
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)

    @staticmethod
    def _ready_address():
        bind = os.environ.get("NVT_BROKER_BIND", "127.0.0.1:7347")
        try:
            host, port_text = bind.rsplit(":", 1)
            port = int(port_text)
        except (ValueError, TypeError) as error:
            raise SeedError("broker-bind-invalid") from error
        host = host.strip("[]")
        if host in ("", "0.0.0.0", "::"):
            host = "127.0.0.1"
        return host, port

    def _wait_ready(self):
        host, port = self._ready_address()
        deadline = time.monotonic() + self.ready_seconds
        while not self.stopping and time.monotonic() < deadline:
            if self.child.poll() is not None:
                return False
            connection = None
            try:
                if os.environ.get("NVT_BROKER_TLS_CERT"):
                    connection = http.client.HTTPSConnection(
                        host,
                        port,
                        timeout=0.2,
                        context=ssl._create_unverified_context(),
                    )
                else:
                    connection = http.client.HTTPConnection(host, port, timeout=0.2)
                connection.request("GET", "/health")
                response = connection.getresponse()
                response.read(4096)
                if response.status == 200:
                    return True
            except (OSError, http.client.HTTPException, ssl.SSLError):
                time.sleep(0.05)
            finally:
                if connection is not None:
                    connection.close()
        return False

    def request_stop(self, _signum, _frame):
        self.stopping = True

    def run(self):
        signal.signal(signal.SIGTERM, self.request_stop)
        signal.signal(signal.SIGINT, self.request_stop)
        try:
            self.reconciler.recover_incomplete()
        except SeedError:
            self._notice("recovery state is invalid; broker held unready")
            return 1

        while not self.stopping:
            if self.child is not None and self.child.poll() is not None:
                return self.child.returncode or 1
            try:
                actions, fingerprint = self.reconciler.plan()
            except SeedError:
                self._stop()
                self._notice("seed input is invalid; broker held unready")
                time.sleep(self.poll_seconds)
                continue

            if self.blocked_fingerprint == fingerprint:
                time.sleep(self.poll_seconds)
                continue
            if actions:
                self._stop()
                self._notice("seed generation changed; broker restarting")
                try:
                    recovery_paths = self.reconciler.apply(actions)
                except SeedError:
                    self._notice("seed import failed; broker held unready")
                    time.sleep(self.poll_seconds)
                    continue
                if self.stopping:
                    self.reconciler.recover_incomplete()
                    break
                self._start()
                if not self._wait_ready():
                    self._stop()
                    self.reconciler.recover_incomplete()
                    self.blocked_fingerprint = fingerprint
                    self._notice("replacement was not accepted; broker held unready")
                    continue
                self.reconciler.accept(recovery_paths)
                self.blocked_fingerprint = None
                self._notice("broker ready after seed reconciliation")
            elif self.child is None:
                self._start()
                if not self._wait_ready():
                    self._stop()
                    return 1
                self._notice("broker ready")
            time.sleep(self.poll_seconds)

        self._stop()
        return 0


def _positive_float(name, default, minimum, maximum):
    try:
        value = float(os.environ.get(name, default))
    except ValueError as error:
        raise SeedError("supervisor-timing-invalid") from error
    if value < minimum or value > maximum:
        raise SeedError("supervisor-timing-invalid")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        command = [str(Path(__file__).with_name("brokerd.py"))]
    try:
        reconciler = SeedReconciler(
            os.environ.get("NVT_BROKER_SEED_DIR", "/seed"),
            os.environ.get("NVT_BROKER_STATE_DIR", "/state"),
            os.environ.get("NVT_BROKER_SEED_TARGET_DIR", "credentials"),
        )
        supervisor = BrokerSupervisor(
            reconciler,
            command,
            _positive_float("NVT_BROKER_SEED_POLL_SECONDS", "1", 0.01, 60),
            _positive_float("NVT_BROKER_SEED_READY_SECONDS", "15", 0.1, 120),
        )
        return supervisor.run()
    except SeedError as error:
        print(f"broker-seed-supervisor: startup failed ({error})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
