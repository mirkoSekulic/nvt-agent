package broker_test

import (
	"strings"
	"testing"
)

func TestBrokerSeedReconciliationContract(t *testing.T) {
	out, err := runBrokerPython(t, `
import os
import stat
import tempfile
from pathlib import Path

from broker.seed_supervisor import SeedReconciler

def reconcile(reconciler):
    actions, _ = reconciler.plan()
    recovery = reconciler.apply(actions)
    reconciler.accept(recovery)
    return actions

with tempfile.TemporaryDirectory() as seed_name, tempfile.TemporaryDirectory() as state_name:
    seed = Path(seed_name)
    state = Path(state_name)
    (seed / "first.json").write_bytes(b"source-A")
    reconciler = SeedReconciler(seed, state, "credentials")

    actions = reconcile(reconciler)
    canonical = state / "credentials" / "first.json"
    assert [item["action"] for item in actions] == ["import"]
    assert canonical.read_bytes() == b"source-A"
    assert stat.S_IMODE(canonical.stat().st_mode) == 0o600

    canonical.write_bytes(b"broker-B")
    os.chmod(canonical, 0o600)
    assert reconcile(reconciler) == []
    assert canonical.read_bytes() == b"broker-B"

    (seed / "first.json").write_bytes(b"source-C")
    reconcile(reconciler)
    assert canonical.read_bytes() == b"source-C"
    canonical.write_bytes(b"broker-D")
    assert reconcile(reconciler) == []
    assert canonical.read_bytes() == b"broker-D"

    (seed / "second.json").write_bytes(b"second-A")
    reconcile(reconciler)
    second = state / "credentials" / "second.json"
    assert second.read_bytes() == b"second-A"
    (seed / "second.json").write_bytes(b"second-C")
    reconcile(reconciler)
    assert canonical.read_bytes() == b"broker-D"
    assert second.read_bytes() == b"second-C"

    (seed / "second.json").unlink()
    assert reconcile(reconciler) == []
    assert second.read_bytes() == b"second-C"

with tempfile.TemporaryDirectory() as seed_name, tempfile.TemporaryDirectory() as state_name:
    seed = Path(seed_name)
    state = Path(state_name)
    target = state / "credentials"
    target.mkdir()
    canonical = target / "existing.json"
    canonical.write_bytes(b"already-rotated")
    os.chmod(canonical, 0o640)
    (seed / "existing.json").write_bytes(b"stale-seed")
    reconciler = SeedReconciler(seed, state, "credentials")
    actions = reconcile(reconciler)
    assert [item["action"] for item in actions] == ["adopt"]
    assert canonical.read_bytes() == b"already-rotated"
    assert stat.S_IMODE(canonical.stat().st_mode) == 0o600
    assert reconcile(reconciler) == []

with tempfile.TemporaryDirectory() as seed_name, tempfile.TemporaryDirectory() as state_name:
    seed = Path(seed_name)
    state = Path(state_name)
    (seed / "recover.json").write_bytes(b"recovery-source-A")
    reconciler = SeedReconciler(seed, state, "credentials")
    reconcile(reconciler)
    canonical = state / "credentials" / "recover.json"
    canonical.write_bytes(b"recovery-broker-B")
    (seed / "recover.json").write_bytes(b"recovery-source-C")
    actions, _ = reconciler.plan()
    recovery_paths = reconciler.apply(actions)
    assert canonical.read_bytes() == b"recovery-source-C"
    assert len(recovery_paths) == 1 and recovery_paths[0].exists()
    assert stat.S_IMODE(recovery_paths[0].stat().st_mode) == 0o600

    restarted = SeedReconciler(seed, state, "credentials")
    restarted.recover_incomplete()
    assert canonical.read_bytes() == b"recovery-broker-B"
    actions, _ = restarted.plan()
    recovery_paths = restarted.apply(actions)
    restarted.accept(recovery_paths)
    assert canonical.read_bytes() == b"recovery-source-C"
    assert list((state / ".nvt-seed-recovery" / "credentials").iterdir()) == []

print("OK")
`)
	if err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("seed reconciliation contract failed: %v\n%s", err, out)
	}
}

func TestBrokerSeedValidationAndProjectedSecretUpdates(t *testing.T) {
	out, err := runBrokerPython(t, `
import os
import tempfile
from pathlib import Path

from broker.seed_supervisor import MAX_SEED_BYTES, SeedError, SeedReconciler

def rejected(callback):
    try:
        callback()
    except SeedError:
        return
    raise AssertionError("unsafe seed input was accepted")

with tempfile.TemporaryDirectory() as seed_name, tempfile.TemporaryDirectory() as state_name:
    seed = Path(seed_name)
    state = Path(state_name)
    rejected(lambda: SeedReconciler(seed, state, "../escape"))
    rejected(lambda: SeedReconciler(seed, state, "/absolute"))
    rejected(lambda: SeedReconciler(seed, state, "credentials//nested"))

    (seed / "oversized").write_bytes(b"x" * (MAX_SEED_BYTES + 1))
    rejected(lambda: SeedReconciler(seed, state, "credentials").plan())
    (seed / "oversized").unlink()

    outside = state / "outside"
    outside.write_bytes(b"outside-canary")
    (seed / "linked").symlink_to(outside)
    rejected(lambda: SeedReconciler(seed, state, "credentials").plan())
    (seed / "linked").unlink()

    (seed / "directory").mkdir()
    rejected(lambda: SeedReconciler(seed, state, "credentials").plan())
    (seed / "directory").rmdir()

    version_a = seed / "..2026_07_16_00_00_00.000000001"
    version_a.mkdir()
    (version_a / "auth.json").write_bytes(b"projected-A")
    (seed / "..data").symlink_to(version_a.name)
    (seed / "auth.json").symlink_to("..data/auth.json")
    reconciler = SeedReconciler(seed, state, "credentials")
    actions, _ = reconciler.plan()
    recovery = reconciler.apply(actions)
    reconciler.accept(recovery)
    assert (state / "credentials" / "auth.json").read_bytes() == b"projected-A"

    version_c = seed / "..2026_07_16_00_00_01.000000002"
    version_c.mkdir()
    (version_c / "auth.json").write_bytes(b"projected-C")
    temporary_link = seed / "..data-next"
    temporary_link.symlink_to(version_c.name)
    os.replace(temporary_link, seed / "..data")
    actions, _ = reconciler.plan()
    recovery = reconciler.apply(actions)
    reconciler.accept(recovery)
    assert (state / "credentials" / "auth.json").read_bytes() == b"projected-C"

    canonical = state / "credentials" / "auth.json"
    canonical.unlink()
    canonical.symlink_to(outside)
    rejected(reconciler.plan)

print("OK")
`)
	if err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("seed validation test failed: %v\n%s", err, out)
	}
}

func TestBrokerSeedSupervisorRestartsAndRecoversWithoutSecretDisclosure(t *testing.T) {
	out, err := runBrokerPython(t, `
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

def wait_for(predicate, message, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError(message)

def listening(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.05):
            return True
    except OSError:
        return False

with tempfile.TemporaryDirectory() as root_name:
    root = Path(root_name)
    seed = root / "seed"
    state = root / "state"
    seed.mkdir()
    state.mkdir()
    starts = root / "starts"
    fake = root / "fake-broker.py"
    fake.write_text(r'''
import os, pathlib, signal, socket, sys, time
starts = os.environ["FAKE_BROKER_STARTS"]
try:
    count = len(open(starts, "r", encoding="utf-8").readlines()) + 1
except FileNotFoundError:
    count = 1
with open(starts, "a", encoding="utf-8") as handle:
    handle.write("start\n")
if pathlib.Path(os.environ["FAKE_BROKER_CREDENTIAL"]).read_text(encoding="utf-8") == "broker-reject-canary":
    raise SystemExit(3)
if count > 1:
    time.sleep(0.3)
host, port = os.environ["NVT_BROKER_BIND"].rsplit(":", 1)
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host, int(port)))
server.listen()
server.settimeout(0.05)
running = True
def stop(*_args):
    global running
    running = False
signal.signal(signal.SIGTERM, stop)
while running:
    try:
        connection, _ = server.accept()
    except socket.timeout:
        continue
    try:
        connection.recv(4096)
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
    finally:
        connection.close()
server.close()
''', encoding="utf-8")

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    version_a = seed / "..2026_07_16_00_00_00.000000001"
    version_a.mkdir()
    source_a = "seed-source-canary-A"
    source_c = "seed-source-canary-C"
    source_e = "seed-source-canary-E"
    (version_a / "auth.json").write_text(source_a, encoding="utf-8")
    (seed / "..data").symlink_to(version_a.name)
    (seed / "auth.json").symlink_to("..data/auth.json")

    env = os.environ.copy()
    env.update({
        "NVT_BROKER_SEED_DIR": str(seed),
        "NVT_BROKER_STATE_DIR": str(state),
        "NVT_BROKER_SEED_TARGET_DIR": "credentials",
        "NVT_BROKER_SEED_POLL_SECONDS": "0.03",
        "NVT_BROKER_SEED_READY_SECONDS": "2",
        "NVT_BROKER_BIND": f"127.0.0.1:{port}",
        "FAKE_BROKER_STARTS": str(starts),
        "FAKE_BROKER_CREDENTIAL": str(state / "credentials" / "auth.json"),
    })
    process = subprocess.Popen(
        [sys.executable, "broker/seed_supervisor.py", "--", sys.executable, str(fake)],
        cwd=os.environ["PYTHONPATH"].split(os.pathsep)[0],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        canonical = state / "credentials" / "auth.json"
        wait_for(lambda: canonical.exists() and canonical.read_text() == source_a and listening(port), "initial import did not become ready")
        assert len(starts.read_text().splitlines()) == 1

        canonical.write_text("broker-rotated-canary-B", encoding="utf-8")
        time.sleep(0.15)
        assert canonical.read_text() == "broker-rotated-canary-B"
        assert len(starts.read_text().splitlines()) == 1

        version_c = seed / "..2026_07_16_00_00_01.000000002"
        version_c.mkdir()
        (version_c / "auth.json").write_text(source_c, encoding="utf-8")
        next_link = seed / "..data-next"
        next_link.symlink_to(version_c.name)
        os.replace(next_link, seed / "..data")
        wait_for(lambda: starts.exists() and len(starts.read_text().splitlines()) >= 2, "broker did not restart")
        assert not listening(port), "broker remained ready while canonical state was changing"
        wait_for(lambda: canonical.read_text() == source_c and listening(port), "changed seed was not accepted")

        canonical.write_text("broker-rotated-canary-D", encoding="utf-8")
        time.sleep(0.15)
        assert canonical.read_text() == "broker-rotated-canary-D"
        assert len(starts.read_text().splitlines()) == 2

        version_rejected = seed / "..2026_07_16_00_00_02.000000003"
        version_rejected.mkdir()
        (version_rejected / "auth.json").write_text("broker-reject-canary", encoding="utf-8")
        next_link = seed / "..data-next"
        next_link.symlink_to(version_rejected.name)
        os.replace(next_link, seed / "..data")
        wait_for(lambda: len(starts.read_text().splitlines()) >= 3 and canonical.read_text() == "broker-rotated-canary-D" and not listening(port), "rejected replacement did not restore the last usable canonical state")
        assert canonical.read_text() == "broker-rotated-canary-D"

        (seed / "auth.json").unlink()
        (seed / "auth.json").symlink_to(root / "outside-invalid")
        (root / "outside-invalid").write_text("invalid-source-response-canary", encoding="utf-8")
        wait_for(lambda: not listening(port), "invalid replacement did not fail closed")
        assert canonical.read_text() == "broker-rotated-canary-D"

        version_e = seed / "..2026_07_16_00_00_03.000000004"
        version_e.mkdir()
        (version_e / "auth.json").write_text(source_e, encoding="utf-8")
        (seed / "auth.json").unlink()
        (seed / "auth.json").symlink_to("..data/auth.json")
        next_link = seed / "..data-next"
        next_link.symlink_to(version_e.name)
        os.replace(next_link, seed / "..data")
        wait_for(lambda: canonical.read_text() == source_e and listening(port), "corrected source did not recover automatically")

        (seed / "auth.json").unlink()
        time.sleep(0.15)
        assert canonical.read_text() == source_e
        assert listening(port)
    finally:
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
    combined = stdout + stderr
    for canary in (source_a, source_c, source_e, "broker-rotated-canary-B", "broker-rotated-canary-D", "broker-reject-canary", "invalid-source-response-canary"):
        assert canary not in combined, combined
    assert process.returncode == 0, combined

print("OK")
`)
	if err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("seed supervisor lifecycle test failed: %v\n%s", err, out)
	}
}
