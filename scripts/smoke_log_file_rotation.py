#!/usr/bin/env python3
"""Live proof of protected ordinary-log rotation, fallback and status counters."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import errno
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from smoke_operational_events import ROOT, port


def deletion_result(before, after):
    assert not after["failed"] and after["write_errors"] == before["write_errors"], after
    reopens = after["reopens"] - before["reopens"]
    errors = after["reopen_errors"] - before["reopen_errors"]
    if (reopens, errors) == (0, 0):
        return None  # The worker has not completed its reopen check yet.
    assert (reopens, errors) in ((1, 0), (0, 1)), (before, after)
    return "recreated" if reopens else "pending"


def fixture_parent(quota):
    if quota:
        # No caller-supplied filesystem path: destructive filling is confined to
        # the documented disposable container mount, never a host-selected root.
        mount = Path("/quota")
        if sys.platform != "linux" or mount.is_symlink() or not mount.is_mount():
            raise ValueError("quota smoke requires a disposable Linux /quota mount")
        stats = os.statvfs(mount)
        if not 0 < stats.f_blocks * stats.f_frsize <= 8 * 1024 * 1024:
            raise ValueError("quota mount must be at most 8 MiB")
        if any(mount.iterdir()):
            raise ValueError("quota mount must be empty")
        return mount
    if os.name == "nt":
        return None  # tempfile selects the user-local root, outside the checkout.
    temporary = ROOT / "target" / "fh"
    temporary.mkdir(parents=True, exist_ok=True)
    return temporary


def protect_directory(root):
    if sys.platform == "win32":
        # Windows PowerShell must discover its own modules, not inherit PowerShell
        # 7's incompatible Security module through a CI parent process.
        environment = {key: value for key, value in os.environ.items()
                       if key.casefold() != "psmodulepath"}
        subprocess.run([
            "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "RemoteSigned",
            "-File", str(ROOT / "scripts" / "protect_windows_smoke_directory.ps1"),
            "-Directory", str(root),
        ], check=True, timeout=30, env=environment)


@contextmanager
def private_fixture(temporary):
    with tempfile.TemporaryDirectory(prefix="rotate-", dir=temporary) as temp:
        root = Path(temp).resolve()
        # A private directory alone is insufficient if its ACL does not inherit
        # to children: config/secret files can receive a broader default DACL.
        protect_directory(root)
        yield root


def request(port_, path, token=None, method="GET"):
    connection = http.client.HTTPConnection("127.0.0.1", port_, timeout=5)
    try:
        headers = {"Host": "rotation.test", "Connection": "close"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def wait_for(check):
    deadline = time.monotonic() + 10
    while not check():
        if time.monotonic() > deadline:
            raise AssertionError("rotation assertion timed out")
        time.sleep(0.05)


def records(path):
    if not path.is_file():
        return []
    content = path.read_text()
    if content and not content.endswith("\n"):
        return []  # The worker may still be completing the last OS write.
    return [json.loads(line) for line in content.splitlines()]


def run(binary, quota=False):
    with private_fixture(fixture_parent(quota)) as root:
        public, admin, origin = port(), port(), port()
        log, old = root / "events.log", root / "events.old"
        fatal = root / "fatal.log"
        token = root / "token"
        token.write_text("rotation-test-secret")
        token.chmod(0o600)
        key = root / "key"
        key.write_text("0123456789abcdef0123456789abcdef")
        key.chmod(0o600)
        config = root / "fluxheim.toml"
        config.write_text(f'''[server]
listen = ["127.0.0.1:{public}"]
[server.process]
threads = 1
pid_file = "fluxheim.pid"
upgrade_sock = "upgrade.sock"
certificate_reload_sock = "reload.sock"
[logging]
format = "json"
crash_file = "{fatal.as_posix()}"
[logging.access]
enabled = false
[logging.file]
enabled = true
path = "{log.as_posix()}"
append = false
[proxy]
upstreams = ["127.0.0.1:{origin}"]
upstream_tls = false
[admin]
enabled = true
listen = "127.0.0.1:{admin}"
require_loopback = true
token_file = "{token.as_posix()}"
snapshot_store = "{(root / 'snapshots').as_posix()}"
snapshot_integrity_key_file = "{key.as_posix()}"
''')
        with (root / "stderr.log").open("wb") as stderr:
            process = subprocess.Popen([str(binary), "--config", str(config)], cwd=root,
                stderr=stderr, stdout=stderr,
                env=dict(os.environ, RUST_LOG="off,fluxheim::event::error=error,fluxheim::event::audit=info"))
            pending_delete = False
            try:
                def status_document():
                    code, body = request(admin, "/_fluxheim/status", token.read_text())
                    assert code == 200, (code, body)
                    return json.loads(body)

                def status():
                    return status_document()["legacy_logging"]["file_sink"]

                def ready():
                    assert process.poll() is None, (root / "stderr.log").read_text()
                    try:
                        return status() is not None
                    except OSError:
                        return False
                wait_for(ready)

                def emit():
                    assert request(public, "/secret-canary?token=secret-canary") == (502, b"bad gateway\n")

                emit()
                wait_for(lambda: len(records(log)) == 1)
                log.rename(old)
                time.sleep(1.1)
                emit()
                wait_for(lambda: len(records(log)) == 1)
                assert len(records(old)) == 1
                assert status()["reopens"] == 1

                reopens = 1
                if os.name != "nt":
                    log.unlink()
                    time.sleep(1.1)
                    emit()
                    wait_for(lambda: len(records(log)) == 1)
                    reopens += 1
                    assert status()["reopens"] == reopens

                log.write_bytes(b"")
                emit()
                wait_for(lambda: len(records(log)) == 1)

                retained = root / "retained.log"
                log.rename(retained)
                log.mkdir()  # An unsafe replacement must never replace the retained handle.
                time.sleep(1.1)
                emit()
                wait_for(lambda: len(records(retained)) == 2)
                assert status()["reopen_errors"] >= 1
                log.rmdir()
                time.sleep(1.1)
                emit()
                wait_for(lambda: len(records(log)) == 1)
                assert status()["reopens"] == reopens + 1
                assert not status()["failed"]
                assert fatal.read_bytes() == b""
                for path in (log, old, retained):
                    assert "secret-canary" not in path.read_text()
                    for record in records(path):
                        assert record["data"]["reason"] == "connection_refused"
                code, body = request(admin, "/_fluxheim/snapshot", token.read_text(), "POST")
                assert code == 201, (code, body)
                wait_for(lambda: any(record["data"].get("operation") == "snapshot" for record in records(log)))
                reload_old = root / "before-reload.log"
                log.rename(reload_old)
                time.sleep(1.1)
                with ThreadPoolExecutor(max_workers=1) as executor:
                    reload_result = executor.submit(request, admin, "/_fluxheim/reload", token.read_text(), "POST")
                    emit()
                    code, body = reload_result.result(timeout=10)
                    assert code == 200, (code, body)
                wait_for(lambda: any(record["data"].get("operation") == "reload" for record in records(log)))
                assert status()["reopens"] == reopens + 2
                assert "secret-canary" not in log.read_text()
                wait_for(lambda: len(records(log)) == 2)
                before = status()
                written = status_document()["operational_events"]["ordinary"]["written"]
                log.unlink()
                time.sleep(1.1)
                emit()
                wait_for(lambda: deletion_result(before, status()))
                outcome = deletion_result(before, status())
                wait_for(lambda: status_document()["operational_events"]["ordinary"]["written"] > written)
                if outcome == "recreated":
                    wait_for(lambda: len(records(log)) == 1)
                    assert records(log)[0]["data"]["reason"] == "connection_refused"
                else:
                    assert os.name == "nt", (before, status())
                    pending_delete = True
                print(f"log deletion: {outcome}; new record written without sink failure")
                if os.name == "posix" and not quota:
                    private_old = root / "private-old.log"
                    log.rename(private_old)
                    previous_records = len(records(private_old))
                    log.write_bytes(b"public replacement must stay unchanged\n")
                    log.chmod(0o644)
                    before = status()
                    time.sleep(1.1)
                    emit()
                    wait_for(lambda: len(records(private_old)) == previous_records + 1)
                    assert log.read_bytes() == b"public replacement must stay unchanged\n"
                    assert status()["reopen_errors"] > before["reopen_errors"]
                    assert status()["reopens"] == before["reopens"]
                    assert not status()["failed"]
                    log.chmod(0o600)
                    time.sleep(1.1)
                    emit()
                    wait_for(lambda: status()["reopens"] == before["reopens"] + 1)
                    wait_for(lambda: len(log.read_bytes().splitlines()) == 2)
                    private_bytes = log.read_bytes()
                    log.chmod(0o640)
                    emit()
                    wait_for(lambda: status()["failed"])
                    assert status()["write_errors"] == 1
                    assert log.read_bytes() == private_bytes
                    log.chmod(0o600)
                    emit()
                    time.sleep(0.1)
                    assert log.read_bytes() == private_bytes
                    print("log confidentiality: readable replacement rejected; active read access stops writes")
                if quota:
                    filler = root / "quota-filler"
                    try:
                        with filler.open("xb", buffering=0) as output:
                            for _ in range(2049):
                                output.write(b"x" * 4096)
                        raise AssertionError("bounded mount did not report ENOSPC")
                    except OSError as error:
                        assert error.errno == errno.ENOSPC, error
                    # Consume any space remaining in the log's allocated page.
                    for _ in range(100):
                        emit()
                        time.sleep(0.02)
                        if status()["failed"]:
                            break
                    assert status()["failed"] and status()["write_errors"] == 1
                    before = log.read_bytes()
                    filler.unlink()
                    emit()
                    time.sleep(1.1)
                    assert log.read_bytes() == before, "failed records must not replay"
                    assert status()["failed"], "recovery requires restart"
                    assert (root / "stderr.log").read_bytes() == b""
                    print("real ENOSPC: HTTP responsive, failure latched, no replay or stderr fallback")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if pending_delete:
                assert not log.exists(), "pending deletion completes when the process closes its handle"
        print("log file rotation: rename/delete/truncate/unsafe replacement/recovery/concurrent reload/status passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--quota", action="store_true",
        help="also fill the empty disposable Linux /quota mount (at most 8 MiB)")
    args = parser.parse_args()
    run(args.binary.resolve(strict=True), args.quota)
