#!/usr/bin/env python3
"""Linux live proof: a full stderr pipe cannot block typed-event producers."""
import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from smoke_operational_events import ROOT, port


def request(listener, method, path, host="known.test", auth=False):
    connection = http.client.HTTPConnection("127.0.0.1", listener, timeout=3)
    headers = {"Host": host, "Connection": "close"}
    if auth:
        headers["Authorization"] = "Bearer backpressure-secret-canary"
    try:
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def run(binary, recover):
    temporary = ROOT / "target" / "fluxheim-smoke-tmp"
    temporary.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="events-pressure-", dir=temporary) as temp:
        directory = Path(temp).resolve()
        public, admin = port(), port()
        (directory / "public").mkdir()
        (directory / "public" / "index.html").write_text("healthy\n")
        token = directory / "token"
        token.write_text("backpressure-secret-canary")
        token.chmod(0o600)
        key = directory / "integrity.key"
        key.write_text("0123456789abcdef0123456789abcdef")
        key.chmod(0o600)
        config = directory / "fluxheim.toml"
        config.write_text(f'''[server]
listen = ["127.0.0.1:{public}"]
default_vhost = "known"
[server.host_routing]
strict = true
[server.process]
threads = 1
pid_file = "fluxheim.pid"
upgrade_sock = "upgrade.sock"
certificate_reload_sock = "reload.sock"
grace_period_seconds = 1
graceful_shutdown_timeout_seconds = 2
[logging]
level = "info"
format = "json"
target = "stderr"
[logging.access]
enabled = false
[admin]
enabled = true
listen = "127.0.0.1:{admin}"
require_loopback = true
token_file = "{token}"
snapshot_store = "{directory / 'snapshots'}"
snapshot_integrity_key_file = "{key}"
[[vhosts]]
name = "known"
hosts = ["known.test"]
[vhosts.web]
root = "{directory / 'public'}"
''')
        subprocess.run([str(binary), "--config", str(config), "--validate-config"],
                       cwd=directory, check=True, timeout=20)
        reader, writer = os.pipe()
        process = None
        drain = None
        captured = bytearray()
        try:
            os.set_blocking(writer, False)
            while True:
                try:
                    os.write(writer, b"\n" * 4096)
                except BlockingIOError:
                    break
            os.set_blocking(writer, True)
            process = subprocess.Popen([str(binary), "--config", str(config)], cwd=directory,
                stdout=subprocess.DEVNULL, stderr=writer,
                env=dict(os.environ, RUST_LOG="off,fluxheim::event::security=warn,fluxheim::event::audit=info"))
            os.close(writer)
            writer = None
            deadline = time.monotonic() + 20
            while True:
                if process.poll() is not None:
                    raise RuntimeError("runtime failed before listening")
                try:
                    with socket.create_connection(("127.0.0.1", public), timeout=1):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError("runtime did not listen")
                    time.sleep(0.05)
            for _ in range(1200):
                status, _ = request(public, "GET", "/secret-canary", host="unknown.test")
                assert status == 421, status
            assert request(public, "GET", "/") == (200, b"healthy\n")
            status, body = request(admin, "GET", "/_fluxheim/status", auth=True)
            assert status == 200, (status, body)
            counters = json.loads(body)["operational_events"]
            assert counters["security"]["rate_limited"] + counters["security"]["queue_full"] > 0, counters
            assert counters["security"]["encoded"] == 1, counters
            assert counters["security"]["written"] == 0, counters
            assert counters["audit"]["accepted"] == 0, counters
            assert request(admin, "POST", "/_fluxheim/snapshot", auth=True)[0] == 201
            counters = json.loads(request(admin, "GET", "/_fluxheim/status", auth=True)[1])["operational_events"]
            assert counters["audit"]["accepted"] == 1, counters
            assert counters["audit"]["queue_full"] == counters["audit"]["rate_limited"] == 0, counters
            assert request(public, "GET", "/") == (200, b"healthy\n")
            if recover:
                # Rejected authenticated attempts consume audit credits too. A full
                # blocked lane must reject a new snapshot BEFORE changing the store.
                before = request(admin, "GET", "/_fluxheim/snapshots", auth=True)
                assert before[0] == 200, before
                deadline = time.monotonic() + 10
                while counters["audit"]["accepted"] < 128:
                    status, body = request(admin, "POST", "/_fluxheim/rollback?to=missing", auth=True)
                    assert status in (400, 404, 503), (status, body)
                    assert time.monotonic() < deadline, counters
                    if status == 503:
                        assert json.loads(body)["error"] == "audit_unavailable", body
                        time.sleep(0.05)
                    counters = json.loads(request(admin, "GET", "/_fluxheim/status", auth=True)[1])["operational_events"]
                time.sleep(1.1)  # Prove queue exhaustion independently of rate limiting.
                status, body = request(admin, "POST", "/_fluxheim/snapshot", auth=True)
                assert status == 503 and json.loads(body)["error"] == "audit_unavailable", (status, body)
                assert request(admin, "GET", "/_fluxheim/snapshots", auth=True) == before
                assert request(public, "GET", "/") == (200, b"healthy\n")
                def consume():
                    while chunk := os.read(reader, 8192):
                        captured.extend(chunk)
                drain = threading.Thread(target=consume)
                drain.start()
                deadline = time.monotonic() + 5
                while True:
                    counters = json.loads(request(admin, "GET", "/_fluxheim/status", auth=True)[1])["operational_events"]
                    if counters["audit"]["written"] == 128:
                        break
                    assert time.monotonic() < deadline, counters
                    time.sleep(0.02)
                assert counters["audit"]["reserved"] == 0, counters
                assert counters["audit"]["queue_full"] > 0, counters
                assert request(admin, "POST", "/_fluxheim/snapshot", auth=True)[0] == 201
            started = time.monotonic()
            process.terminate()
            process.wait(timeout=6)
            assert time.monotonic() - started < 6
            if drain:
                drain.join(timeout=5)
                assert not drain.is_alive()
                events = [json.loads(line) for line in captured.splitlines() if line.startswith(b"{")]
                audits = [event for event in events if event["data"]["kind"] == "audit"]
                assert len(audits) == 129, audits
                assert sum(event["data"]["operation"] == "snapshot" for event in audits) == 2
                assert audits[0]["data"]["operation"] == "snapshot"
                assert audits[0]["data"]["outcome"] == "succeeded"
                assert audits[0]["data"]["actor"] == "admin_token"
                assert b"secret-canary" not in captured
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if drain:
                drain.join(timeout=5)
            os.close(reader)
            if writer is not None:
                os.close(writer)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    binary = parser.parse_args().binary.resolve(strict=True)
    run(binary, recover=True)
    run(binary, recover=False)
    print("operational backpressure smoke: flood/audit recovery and blocked-sink shutdown passed")
