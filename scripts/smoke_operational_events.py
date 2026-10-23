#!/usr/bin/env python3
"""Live binary proof of bounded operational JSON/text, filtering and redaction."""
import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
CANARY = "operational-secret-canary"


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(binary, format_, filter_, expected, target="stderr", file_sink=False):
    temporary = ROOT / "target" / "fluxheim-smoke-tmp"
    temporary.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="events-", dir=temporary) as temp:
        directory = Path(temp).resolve()
        listen = port()
        sink_path = directory / "file-sink.log"
        crash_path = directory / "fatal.log"
        crash_config = f'crash_file = "{crash_path}"\n' if file_sink else ""
        file_config = (f'[logging.file]\nenabled = true\npath = "{sink_path}"\n'
                       if file_sink else "")
        # Reserved but not listening: repeatable connection refusal, no external DNS.
        with socket.socket() as origin:
            origin.bind(("127.0.0.1", 0))
            config = directory / "fluxheim.toml"
            config.write_text(f'''[server]
listen = ["127.0.0.1:{listen}"]
[server.process]
pid_file = "fluxheim.pid"
upgrade_sock = "upgrade.sock"
certificate_reload_sock = "reload.sock"
threads = 1
grace_period_seconds = 1
graceful_shutdown_timeout_seconds = 2
[logging]
level = "info"
format = "{format_}"
target = "{target}"
{crash_config}
{file_config}
[logging.access]
enabled = false
[proxy]
upstreams = ["127.0.0.1:{origin.getsockname()[1]}"]
upstream_tls = false
''')
            environment = dict(os.environ, RUST_LOG=filter_)
            log_path = directory / "events.log"
            with log_path.open("wb") as log:
                process = subprocess.Popen([str(binary), "--config", str(config)],
                                           cwd=directory, env=environment, stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 20
                    while True:
                        if process.poll() is not None:
                            raise RuntimeError(log_path.read_text())
                        try:
                            with socket.create_connection(("127.0.0.1", listen), timeout=1):
                                break
                        except OSError:
                            if time.monotonic() >= deadline:
                                raise RuntimeError("runtime did not listen")
                            time.sleep(0.05)
                    connection = http.client.HTTPConnection("127.0.0.1", listen, timeout=5)
                    try:
                        connection.request("GET", f"/{CANARY}?token={CANARY}", headers={
                            "Host": "events.test", "Authorization": f"Bearer {CANARY}",
                            "Cookie": f"session={CANARY}", "X-Request-ID": CANARY,
                            "X-Fluxheim-Actor": "automatic", "Connection": "close",
                        })
                        response = connection.getresponse()
                        assert response.status == 502, response.status
                        assert response.read() == b"bad gateway\n"
                    finally:
                        connection.close()
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            contents = log_path.read_text()
            if file_sink:
                contents += sink_path.read_text()
                assert crash_path.read_bytes() == b"", "ordinary traffic reached fatal sink"
                if os.name == "posix":
                    assert crash_path.stat().st_mode & 0o777 == 0o600
            assert CANARY not in contents, "private input leaked to logs"
            events = []
            for line in contents.splitlines():
                if format_ == "text" and line.startswith("ERROR error "):
                    line = line.removeprefix("ERROR error ")
                if line.startswith("{"):
                    event = json.loads(line)
                    if "schema_version" in event:
                        assert len(line.encode()) + 1 <= 8192
                        events.append(event)
            assert len(events) == expected, events
            for event in events:
                assert event["data"]["reason"] == "connection_refused"
                assert event["correlation"] == {}
                assert "resource" not in event


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    binary = parser.parse_args().binary.resolve(strict=True)
    run(binary, "json", "off,fluxheim::event::error=error", 1)
    run(binary, "text", "off,fluxheim::event::error=error", 1)
    run(binary, "json", "off", 0)
    run(binary, "json", "error/Operation failed", 1)
    run(binary, "json", "error/NEVER_MATCH", 0)
    run(binary, "json", "off,fluxheim::event::error=error", 1, target="stdout")
    run(binary, "json", "off,fluxheim::event::error=error", 1, file_sink=True)
    print("operational events live smoke: 7 scenarios passed")


if __name__ == "__main__":
    main()
