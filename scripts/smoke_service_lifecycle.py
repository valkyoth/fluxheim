#!/usr/bin/env python3
"""Linux lifecycle checks against a trusted, locally built Fluxheim binary."""

from contextlib import closing
import http.client
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import tomllib

from smoke_configuration_examples import port, validate
from smoke_geoip_examples import replace_once

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target/debug/fluxheim"
EXAMPLE = ROOT / "examples/service-lifecycle/fluxheim.toml"


def prepare(source, public, *, inactive=False):
    config = tomllib.loads(source)
    if config["server"]["listen"] != ["127.0.0.1:8080"]:
        raise ValueError("unexpected lifecycle example listener")
    source = replace_once(source, 'listen = ["127.0.0.1:8080"]',
                          f'listen = ["127.0.0.1:{public}"]')
    source = replace_once(source, "graceful_shutdown_timeout_seconds = 5",
                          "graceful_shutdown_timeout_seconds = 1")
    if inactive:
        source = replace_once(source, "[server.process]", '''[server.process]
daemon = true
error_log = "unused.log"
listener_tasks_per_fd = 3
work_stealing = false
max_retries = 0''')
    return source


def child_environment(notify):
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("LISTEN_") and key not in
                   {"NOTIFY_SOCKET", "FLUXHEIM_CONFIG", "RUST_LOG"}}
    environment["NOTIFY_SOCKET"] = "@" + notify
    return environment


def notification(sock, marker):
    deadline = time.monotonic() + 10
    while True:
        remaining = deadline - time.monotonic()
        assert remaining > 0, "lifecycle notification deadline"
        sock.settimeout(remaining)
        packet = sock.recv(4096)
        if marker in packet.splitlines():
            return


def fetch(connection):
    connection.request("GET", "/", headers={"Host": "lifecycle.example.test"})
    response = connection.getresponse()
    body = response.read(4096)
    assert response.status == 200 and body == b"service-lifecycle-ok\n"


def case(root, stop_signal, *, expire=False, inactive=False):
    public = port()
    source = root / "fluxheim.toml"
    source.write_text(prepare(EXAMPLE.read_text(), public, inactive=inactive))
    (root / "site").mkdir()
    (root / "site/index.html").write_bytes(
        (EXAMPLE.parent / "site/index.html").read_bytes())
    validate(source)
    name = "fluxheim-" + root.parent.name + "-" + root.name
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify, \
            tempfile.TemporaryFile() as output:
        notify.bind("\0" + name)
        process = subprocess.Popen(
            [str(BINARY), "--config", str(source)], env=child_environment(name),
            stdin=subprocess.DEVNULL, stdout=output, stderr=output,
        )
        persistent = http.client.HTTPConnection("127.0.0.1", public, timeout=3)
        try:
            notification(notify, b"READY=1")
            fetch(persistent)
            assert persistent.sock is not None, "fixture must keep its connection"
            assert process.poll() is None, "daemon setting unexpectedly detached"
            if inactive:
                for path in ("fluxheim.pid", "upgrade.sock", "unused.log"):
                    assert not (root / path).exists(), "inactive setting changed behavior"
            # READY precedes registration of shutdown signals by a few instructions.
            time.sleep(0.1)
            started = time.monotonic()
            process.send_signal(stop_signal)
            notification(notify, b"STOPPING=1")
            with closing(http.client.HTTPConnection("127.0.0.1", public, timeout=2)) as fresh:
                fetch(fresh)  # Grace is a handoff delay, not an immediate accept stop.
            deadline = started + 5
            while True:
                assert process.poll() is None, "exited with established client before drain"
                try:
                    with socket.create_connection(("127.0.0.1", public), timeout=0.1):
                        pass
                except ConnectionRefusedError:
                    break
                assert time.monotonic() < deadline, "public listener did not close"
                time.sleep(0.025)
            if expire:
                assert process.wait(timeout=5) == 0, "drain timeout exit status changed"
                assert time.monotonic() - started >= 2.8, "drain skipped its configured budget"
                output.seek(0)
                assert b"graceful drain timed out" in output.read(65536)
            else:
                # Reuse the accepted socket, not a new connection after accept stops.
                assert persistent.sock is not None
                fetch(persistent)
                persistent.close()
                assert process.wait(timeout=5) == 0, "clean drain failed"
        finally:
            persistent.close()
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main():
    if sys.platform != "linux":
        raise SystemExit("lifecycle notification smoke requires Linux")
    parent = subprocess.check_output(
        ["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")], text=True, timeout=10,
    ).strip()
    with tempfile.TemporaryDirectory(prefix="lifecycle-guide-", dir=parent) as temporary:
        for name, stop_signal, expire, inactive in (
            ("term-clean", signal.SIGTERM, False, True),
            ("term-timeout", signal.SIGTERM, True, False),
            ("interrupt", signal.SIGINT, False, False),
            ("quit", signal.SIGQUIT, False, False),
        ):
            root = Path(temporary) / name
            root.mkdir(mode=0o700)
            case(root, stop_signal, expire=expire, inactive=inactive)
    print("service lifecycle: readiness, signals, grace, clean/timeout drain and inactive settings: ok")


if __name__ == "__main__":
    main()
