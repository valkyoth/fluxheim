#!/usr/bin/env python3
"""Exercise the operational contract through a real admin listener, not log parsing."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading
import time

from operational_status_client import PATH, read_status
from smoke_log_file_rotation import fixture_parent, private_fixture, request, wait_for
from smoke_operational_events import port
from test_operational_status_contract import VALIDATOR

CANARY = "operational-private-secret-canary"
OBSERVER = "operational-observer-secret-canary"


class Collector(BaseHTTPRequestHandler):
    def do_POST(self):
        self.connection.settimeout(2)
        length = int(self.headers["Content-Length"])
        assert 0 <= length <= 4 * 1024 * 1024
        self.rfile.read(length)
        self.send_response(503 if self.server.failed.is_set() else 200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_):
        pass


def run(binary, reduced=False):
    collector = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
    collector.failed = threading.Event()
    collector.failed.set()
    worker = threading.Thread(target=collector.serve_forever, daemon=True)
    worker.start()
    try:
        with private_fixture(fixture_parent(False)) as root:
            public, admin, metrics = port(), port(), port()
            token, key = root / "token", root / "key"
            observer = root / "observer-token"
            observer.write_text(OBSERVER)
            observer.chmod(0o600)
            token.write_text(CANARY)
            key.write_text("0123456789abcdef0123456789abcdef")
            token.chmod(0o600)
            key.chmod(0o600)
            (root / "index.html").write_text("ready")
            config = root / "fluxheim.toml"
            configuration = f'''[server]
listen = ["127.0.0.1:{public}"]
trusted_proxies = ["127.0.0.1"]
[server.process]
threads = 2
pid_file = "fluxheim.pid"
upgrade_sock = "upgrade.sock"
certificate_reload_sock = "reload.sock"
grace_period_seconds = 1
graceful_shutdown_timeout_seconds = 2
[logging]
format = "json"
[admin]
enabled = true
listen = "127.0.0.1:{admin}"
token_file = "{token.as_posix()}"
operational_token_file = "{observer.as_posix()}"
snapshot_store = "{(root / 'snapshots').as_posix()}"
snapshot_integrity_key_file = "{key.as_posix()}"
'''
            if not reduced:
                configuration += f'''[metrics]
enabled = true
listen = "127.0.0.1:{metrics}"
[metrics.otlp]
enabled = true
interval_secs = 1
timeout_secs = 1
endpoint = "http://127.0.0.1:{collector.server_port}/v1/metrics"
[tracing]
enabled = true
[tracing.otlp]
enabled = true
timeout_secs = 1
endpoint = "http://127.0.0.1:{collector.server_port}/v1/traces"
'''
            configuration += f'''[[vhosts]]
name = "rotation.test"
hosts = ["rotation.test"]
[vhosts.web]
root = "{root.as_posix()}"
'''
            config.write_text(configuration)
            origin = f"http://127.0.0.1:{admin}"

            def sample():
                value = read_status(origin, OBSERVER)
                VALIDATOR.validate(value)
                text = json.dumps(value)
                assert CANARY not in text and OBSERVER not in text and str(root) not in text and "rotation.test" not in text
                return value

            with (root / "process.log").open("wb") as output:
                def launch():
                    process = subprocess.Popen([str(binary), "--config", str(config)], cwd=root,
                                               stdout=output, stderr=output)
                    def available():
                        assert process.poll() is None, "server exited before admin listener became ready"
                        try:
                            return request(admin, PATH, CANARY)[0] == 200
                        except OSError:
                            return False
                    try:
                        wait_for(available)
                    except BaseException:
                        stop(process)
                        raise
                    return process

                process = launch()
                try:
                    initial = sample()
                    assert initial["configuration"]["generation"] == 1
                    assert initial["configuration"]["last_change"] is None
                    assert request(admin, PATH)[0] == 401
                    assert request(admin, PATH, OBSERVER)[0] == 200
                    for route, method in (("snapshots", "GET"), ("snapshot", "POST"),
                                          ("reload", "POST"), ("rollback", "POST")):
                        assert request(admin, "/_fluxheim/" + route, OBSERVER, method)[0] == 403
                    assert sample()["configuration"]["last_change"] is None
                    assert request(admin, PATH, CANARY, "POST")[0] == 405
                    assert request(admin, PATH + "?secret=" + CANARY, CANARY)[0] == 400
                    assert request(public, "/") == (200, b"ready")
                    assert request(admin, "/_fluxheim/status", CANARY)[0] == 200
                    assert request(admin, "/_fluxheim/reload", CANARY, "POST")[0] == 400
                    assert sample()["configuration"]["last_change"]["outcome"] == "failed"
                    first = json.loads(request(admin, "/_fluxheim/snapshot", CANARY, "POST")[1])["snapshot"]
                    assert request(admin, "/_fluxheim/snapshot", CANARY, "POST")[0] == 201
                    assert request(admin, "/_fluxheim/reload", CANARY, "POST")[0] == 200
                    assert sample()["configuration"]["generation"] == 2
                    assert request(admin, f"/_fluxheim/rollback?live=true&to={first}", CANARY, "POST")[0] == 200
                    after = sample()
                    assert after["configuration"]["generation"] == 3
                    assert after["configuration"]["last_change"]["operation"] == "rollback"
                    assert after["configuration"]["last_change"]["outcome"] == "succeeded"
                    if not reduced:
                        def exporters(state):
                            connection = http.client.HTTPConnection("127.0.0.1", public, timeout=2)
                            try:
                                connection.request("GET", "/", headers={"Host": "rotation.test",
                                    "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"})
                                response = connection.getresponse()
                                assert response.status == 200 and response.read() == b"ready"
                            finally:
                                connection.close()
                            value = sample()
                            return all(value["telemetry"][signal]["state"] == state for signal in ("metrics", "traces"))
                        wait_for(lambda: exporters("degraded"))
                        assert sample()["readiness"] == "ready", "telemetry failure changed readiness"
                        assert request(public, "/") == (200, b"ready")
                        collector.failed.clear()
                        wait_for(lambda: exporters("observed"))
                    else:
                        assert sample()["telemetry"]["metrics"]["state"] == "not_compiled"
                    started = time.monotonic()
                    with ThreadPoolExecutor(max_workers=12) as pool:
                        replies = list(pool.map(lambda _: request(admin, PATH, CANARY), range(80)))
                    assert time.monotonic() - started < 10
                    for status, body in replies:
                        assert status in (200, 503) and len(body) <= 16384
                        if status == 200:
                            VALIDATOR.validate(json.loads(body))
                    assert sample()["configuration"]["generation"] == 3
                    # A lower-privilege success must not reset control-token guesses,
                    # including guesses sent through the observer endpoint itself.
                    for attempt in range(9):
                        target = PATH if attempt % 2 else "/_fluxheim/status"
                        assert request(admin, target, "incorrect-control-token")[0] == 401
                        sample()
                    assert request(admin, PATH, "incorrect-control-token")[0] == 429
                    assert request(admin, PATH, OBSERVER)[0] == 429
                finally:
                    stop(process)
                process = launch()
                try:
                    restarted = sample()
                    assert restarted["instance_id"] != initial["instance_id"]
                    assert restarted["configuration"]["generation"] == 1
                    assert restarted["configuration"]["last_change"] is None
                finally:
                    stop(process)
    finally:
        collector.shutdown()
        collector.server_close()
        worker.join(timeout=5)
    print("operational status: auth, schema, redaction, reload/rollback/restart, bounds, API-only client and telemetry isolation: ok")


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise AssertionError("server shutdown exceeded deadline")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--reduced", action="store_true", help="proxy/web build without OTLP features")
    args = parser.parse_args()
    run(args.binary.resolve(strict=True), args.reduced)
