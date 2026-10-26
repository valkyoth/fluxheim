#!/usr/bin/env python3
"""Real-server OTLP failure/recovery proof, with an optional Linux container run."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading
import time

from smoke_log_file_rotation import fixture_parent, private_fixture, request, wait_for
from smoke_operational_events import port
from smoke_request_correlation import server_command, validate_container_image

CANARY = "collector-response-secret-canary"


class Collector(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        self.connection.settimeout(4)
        length = int(self.headers["Content-Length"])
        assert 0 < length <= 4 * 1024 * 1024
        payload = json.loads(self.rfile.read(length))
        signal = "metrics" if "resourceMetrics" in payload else "traces"
        with self.server.lock:
            mode = self.server.mode
            key = (mode, signal)
            self.server.seen[key] = self.server.seen.get(key, 0) + 1
        status, body = 200, b"{}"
        if mode in ("429", "503", "401", "403", "400"):
            status, body = int(mode), CANARY.encode()
        elif mode == "malformed":
            body = CANARY.encode()
        elif mode == "oversized":
            body = b"x" * 20000
        elif mode == "partial":
            field = "rejectedDataPoints" if signal == "metrics" else "rejectedSpans"
            body = json.dumps({"partialSuccess": {field: "1", "errorMessage": CANARY}}).encode()
        elif mode == "redirect":
            status = 302
        try:
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.send_header("Server", CANARY)
            if mode == "redirect":
                self.send_header("Location", "http://127.0.0.1:1/" + CANARY)
            if mode == "slow":
                self.end_headers()
                time.sleep(2.5)  # Stall after headers: response body timeout must apply.
            else:
                self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        self.close_connection = True

    def log_message(self, *_):
        pass


def counter(text, signal, outcome):
    prefix = f'fluxheim_otlp_{outcome}{{signal="{signal}"}} '
    return next(int(line[len(prefix):]) for line in text.splitlines() if line.startswith(prefix))


def sampled_request(public):
    connection = http.client.HTTPConnection("127.0.0.1", public, timeout=2)
    try:
        connection.request("GET", "/", headers={"Host": "rotation.test", "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def validate_transport_policy(binary, config, root, image, collector_port):
    original = config.read_text()
    try:
        for signal in ("metrics", "traces"):
            needle = f'endpoint = "http://127.0.0.1:{collector_port}/v1/{signal}"'
            assert needle in original
            for endpoint, accepted in (
                ("http://localhost:4318/v1/export", False),
                ("http://10.0.0.10/v1/export", False),
                ("http://[fd00::1]/v1/export", False),
                ("http://collector.example.test/v1/export", False),
                ("http://[::1]:4318/v1/export", True),
                ("https://collector.example.test/v1/export", True),
                ("https://10.0.0.10/v1/export", True),
            ):
                config.write_text(original.replace(needle, f'endpoint = "{endpoint}"'))
                result = subprocess.run(
                    server_command(binary, config, root, image) + ["--validate-config"],
                    cwd=root, capture_output=True, text=True, timeout=15, check=False,
                )
                assert (result.returncode == 0) == accepted, (signal, endpoint, result.stderr)
                if not accepted:
                    assert "requires HTTPS" in result.stderr + result.stdout
    finally:
        config.write_text(original)


def run(binary, image=None):
    image = validate_container_image(image)
    collector = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
    collector.mode, collector.seen, collector.lock = "503", {}, threading.Lock()
    thread = threading.Thread(target=collector.serve_forever, daemon=True)
    thread.start()
    try:
        with private_fixture(fixture_parent(False)) as root:
            public, metrics = port(), port()
            (root / "index.html").write_text("available")
            config = root / "fluxheim.toml"
            config.write_text(f'''[server]
listen = ["127.0.0.1:{public}"]
trusted_proxies = ["127.0.0.1"]
[server.process]
threads = 1
pid_file = "fluxheim.pid"
upgrade_sock = "upgrade.sock"
certificate_reload_sock = "reload.sock"
grace_period_seconds = 1
graceful_shutdown_timeout_seconds = 2
[logging]
format = "json"
[metrics]
enabled = true
listen = "127.0.0.1:{metrics}"
[metrics.otlp]
enabled = true
endpoint = "http://127.0.0.1:{collector.server_port}/v1/metrics"
interval_secs = 1
timeout_secs = 2
[tracing]
enabled = true
[tracing.otlp]
enabled = true
endpoint = "http://127.0.0.1:{collector.server_port}/v1/traces"
queue_size = 8
timeout_secs = 2
[[vhosts]]
name = "rotation.test"
hosts = ["rotation.test"]
[vhosts.web]
root = "{root.as_posix()}"
''')
            validate_transport_policy(binary, config, root, image, collector.server_port)
            output_path = root / "process.log"
            with output_path.open("wb") as output:
                process = subprocess.Popen(server_command(binary, config, root, image), cwd=root,
                                           env=dict(os.environ, RUST_LOG="trace"), stdout=output, stderr=output)
                try:
                    def ready():
                        assert process.poll() is None, output_path.read_text()
                        try:
                            return request(public, "/")[0] == 200
                        except OSError:
                            return False
                    wait_for(ready)
                    for mode in ("503", "429", "401", "403", "400", "redirect", "malformed", "oversized", "partial", "slow", "success"):
                        with collector.lock:
                            collector.mode = mode
                        def observed():
                            started = time.monotonic()
                            assert sampled_request(public) == (200, b"available")
                            status, body = request(metrics, "/metrics")
                            assert status == 200
                            assert time.monotonic() - started < 2, "collector blocked serving/scraping"
                            text = body.decode()
                            assert CANARY not in text
                            for signal in ("metrics", "traces"):
                                assert counter(text, signal, "queued_bytes") <= 8 * 1024 * 1024
                                assert counter(text, signal, "active_requests") <= 1
                            with collector.lock:
                                return all(collector.seen.get((mode, signal), 0) for signal in ("metrics", "traces"))
                        wait_for(observed)
                    def recovered():
                        text = request(metrics, "/metrics")[1].decode()
                        return all(counter(text, signal, "success_total") > 0 and counter(text, signal, "failed_total") > 0 and counter(text, signal, "partial_total") > 0 for signal in ("traces", "metrics"))
                    wait_for(recovered)
                    # One final stalled request must not turn shutdown into an unbounded wait.
                    with collector.lock:
                        collector.mode = "slow"
                    sampled_request(public)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                        raise AssertionError("OTLP shutdown exceeded deadline")
            assert CANARY not in output_path.read_text(), "collector data leaked to diagnostics"
    finally:
        collector.shutdown()
        collector.server_close()
        thread.join(timeout=5)
    print("OTLP lifecycle: transport policy, serving/scrape isolation, failure/recovery, bounds and secret canary: ok")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--container-image")
    args = parser.parse_args()
    run(args.binary.resolve(strict=True), args.container_image)
