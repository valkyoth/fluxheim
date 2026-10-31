#!/usr/bin/env python3
"""Exercise the metrics guide against a trusted local binary, never an arbitrary archive."""
import argparse
from contextlib import closing, contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import re
import subprocess
import threading
import time

from smoke_log_file_rotation import fixture_parent, private_fixture, wait_for
from smoke_logging_examples import replace_once
from smoke_operational_events import ROOT, port

EXAMPLE = ROOT / "examples/metrics/proxy.toml"
TOKEN = "metrics-guide-private-token-canary"
ROTATED = "metrics-guide-replacement-token-canary"
CANARY = "metrics-guide-request-private-canary"
MAX_RESPONSE = 2 * 1024 * 1024


def request(port_, path="/metrics", method="GET", token=None):
    with closing(http.client.HTTPConnection("127.0.0.1", port_, timeout=2)) as client:
        headers = {"Host": "metrics.example.test", "Connection": "close"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        client.request(method, path, headers=headers)
        response = client.getresponse()
        body = response.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            raise AssertionError("metrics fixture response exceeded bound")
        return response.status, {name.lower(): value for name, value in response.getheaders()}, body


def samples(text, name):
    pattern = re.compile(r"^" + re.escape(name) + r"(?:\{[^\n]*\})? ([0-9.eE+\-]+)$", re.MULTILINE)
    return [float(value) for value in pattern.findall(text)]


class Origin(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_):
        pass


@contextmanager
def server(binary, root, source, metrics_port, *, rejection=None):
    config = root / "fluxheim.toml"
    config.write_text(source)
    env = {key: value for key, value in os.environ.items()
           if key.casefold() not in {"rust_log", "fluxheim_config"}}
    stdout, stderr = root / "stdout.log", root / "stderr.log"
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen([str(binary), "--config", str(config)], cwd=root,
                                   env=env, stdout=out, stderr=err)
        try:
            if rejection is not None:
                assert process.wait(timeout=15) != 0, "invalid token unexpectedly started"
                assert rejection in stderr.read_text(), "unexpected startup rejection"
            else:
                deadline = time.monotonic() + 15
                while True:
                    if process.poll() is not None:
                        diagnostic = stderr.read_text()[-2048:]
                        for value in (TOKEN, ROTATED, CANARY):
                            diagnostic = diagnostic.replace(value, "[redacted]")
                        raise AssertionError("metrics server exited before readiness: " + diagnostic)
                    try:
                        assert request(metrics_port, "/")[0] == 404
                        break
                    except ConnectionRefusedError:
                        if time.monotonic() >= deadline:
                            raise AssertionError("metrics listener did not become ready")
                        time.sleep(0.05)
            yield
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    logs = stdout.read_bytes() + stderr.read_bytes()
    assert all(value.encode() not in logs for value in (TOKEN, ROTATED, CANARY)), "secret in diagnostics"


def exercise(binary):
    with private_fixture(fixture_parent(False)) as root:
        with ThreadingHTTPServer(("127.0.0.1", 0), Origin) as origin:
            origin.daemon_threads = True
            worker = threading.Thread(target=origin.serve_forever, daemon=True)
            worker.start()
            try:
                public, metrics_port = port(), port()
                while metrics_port == public:
                    metrics_port = port()
                source = replace_once(EXAMPLE.read_text(), "127.0.0.1:8080", f"127.0.0.1:{public}")
                source = replace_once(source, "127.0.0.1:9091", f"127.0.0.1:{metrics_port}")
                source = replace_once(source, 'upstreams = ["127.0.0.1:9001"]',
                                      f'upstreams = ["127.0.0.1:{origin.server_port}"]')
                secret = root / "metrics-token"
                secret.write_text(f"  {TOKEN}\n")
                secret.chmod(0o600)
                with server(binary, root, source, metrics_port):
                    for method in ("GET", "HEAD", "POST"):
                        status, headers, _ = request(metrics_port, method=method)
                        assert status == 401 and headers["www-authenticate"] == 'Bearer realm="metrics"'
                    assert request(metrics_port, token="wrong")[0] == 401
                    for path in ("/", "/metrics/", "/unknown"):
                        assert request(metrics_port, path, token=TOKEN)[0] == 404
                    status, headers, body = request(metrics_port, method="HEAD", token=TOKEN)
                    assert status == 200 and body == b"" and int(headers["content-length"]) > 0
                    status, headers, _ = request(metrics_port, method="POST", token=TOKEN)
                    assert status == 405 and headers["allow"] == "GET, HEAD"
                    status, headers, body = request(metrics_port, "/metrics?ignored=yes", token=TOKEN)
                    assert status == 200 and headers["content-type"].startswith("text/plain")
                    before = sum(samples(body.decode(), "fluxheim_http_requests_total"))
                    for _ in range(3):
                        status, _, body = request(public, f"/{CANARY}?query={CANARY}", token=CANARY)
                        assert status == 200 and body == b"ok"

                    def completed():
                        status, _, body = request(metrics_port, token=TOKEN)
                        assert status == 200
                        text = body.decode()
                        assert all(value not in text for value in (TOKEN, ROTATED, CANARY))
                        return sum(samples(text, "fluxheim_http_requests_total")) == before + 3

                    wait_for(completed)
                    # File replacement is not a runtime credential reload.
                    secret.write_text(ROTATED + "\n")
                    assert request(metrics_port, token=TOKEN)[0] == 200
                    assert request(metrics_port, token=ROTATED)[0] == 401
                with server(binary, root, source, metrics_port):
                    assert request(metrics_port, token=TOKEN)[0] == 401
                    assert request(metrics_port, token=ROTATED)[0] == 200
                anonymous = replace_once(source, 'token_file = "metrics-token"', "# no scrape token")
                with server(binary, root, anonymous, metrics_port):
                    assert request(metrics_port)[0] == 200

                if os.name == "posix":
                    # documented contract: invert to rejection when the follow-up lands.
                    for mode in (0o644, 0o660):
                        secret.chmod(mode)
                        with server(binary, root, source, metrics_port):
                            assert request(metrics_port, token=ROTATED)[0] == 200
                    secret.chmod(0o600)
                for value, error in [(b" \n", "metrics token cannot be empty"),
                                     (b"x" * 8193, "too large"),
                                     (b"\xff", "failed to read metrics token file")]:
                    secret.write_bytes(value)
                    with server(binary, root, source, metrics_port, rejection=error):
                        pass
                secret.unlink()
                with server(binary, root, source, metrics_port, rejection="metrics token"):
                    pass
            finally:
                origin.shutdown()
                worker.join(timeout=5)
                assert not worker.is_alive(), "origin failed to stop"
    print("metrics guide: scrape/auth/methods/counts/rotation/rejections passed")
    if os.name == "posix":
        print("documented contract: Unix leaf-permission acceptance characterized; correction pending")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    exercise(args.binary.resolve(strict=True))
