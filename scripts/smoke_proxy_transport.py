#!/usr/bin/env python3
"""Run the trusted proxy transport recipe against bounded loopback fixtures."""

from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from smoke_geoip_examples import replace_once

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/proxy/transport.toml"
PAGE = b"<!doctype html><title>Gateway</title>Try again shortly.\n"


def prepare(source, public, origin):
    source = replace_once(source, 'listen = ["127.0.0.1:8080"]',
                          f'listen = ["127.0.0.1:{public}"]')
    return replace_once(source, 'upstreams = ["127.0.0.1:9001"]',
                        f'upstreams = ["127.0.0.1:{origin}"]')


@contextmanager
def origin_server():
    release_slow = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if self.path == "/broken":
                self.close_connection = True
                return
            if self.path == "/slow":
                release_slow.wait(timeout=6)
                self.close_connection = True
                return
            status = {"/origin-error": 503, "/origin-502": 502}.get(self.path, 200)
            body = b"origin response\n"
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Origin-Port", str(self.client_address[1]))
            self.end_headers()
            self.wfile.write(body)

        def do_HEAD(self):
            self.do_GET()

        def log_message(self, *_args):
            pass

    class Server(ThreadingHTTPServer):
        daemon_threads = False

        def get_request(self):
            stream, peer = super().get_request()
            stream.settimeout(3)
            return stream, peer

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        release_slow.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@contextmanager
def gateway(origin):
    parent = subprocess.check_output(["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")],
                                     text=True, timeout=10).strip()
    with tempfile.TemporaryDirectory(prefix="proxy-transport-", dir=parent) as directory:
        root = Path(directory)
        errors = root / "errors"
        errors.mkdir(mode=0o700)
        page = errors / "gateway.html"
        page.write_bytes(PAGE)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config = root / "fluxheim.toml"
        config.write_text(prepare(EXAMPLE.read_text(), port, origin))
        command = [str(ROOT / "target/debug/fluxheim"), "--config", str(config)]
        subprocess.run(command + ["--validate-config"], check=True, timeout=20,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        with tempfile.TemporaryFile() as log:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=log)
            try:
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None:
                        raise AssertionError("gateway exited before readiness")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise AssertionError("gateway readiness deadline") from None
                        time.sleep(0.05)
                yield port, page
            except Exception:
                log.seek(0)
                print(log.read(8192).decode(errors="replace"))
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def request(port, path, method="GET", headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, headers={"Host": "app.example.test", **(headers or {})})
        response = connection.getresponse()
        body = response.read(8193)
        assert len(body) <= 8192
        return response.status, {key.lower(): value for key, value in response.getheaders()}, body
    finally:
        connection.close()


def main():
    with origin_server() as origin, gateway(origin) as (port, page):
        first, second = request(port, "/one"), request(port, "/two")
        assert first[0] == second[0] == 200
        assert first[1]["x-origin-port"] == second[1]["x-origin-port"], "idle connection not reused"
        for path, expected in (("/origin-error", 503), ("/origin-502", 502)):
            status, _, body = request(port, path)
            assert status == expected and body == b"origin response\n", "origin errors must pass through"
        status, headers, body = request(port, "/broken")
        assert status == 502 and body == PAGE
        assert headers["content-type"].startswith("text/html")
        status, _, body = request(port, "/broken", headers={"Range": "bytes=0-3", "If-None-Match": "*"})
        assert status == 502 and body == PAGE, "gateway page became a conditional/range response"
        status, _, body = request(port, "/broken", method="HEAD")
        assert status == 502 and body == b""
        started = time.monotonic()
        status, _, body = request(port, "/slow")
        assert status == 504 and body == PAGE
        assert time.monotonic() - started < 5, "read deadline did not bound response"
        page.unlink()
        status, _, body = request(port, "/broken")
        assert status == 502 and body == b"bad gateway\n", "missing page must use built-in fallback"
    print("proxy transport: reuse, origin errors, 502/504, HEAD, conditions and missing page: ok")


if __name__ == "__main__":
    main()
