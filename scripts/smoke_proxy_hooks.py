#!/usr/bin/env python3
"""Trusted local auth/mirror recipes; no external credentials or destinations."""

from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import queue
import socket
import subprocess
import tempfile
import threading
import time

from smoke_geoip_examples import replace_once

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples/proxy"


def prepare(source, public, origin, auth, mirror):
    source = replace_once(source, 'listen = ["127.0.0.1:8080"]',
                          f'listen = ["127.0.0.1:{public}"]')
    source = replace_once(source, 'upstreams = ["127.0.0.1:9001"]',
                          f'upstreams = ["127.0.0.1:{origin}"]')
    if 'url = "http://127.0.0.1:9002/check"' in source:
        source = replace_once(source, 'url = "http://127.0.0.1:9002/check"',
                              f'url = "http://127.0.0.1:{auth}/check"')
    else:
        source = replace_once(source, 'base_url = "http://127.0.0.1:9003/shadow"',
                              f'base_url = "http://127.0.0.1:{mirror}/shadow"')
    return source


@contextmanager
def fixture(kind):
    events = queue.Queue(maxsize=32)

    class Handler(BaseHTTPRequestHandler):
        def serve(self):
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 4096:
                raise ValueError("fixture request body exceeds bound")
            body = self.rfile.read(length)
            event = {"path": self.path, "method": self.command,
                     "headers": dict(self.headers), "bytes": len(body)}
            events.put_nowait(event)
            status, payload, extra = 200, json.dumps(event).encode(), {}
            if kind == "auth":
                mode = self.headers.get("Authorization", "")
                status, payload = 403, b"denied\n"
                if mode == "Bearer allow":
                    status, payload, extra = 204, b"", {"x-auth-request-user": "alice"}
                elif mode == "Bearer no-identity":
                    status, payload = 204, b""
                elif mode == "Bearer redirect":
                    status, payload, extra = 302, b"login", {"Location": "/not-followed"}
                elif mode == "Bearer oversize":
                    status, payload = 200, b"x" * 1025
            elif kind == "mirror":
                status, payload = 503, b"shadow failure"
            self.send_response(status)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            for name, value in extra.items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        do_GET = serve
        do_POST = serve
        do_HEAD = serve
        do_OPTIONS = serve

        def log_message(self, *_args):
            pass

    class Server(HTTPServer):
        def get_request(self):
            stream, peer = super().get_request()
            stream.settimeout(3)
            return stream, peer

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, events
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@contextmanager
def gateway(name, origin, auth, mirror):
    parent = subprocess.check_output(["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")],
                                     text=True, timeout=10).strip()
    with tempfile.TemporaryDirectory(prefix="proxy-hooks-", dir=parent) as directory:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config = Path(directory) / "fluxheim.toml"
        config.write_text(prepare((EXAMPLES / name).read_text(), port, origin, auth, mirror))
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
                yield port
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


def request(port, path, method="GET", body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=body,
                           headers={"Host": "app.example.test", **(headers or {})})
        response = connection.getresponse()
        body = response.read(8193)
        assert len(body) <= 8192
        return response.status, body
    finally:
        connection.close()


def lower(event):
    return {name.lower(): value for name, value in event["headers"].items()}


def main():
    with fixture("origin") as (origin, origins), fixture("auth") as (auth, auths), fixture("mirror") as (mirror, mirrors):
        with gateway("auth.toml", origin, auth, mirror) as port:
            status, _ = request(port, "/private?x=1", headers={
                "Authorization": "Bearer allow", "X-Auth-Request-User": "attacker",
                "X-Original-URI": "/spoof", "X-Secret": "not-forwarded"})
            assert status == 200
            assert lower(origins.get(timeout=3))["x-auth-request-user"] == "alice"
            event = auths.get(timeout=3)
            assert event["method"] == "GET" and event["path"] == "/check"
            assert lower(event)["x-original-uri"] == "/private?x=1"
            assert "x-secret" not in lower(event)
            for mode, expected in (("deny", 403), ("redirect", 500), ("oversize", 502)):
                assert request(port, "/private", headers={"Authorization": f"Bearer {mode}"})[0] == expected
                auths.get(timeout=3)
                assert origins.empty(), "rejected auth reached origin"
            assert request(port, "/private", headers={
                "Authorization": "Bearer no-identity", "X-Auth-Request-User": "attacker"})[0] == 200
            auths.get(timeout=3)
            assert "x-auth-request-user" not in lower(origins.get(timeout=3)), "recipe did not scrub identity"
            assert request(port, "/upload", "POST", b"body", {"Authorization": "Bearer allow"})[0] == 200
            assert auths.get(timeout=3)["bytes"] == 0
            assert origins.get(timeout=3)["bytes"] == 4
        with gateway("mirror.toml", origin, auth, mirror) as port:
            status, _ = request(port, "/asset?q=1", headers={
                "Authorization": "Bearer secret", "Cookie": "session=secret", "X-Request-Id": "demo-1"})
            assert status == 200
            primary = origins.get(timeout=3)
            shadow = mirrors.get(timeout=3)
            assert shadow["path"] == "/shadow/asset?q=1"
            assert lower(shadow)["x-request-id"] == lower(primary)["x-request-id"]
            assert "authorization" not in lower(shadow) and "cookie" not in lower(shadow)
            assert request(port, "/write", "POST", b"data")[0] == 200
            assert origins.get(timeout=3)["bytes"] == 4
            # A subsequent eligible request drains after any mistakenly queued POST.
            assert request(port, "/barrier")[0] == 200
            origins.get(timeout=3)
            assert mirrors.get(timeout=3)["path"] == "/shadow/barrier"
            assert mirrors.empty()
            # documented contract: characterize the missing bodyless admission check.
            assert request(port, "/body-get", body=b"body")[0] == 200
            assert origins.get(timeout=3)["bytes"] == 4
            shadow = mirrors.get(timeout=3)
            assert shadow["path"] == "/shadow/body-get" and shadow["bytes"] == 0
        print("proxy hooks: 6 auth and 4 mirror live cases: ok")


if __name__ == "__main__":
    main()
