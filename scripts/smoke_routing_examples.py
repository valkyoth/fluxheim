#!/usr/bin/env python3
"""Exercise trusted routing templates with a local binary and loopback origin."""

from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import tomllib

from smoke_geoip_examples import replace_once

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/routing/local.toml"


def prepare(source, public, upstream):
    config = tomllib.loads(source)
    policies = [route["proxy"] for vhost in config["vhosts"]
                for route in vhost.get("routes", []) if "proxy" in route]
    policies += [vhost["proxy"] for vhost in config["vhosts"] if "proxy" in vhost]
    literal = '"127.0.0.1:9001"'
    if not policies or any(policy["upstreams"] != ["127.0.0.1:9001"] for policy in policies):
        raise ValueError("unexpected guide origin policy")
    if source.count(literal) != len(policies):
        raise ValueError("ambiguous guide origin replacement")
    source = replace_once(source, 'listen = ["127.0.0.1:8080"]',
                          f'listen = ["127.0.0.1:{public}"]')
    return source.replace(literal, f'"127.0.0.1:{upstream}"')


@contextmanager
def origin():
    class Handler(BaseHTTPRequestHandler):
        def handle_request(self):
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 4096:
                raise ValueError("fixture request exceeds bound")
            body = self.rfile.read(length)
            payload = json.dumps({"method": self.command, "path": self.path,
                                  "host": self.headers.get("Host"),
                                  "product": self.headers.get("x-product-id"),
                                  "bytes": len(body)}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        do_GET = handle_request
        do_POST = handle_request
        do_HEAD = handle_request

        def log_message(self, *_args):
            pass

    class Server(HTTPServer):
        def get_request(self):
            stream, peer = super().get_request()
            stream.settimeout(3)
            return stream, peer

    server = Server(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()


def request(port, path, method="GET", body=None, host="gateway.example.test"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=body, headers={"Host": host})
        response = connection.getresponse()
        data = response.read(4097)
        assert len(data) <= 4096
        return response.status, dict(response.getheaders()), data
    finally:
        connection.close()


def checks(port):
    for path, rewritten, route in (
        ("/api/status?check=1", "/api/status?check=1", "status"),
        ("/api/private/users", "/api/private/users", "private"),
        ("/api/users?x=1&x=2", "/internal/users?x=1&x=2", "api"),
        ("/api", "/internal/", "api"),
        ("/api/", "/internal/", "api"),
        ("/apix", "/apix", "fallback"),
        ("/products/Ab_7?x=1", "/items/Ab_7?x=1", "product"),
        ("/products/team/item", "/products/team/item", "product-other"),
        ("/write", "/write", "fallback"),
        ("/other", "/other", "fallback"),
    ):
        status, headers, body = request(port, path)
        data = json.loads(body)
        assert status == 200 and headers.get("x-guide-route") == route, (path, status, headers)
        assert data["path"] == rewritten and data["host"] == "gateway.example.test", data
        if route == "product":
            assert data["product"] == "Ab_7"
    status, headers, body = request(port, "/write", "POST", b"1234")
    assert status == 200 and headers["x-guide-route"] == "write"
    assert json.loads(body)["bytes"] == 4
    assert request(port, "/write", "POST", b"12345")[0] == 413
    status, _, body = request(port, "/assets/hello.txt")
    assert status == 200 and body == b"routing-static-ok\n"
    assert request(port, "/assets/missing.txt")[0] == 404
    status, headers, _ = request(port, "/jump?keep=1")
    assert status == 308 and headers["location"] == "https://destination.example.test/jump?keep=1"
    assert request(port, "/api/%2e%2e/secret")[0] == 400
    assert request(port, "/", host="unknown.example.test")[0] == 421
    for host in ("one.gateway.example.test", "deep.one.gateway.example.test"):
        status, headers, body = request(port, "/", host=host)
        assert status == 200 and headers["x-guide-route"] == "wildcard"
        assert json.loads(body)["host"] == host
    print("routing guide: 19 path/method/body/static/redirect/host cases: ok")


def main():
    parent = subprocess.check_output(["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")],
                                     text=True, timeout=10).strip()
    with tempfile.TemporaryDirectory(prefix="routing-guide-", dir=parent) as directory, origin() as upstream:
        root = Path(directory)
        (root / "site").mkdir()
        (root / "site/hello.txt").write_bytes(b"routing-static-ok\n")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            public = reservation.getsockname()[1]
        config = root / "fluxheim.toml"
        config.write_text(prepare(EXAMPLE.read_text(), public, upstream))
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
                        with socket.create_connection(("127.0.0.1", public), timeout=0.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise AssertionError("gateway readiness deadline") from None
                        time.sleep(0.05)
                checks(public)
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


if __name__ == "__main__":
    main()
