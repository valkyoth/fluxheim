#!/usr/bin/env python3
"""Bounded loopback proof of the CORS recipe, ownership and open contract gaps."""

from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from smoke_geoip_examples import replace_once

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/headers/cors.toml"
APP = "https://app.example.test"
REPORTS = "https://reports.example.test"


def prepare(source, port, upstream):
    source = replace_once(source, 'listen = ["127.0.0.1:8080"]',
                          f'listen = ["127.0.0.1:{port}"]')
    needle = 'upstreams = ["127.0.0.1:9001"]'
    if source.count(needle) != 2:
        raise ValueError("expected exactly two documented origin addresses")
    return source.replace(needle, f'upstreams = ["127.0.0.1:{upstream}"]')


@contextmanager
def origin():
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append((self.command, self.path))
            body = b"cors fixture\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "text/plain")
            self.send_header("Cache-Control", "public, max-age=60")
            self.send_header("Vary", "Accept-Encoding")
            self.send_header("X-Request-Id", "fixture")
            for name, value in (("Allow-Origin", "https://origin.example.test"),
                                ("Allow-Credentials", "true"), ("Expose-Headers", "x-origin"),
                                ("Allow-Methods", "DELETE"), ("Allow-Headers", "x-origin"),
                                ("Max-Age", "86400"), ("Allow-Private-Network", "true")):
                self.send_header("Access-Control-" + name, value)
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_POST = do_GET
        do_OPTIONS = do_GET
        do_HEAD = do_GET
        do_DELETE = do_GET

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
        yield server.server_port, hits
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@contextmanager
def gateway(source, upstream):
    parent = subprocess.check_output(["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")],
                                     text=True, timeout=10).strip()
    with tempfile.TemporaryDirectory(prefix="cors-guide-", dir=parent) as directory:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config = Path(directory) / "fluxheim.toml"
        config.write_text(prepare(source, port, upstream))
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


def request(port, method="GET", path="/resource", origin_value=APP, extra=None):
    headers = {"Host": "api.example.test", **(extra or {})}
    if origin_value is not None:
        headers["Origin"] = origin_value
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        body = response.read(8193)
        assert len(body) <= 8192
        fields = {}
        for name, value in response.getheaders():
            fields.setdefault(name.lower(), []).append(value)
        # Owned CORS fields must never be duplicated.
        assert all(len(values) == 1 for name, values in fields.items()
                   if name.startswith("access-control-"))
        return response.status, {name: ", ".join(values) for name, values in fields.items()}, body
    finally:
        connection.close()


def preflight(port, origin_value=APP, method="POST", headers="Content-Type", path="/resource"):
    return request(port, "OPTIONS", path, origin_value,
                   {"Access-Control-Request-Method": method,
                    "Access-Control-Request-Headers": headers})


def checks(port, hits):
    before = len(hits)
    status, fields, body = preflight(port, headers="Authorization, Content-Type, authorization")
    assert status == 204 and body == b"" and len(hits) == before
    assert fields["access-control-allow-origin"] == APP
    assert fields["access-control-allow-credentials"] == "true"
    assert fields["access-control-max-age"] == "600"
    assert {part.strip().lower() for part in fields["vary"].split(",")} == {
        "origin", "access-control-request-method", "access-control-request-headers"}
    for origin_value in ("https://denied.example.test", "null", APP + "/", None):
        assert preflight(port, origin_value)[0] == 403
    for method, headers in (("DELETE", "content-type"), ("POST", "x-not-allowed"),
                            ("POST", "content-type,,authorization")):
        assert preflight(port, method=method, headers=headers)[0] == 403
    assert len(hits) == before
    status, fields, _ = request(port)
    assert status == 200 and fields["access-control-allow-origin"] == APP
    assert fields["access-control-expose-headers"] == "x-request-id"
    assert "origin" in fields["vary"].lower() and "accept-encoding" in fields["vary"].lower()
    for suffix in ("allow-methods", "allow-headers", "max-age", "allow-private-network"):
        assert "access-control-" + suffix not in fields
    before = len(hits)
    for method, origin_value in (("GET", "https://denied.example.test"), ("GET", None),
                                  ("DELETE", APP)):
        status, fields, _ = request(port, method, origin_value=origin_value)
        assert status == 200 and not any(name.startswith("access-control-") for name in fields)
        assert "origin" in fields["vary"].lower()
    assert len(hits) == before + 3
    assert request(port, "OPTIONS", origin_value=None)[0] == 200
    before = len(hits)
    status, fields, _ = preflight(port, REPORTS, path="/reports")
    assert status == 204 and len(hits) == before
    assert fields["access-control-max-age"] == "0"
    assert fields["access-control-allow-methods"] == "POST"
    assert "access-control-expose-headers" not in fields
    assert preflight(port, APP, path="/reports")[0] == 403
    assert request(port, "POST", "/reports", REPORTS)[1]["access-control-allow-origin"] == REPORTS


def main():
    source = EXAMPLE.read_text()
    with origin() as (upstream, hits):
        with gateway(source, upstream) as port:
            checks(port, hits)
        no_response_policy = replace_once(source, "[headers.cors]",
                                          "[headers.response]\nenabled = false\n\n[headers.cors]")
        with gateway(no_response_policy, upstream) as port:
            assert request(port)[1]["access-control-allow-origin"] == APP
            assert preflight(port)[0] == 204
        no_cors = replace_once(source, "enabled = true", "enabled = false")
        with gateway(no_cors, upstream) as port:
            before = len(hits)
            status, fields, _ = preflight(port)
            assert status == 200 and len(hits) == before + 1
            assert fields["access-control-allow-origin"] == "https://origin.example.test"
        print("CORS: scoped recipe, local preflights, actual requests and header ownership: ok")
        disabled = source + '\n[[vhosts.routes]]\nname = "disabled"\npath_prefix = "/disabled"\n' \
            '[vhosts.routes.web]\nroot = "."\n[vhosts.routes.headers.cors]\nenabled = false\n'
        with gateway(disabled, upstream) as port:
            # documented contract: parent preflight survives route opt-out; not desired behavior.
            assert preflight(port, path="/disabled")[0] == 204
            assert "access-control-allow-origin" not in request(port, path="/disabled/missing")[1]
        wildcard = replace_once(source, 'allow_origins = ["https://app.example.test"]',
                                'allow_origins = ["*"]')
        wildcard = replace_once(wildcard, "allow_credentials = true", "allow_credentials = false")
        with gateway(wildcard, upstream) as port:
            # documented contract: varying ACAO with no Origin cache discriminator.
            absent = request(port, origin_value=None)[1]
            present = request(port)[1]
            assert "access-control-allow-origin" not in absent
            assert present["access-control-allow-origin"] == "*"
            assert "origin" not in absent["vary"].lower() and "origin" not in present["vary"].lower()
        for field, original in (("allow_headers", '["authorization", "content-type", "x-request-id"]'),
                                 ("allow_methods", '["GET", "HEAD", "POST"]')):
            stars = replace_once(source, f"{field} = {original}", f'{field} = ["*"]')
            stars = replace_once(stars, "allow_credentials = true", "allow_credentials = false")
            with gateway(stars, upstream) as port:
                # documented contract: accepted wildcard is compared as a literal token.
                assert preflight(port)[0] == 403
        print("CORS: route opt-out, wildcard Vary and wildcard-token gaps reproduced: ok")


if __name__ == "__main__":
    main()
