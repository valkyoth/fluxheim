#!/usr/bin/env python3
"""Inspect response policy on a real loopback server; no browser guarantees implied."""

import base64
from contextlib import contextmanager
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import threading

from smoke_cors_examples import gateway
from smoke_geoip_examples import replace_once

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/headers/response.toml"
BODY = b"response header fixture\n"


@contextmanager
def origin():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(500 if self.path.endswith("/error") else 200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(BODY)))
            self.send_header("X-Powered-By", "fixture")
            self.send_header("X-Origin-Secret", "remove-me")
            self.send_header("Strict-Transport-Security", "max-age=900")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("Location", "http://origin.example.test/internal/login")
            self.send_header("Refresh", '0; url="http://origin.example.test/internal/login"')
            self.send_header("Set-Cookie", "session=fixture; Domain=.ORIGIN.example.test; Path=/internal/login; Secure; HttpOnly; SameSite=Lax")
            self.send_header("Set-Cookie", "other=fixture; Domain=other.example.test; Path=/internalized; Secure")
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(BODY)

        do_HEAD = do_GET

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


def request(port, path="/", method="GET", body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=body, headers={"Host": "api.example.test"})
        response = connection.getresponse()
        fields = {}
        for name, value in response.getheaders():
            fields.setdefault(name.lower(), []).append(value)
        payload = response.read(8193)
        assert len(payload) <= 8192
        return response.status, fields, payload
    finally:
        connection.close()


def digest(body):
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode("ascii") + ":"


def checks(port):
    status, fields, body = request(port)
    assert status == 200 and body == BODY
    for removed in ("server", "x-powered-by", "x-origin-secret"):
        assert removed not in fields
    for name, expected in (("x-content-type-options", "nosniff"), ("x-frame-options", "DENY"),
                           ("referrer-policy", "no-referrer"), ("strict-transport-security", "max-age=300"),
                           ("cross-origin-opener-policy", "same-origin"),
                           ("cross-origin-resource-policy", "same-origin"),
                           ("cross-origin-embedder-policy", "require-corp"),
                           ("x-permitted-cross-domain-policies", "none"),
                           ("reporting-endpoints", 'csp="https://reports.example.test/csp"'),
                           ("x-edge", "demo"), ("content-digest", digest(BODY)),
                           ("repr-digest", digest(BODY))):
        assert fields[name] == [expected], (name, fields.get(name))
    assert fields["permissions-policy"] == ["camera=(), geolocation=(), microphone=(), payment=(), usb=()"]
    assert "frame-ancestors 'none'" in fields["content-security-policy"][0]
    assert fields["content-security-policy-report-only"] == ["default-src 'self'; report-to csp"]
    assert fields["location"] == ["https://public.example.test/app/login"]
    assert fields["refresh"] == ['0; url="https://public.example.test/app/login"']
    assert fields["set-cookie"] == [
        "session=fixture; Domain=public.example.test; Path=/app/login; Secure; HttpOnly; SameSite=Lax",
        "other=fixture; Domain=other.example.test; Path=/internalized; Secure"], fields["set-cookie"]
    assert len(fields["link"]) == 2
    _, child, _ = request(port, "/child")
    assert child["referrer-policy"] == ["same-origin"] and child["x-route"] == ["child"]
    assert child["x-edge"] == ["demo"]
    status, head, body = request(port, method="HEAD")
    assert status == 200 and body == b"" and head["content-digest"] == [digest(b"")]
    assert "repr-digest" not in head
    status, error, _ = request(port, "/error")
    assert status == 500 and "content-security-policy" in error
    assert "repr-digest" not in error
    # documented contract: early local errors bypass the policy applied to origin errors.
    status, rejected, _ = request(port, "/child", "POST", b"12345")
    assert status == 413 and "content-security-policy" not in rejected
    assert "x-content-type-options" not in rejected and "strict-transport-security" not in rejected


def main():
    source = EXAMPLE.read_text()
    with origin() as upstream:
        with gateway(source, upstream) as port:
            checks(port)
        print("response headers: hardening, precedence, rewrites, cookies and SHA-256 digests: ok")
        disabled = replace_once(source, "[headers.response]\nenabled = true",
                                "[headers.response]\nenabled = false")
        with gateway(disabled, upstream) as port:
            _, fields, _ = request(port)
            assert "x-powered-by" in fields and "server" in fields
            assert "x-edge" not in fields and "content-digest" not in fields
            assert fields["location"] == ["http://origin.example.test/internal/login"]
        hsts_off = replace_once(source, "[headers.response.hsts]\nenabled = true",
                                "[headers.response.hsts]\nenabled = false")
        with gateway(hsts_off, upstream) as port:
            assert request(port)[1]["strict-transport-security"] == ["max-age=900"]
        isolated = replace_once(source, 'profile = "baseline"', 'profile = "cross-origin-isolated"')
        isolated = replace_once(isolated, 'cross_origin_opener_policy = "same-origin"',
                                'cross_origin_opener_policy = "unsafe-none"')
        with gateway(isolated, upstream) as port:
            assert request(port)[1]["cross-origin-opener-policy"] == ["unsafe-none"]
        mutation = replace_once(source, '[headers.response.add]\nx-edge = "demo"',
                                '[headers.response.set]\nx-edge = "demo"\nx-template = "{host}"')
        mutation = replace_once(mutation, '[vhosts.routes.headers.response]\n',
                                '[vhosts.routes.headers.response]\nremove = ["x-edge", "link"]\n')
        with gateway(mutation, upstream) as port:
            _, fields, _ = request(port, "/child")
            # documented contract/002: inherited set/append survives removal; template stays literal.
            assert fields["x-edge"] == ["demo"] and len(fields["link"]) == 2
            assert fields["x-template"] == ["{host}"]
        broad_path = replace_once(source, 'from = "/internal/"', 'from = "/internal"')
        broad_path = replace_once(broad_path, 'to = "/app/"', 'to = "/app"')
        with gateway(broad_path, upstream) as port:
            # Literal prefix semantics are documented; this is not route-segment matching.
            assert "Path=/appized;" in request(port)[1]["set-cookie"][1]
        print("response headers: disabled ownership and three open contract gaps reproduced: ok")


if __name__ == "__main__":
    main()
