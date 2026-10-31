#!/usr/bin/env python3
"""Capture real upstream requests for the header guide and known contract gaps."""

from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import threading

from smoke_cors_examples import gateway
from smoke_geoip_examples import replace_once

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/headers/request.toml"


@contextmanager
def origin():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            fields = {}
            for name, value in self.headers.items():
                fields.setdefault(name.lower(), []).append(value)
            body = json.dumps({"path": self.path, "headers": fields}).encode()
            assert len(body) <= 8192
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

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


def request(port, path="/", extra=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path, headers={"Host": "api.example.test", **(extra or {})})
        response = connection.getresponse()
        body = response.read(8193)
        assert len(body) <= 8192
        return response.status, json.loads(body) if response.status == 200 else None
    finally:
        connection.close()


def capture(port, path="/", extra=None):
    status, payload = request(port, path, extra)
    assert status == 200, status
    return payload


def checks(port):
    captured = capture(port, "/items/alpha?q=one", {
        "X-Forwarded-For": "198.51.100.90", "X-Real-IP": "198.51.100.91",
        "X-Forwarded-Host": "spoof.example.test", "X-Forwarded-Proto": "https",
        "Forwarded": "for=198.51.100.92", "CF-Connecting-IP": "198.51.100.93",
        "X-Forwarded-Client-Cert": "spoof", "X-Internal-User": "spoof",
        "X-Edge-Note": "inbound"})
    fields = captured["headers"]
    assert captured["path"] == "/internal/alpha?q=one"
    for name, value in (("host", "api.example.test"), ("x-forwarded-host", "api.example.test"),
                        ("x-real-ip", "127.0.0.1"), ("x-forwarded-for", "127.0.0.1"),
                        ("x-client-address", "127.0.0.1"), ("x-forwarded-proto", "http"),
                        ("x-downstream-scheme", "http"), ("x-public-host", "api.example.test"),
                        ("x-item-id", "alpha"), ("x-request-path", "/internal/alpha"),
                        ("x-request-query", "q=one"), ("x-request-target", "/internal/alpha?q=one")):
        assert fields[name] == [value], (name, fields.get(name))
    assert fields["forwarded"] == ['for=127.0.0.1;host="api.example.test";proto=http']
    assert fields["x-edge-note"] == ["inbound", "first", "second"]
    assert fields["x-diagnostic-id"] == fields["x-request-id"]
    for name in ("x-internal-user", "cf-connecting-ip", "x-forwarded-client-cert"):
        assert name not in fields
    assert "x-request-query" not in capture(port)["headers"]


def main():
    source = EXAMPLE.read_text()
    with origin() as upstream:
        with gateway(source, upstream) as port:
            checks(port)
        disabled = replace_once(source, "[headers.request]\nenabled = true", "[headers.request]\nenabled = false")
        with gateway(disabled, upstream) as port:
            fields = capture(port, extra={"X-Real-IP": "198.51.100.90", "X-Internal-User": "spoof"})["headers"]
            assert fields["x-real-ip"] == ["198.51.100.90"] and fields["x-internal-user"] == ["spoof"]
            assert "x-public-host" not in fields
        unsupported = replace_once(source, '[headers.request.add]',
            '[headers.request.add]\nx-copy-agent = "{http.user-agent}"\nx-absent = "prefix-{http.user-agent}"')
        with gateway(unsupported, upstream) as port:
            fields = capture(port, extra={"User-Agent": "fixture-agent"})["headers"]
            assert fields["user-agent"] == ["fixture-agent"]
            assert "x-copy-agent" not in fields and fields["x-absent"] == ["prefix-"]
        own_host = replace_once(source, '[headers.request.add]', '[headers.request.add]\nhost = "{host}"')
        with gateway(own_host, upstream) as port:
            fields = capture(port)["headers"]
            assert fields["host"] == [f"127.0.0.1:{upstream}"]
            assert "x-public-host" not in fields
            assert fields["x-forwarded-host"] == ["api.example.test"]
        trusted = replace_once(source, 'trusted_proxies = []',
                               'trusted_proxies = ["127.0.0.1", "203.0.113.10"]')
        trusted = replace_once(trusted, "[vhosts.proxy]", '[vhosts.access]\nallow = ["198.51.100.9"]\n\n[vhosts.proxy]')
        with gateway(trusted, upstream) as port:
            assert request(port)[0] == 403
            # Provider headers are not an alternative to the generic XFF input.
            assert request(port, extra={"CF-Connecting-IP": "198.51.100.9",
                                        "CF-IPCountry": "US", "CF-Ray": "fixture"})[0] == 403
            fields = capture(port, extra={"X-Forwarded-For": "198.51.100.9, 203.0.113.10"})["headers"]
            # documented contract: ACL uses the restored client, forwarding loses it after stripping.
            assert fields["x-real-ip"] == ["127.0.0.1"]
            assert fields["x-forwarded-for"] == ["127.0.0.1"]
        append = replace_once(trusted, "strip_inbound_client_ip_headers = true", "strip_inbound_client_ip_headers = false")
        append = replace_once(append, 'x_forwarded_for = "replace"', 'x_forwarded_for = "append"')
        with gateway(append, upstream) as port:
            fields = capture(port, extra={"X-Forwarded-For": "198.51.100.9, 203.0.113.10"})["headers"]
            assert fields["x-real-ip"] == ["198.51.100.9"]
            assert fields["x-forwarded-for"] == ["198.51.100.9, 203.0.113.10, 198.51.100.9"]
        # Shared documented contract also affects request mutations.
        inherited = replace_once(source, '[headers.request.add]', '[headers.request.set]\nx-parent = "parent"')
        inherited = replace_once(inherited, '[vhosts.routes.headers.request.add]',
            '[vhosts.routes.headers.request]\nremove = ["x-parent", "x-edge-note"]\n[vhosts.routes.headers.request.add]')
        with gateway(inherited, upstream) as port:
            fields = capture(port, "/items/alpha")["headers"]
            assert fields["x-parent"] == ["parent"] and fields["x-edge-note"] == ["first", "second"]
    print("request headers: spoof stripping, typed forwarding, rewritten templates, captures and scopes: ok")
    print("request headers: unsupported templates, mutable Host, trusted client loss and inherited removal gaps: ok")


if __name__ == "__main__":
    main()
