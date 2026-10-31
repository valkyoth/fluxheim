#!/usr/bin/env python3
"""Run guide templates against local TLS origins using a trusted local binary."""

from collections import deque
from contextlib import contextmanager
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from smoke_geoip_examples import replace_once
from smoke_tls_examples import generate

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples/tls"


def prepare(source, port, origin_port):
    source = replace_once(source, 'listen = ["127.0.0.1:8080"]',
                          f'listen = ["127.0.0.1:{port}"]')
    return replace_once(source, 'upstreams = ["127.0.0.1:9443"]',
                        f'upstreams = ["127.0.0.1:{origin_port}"]')


@contextmanager
def origin(root, require_client):
    requests = deque(maxlen=16)
    names = deque(maxlen=16)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(root / "origin.pem", root / "origin-key.pem")
    context.set_alpn_protocols(["http/1.1"])
    context.set_servername_callback(lambda _socket, name, _ctx: names.append(name))
    if require_client:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(root / "gateway-client.pem")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            cert = self.connection.getpeercert(binary_form=True)
            requests.append((self.headers.get("Host"),
                             hashlib.sha256(cert).digest() if cert else None))
            body = b"upstream-guide-ok\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    class Server(HTTPServer):
        def get_request(self):
            stream, address = super().get_request()
            stream.settimeout(3)
            try:
                return context.wrap_socket(stream, server_side=True), address
            except BaseException:
                stream.close()
                raise

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, requests, names
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), "origin did not stop"


@contextmanager
def gateway(root, source, origin_port):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config = root / "fluxheim.toml"
    config.write_text(prepare(source, port, origin_port))
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


def run_case(root, label, source, status, require_client=False, client=None,
             sni="origin.example.test"):
    with origin(root, require_client) as (origin_port, requests, names):
        with gateway(root, source, origin_port) as port:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            try:
                connection.request("GET", "/", headers={"Host": "gateway.example.test"})
                response = connection.getresponse()
                body = response.read(4097)
                assert response.status == status, (label, response.status, body)
                if status == 200:
                    assert body == b"upstream-guide-ok\n"
                    assert list(requests) == [("gateway.example.test", client)], requests
                else:
                    assert body == b"bad gateway\n"
                    assert not requests, "rejected TLS reached origin HTTP handler"
                assert names and all(name == sni for name in names), names
            finally:
                connection.close()
    print(f"Upstream TLS guide: {label}: ok")


def main():
    parent = subprocess.check_output(["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")],
                                     text=True, timeout=10).strip()
    with tempfile.TemporaryDirectory(prefix="upstream-guide-", dir=parent) as directory:
        root = Path(directory)
        root.chmod(0o700)
        generate(root, "origin", ["origin.example.test"])
        client = generate(root, "gateway-client", ["gateway-client.example.test"], client=True)
        generate(root, "unrelated", ["unrelated.example.test"], client=True)
        # Exact self-signed fixture anchors; production examples use issuing CA bundles.
        (root / "origin-ca.pem").write_bytes((root / "origin.pem").read_bytes())
        basic = (EXAMPLES / "upstream.toml").read_text()
        mutual = (EXAMPLES / "upstream-mtls.toml").read_text()
        run_case(root, "verified origin, unchanged HTTP Host", basic, 200)
        run_case(root, "untrusted origin rejected", replace_once(
            basic, 'upstream_ca_path = "origin-ca.pem"',
            'upstream_ca_path = "unrelated.pem"'), 502)
        wrong = replace_once(basic, 'upstream_sni = "origin.example.test"',
                             'upstream_sni = "routing.example.test"')
        run_case(root, "wrong name rejected", wrong, 502, sni="routing.example.test")
        run_case(root, "separate SNI and verification name", wrong +
                 '\nupstream_alternative_cn = "origin.example.test"\n',
                 200, sni="routing.example.test")
        run_case(root, "alternative replaces rather than adds identity", basic +
                 '\nupstream_alternative_cn = "wrong.example.test"\n', 502)
        run_case(root, "origin requires client certificate", basic, 502, require_client=True)
        run_case(root, "origin accepts gateway client certificate", mutual, 200,
                 require_client=True, client=client)
        wrong_client = replace_once(mutual, 'upstream_client_cert_path = "gateway-client.pem"',
                                    'upstream_client_cert_path = "unrelated.pem"')
        wrong_client = replace_once(wrong_client, 'upstream_client_key_path = "gateway-client-key.pem"',
                                    'upstream_client_key_path = "unrelated-key.pem"')
        run_case(root, "untrusted client rejected", wrong_client, 502, require_client=True)


if __name__ == "__main__":
    main()
