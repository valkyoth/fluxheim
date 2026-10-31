#!/usr/bin/env python3
"""Bounded local protocol recipes and explicit current-behavior characterizations."""

from contextlib import contextmanager
import http.client
from pathlib import Path
import queue
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time

from smoke_geoip_examples import replace_once
from smoke_tls_examples import generate, exchange, run_case

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples/proxy"
ACCEPT = b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
FRAME = b"\x81\x84\x01\x02\x03\x04" + bytes(a ^ b for a, b in zip(b"ping", b"\x01\x02\x03\x04"))


def prepare(source, port, origin):
    source = replace_once(source, 'listen = ["127.0.0.1:8080"]', f'listen = ["127.0.0.1:{port}"]')
    return replace_once(source, 'upstreams = ["127.0.0.1:9001"]', f'upstreams = ["127.0.0.1:{origin}"]')


def exact(stream, size):
    result = bytearray()
    while len(result) < size:
        chunk = stream.recv(size - len(result))
        if not chunk:
            raise EOFError("fixture connection closed early")
        result.extend(chunk)
    return bytes(result)


def head(stream):
    result = bytearray()
    while not result.endswith(b"\r\n\r\n"):
        assert len(result) < 8192, "fixture head limit"
        result.extend(exact(stream, 1))
    return bytes(result)


def preamble(version, destination):
    if version == "v1":
        return f"PROXY TCP4 198.51.100.20 127.0.0.1 4567 {destination}\r\n".encode()
    return SIGNATURE + b"\x21\x11\x00\x0c" + socket.inet_aton("198.51.100.20") + socket.inet_aton("127.0.0.1") + struct.pack("!HH", 4567, destination)


@contextmanager
def origin_fixture(kind):
    events, failures = queue.Queue(maxsize=16), queue.Queue(maxsize=16)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            try:
                if kind == "v1":
                    prefix = bytearray()
                    while not prefix.endswith(b"\r\n"):
                        assert len(prefix) < 108
                        prefix.extend(exact(self.request, 1))
                    events.put_nowait(bytes(prefix))
                elif kind == "v2":
                    events.put_nowait(exact(self.request, 28))
                request = head(self.request)
                if kind == "websocket":
                    if b" /socket/deny " in request:
                        self.request.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\nConnection: close\r\n\r\ndenied\n')
                        return
                    self.request.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: " + ACCEPT + b"\r\n\r\n")
                    assert exact(self.request, len(FRAME)) == FRAME
                    self.request.sendall(b"\x81\x04pong")
                    events.put_nowait(b"echo")
                else:
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            except Exception as error:
                failures.put_nowait(error)

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1], events
        finally:
            server.shutdown()
            thread.join(timeout=5)
            assert not thread.is_alive()
            if not failures.empty():
                raise failures.get_nowait()


@contextmanager
def gateway(root, source, origin):
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    config = root / "fluxheim.toml"
    config.write_text(prepare(source, port, origin))
    command = [str(ROOT / "target/debug/fluxheim"), "--config", str(config)]
    subprocess.run(command + ["--validate-config"], check=True, timeout=20,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
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


def websocket_request(path):
    return (f"GET {path} HTTP/1.1\r\nHost: app.example.test\r\nConnection: Upgrade\r\n"
            "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").encode()


def main():
    parent = subprocess.check_output(["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")], text=True, timeout=10).strip()
    with tempfile.TemporaryDirectory(prefix="protocol-guides-", dir=parent) as directory:
        root = Path(directory)
        with origin_fixture("websocket") as (origin, events), gateway(root, (EXAMPLES / "websocket.toml").read_text(), origin) as port:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as stream:
                stream.sendall(websocket_request("/socket/echo"))
                response = head(stream)
                assert response.startswith(b"HTTP/1.1 101 ") and ACCEPT in response
                stream.sendall(FRAME)
                assert exact(stream, 6) == b"\x81\x04pong"
                assert events.get(timeout=3) == b"echo"
            with socket.create_connection(("127.0.0.1", port), timeout=3) as stream:
                stream.sendall(websocket_request("/socket/deny"))
                # documented contract: origin rejection is lost rather than forwarded.
                assert stream.recv(1024) == b""
        for version in ("v1", "v2"):
            source = (EXAMPLES / "proxy-protocol.toml").read_text().replace('= "v1"', f'= "{version}"')
            with origin_fixture(version) as (origin, events), gateway(root, source, origin) as port:
                with socket.create_connection(("127.0.0.1", port), timeout=3) as stream:
                    stream.sendall(preamble(version, port) + b"GET / HTTP/1.1\r\nHost: app.example.test\r\nConnection: close\r\n\r\n")
                    response = http.client.HTTPResponse(stream)
                    response.begin()
                    assert response.status == 200 and response.read(3) == b"ok"
                assert events.get(timeout=3) == preamble(version, port)
            untrusted = replace_once(source, 'trusted_proxies = ["127.0.0.1"]', 'trusted_proxies = ["192.0.2.10"]')
            with origin_fixture(version) as (origin, events), gateway(root, untrusted, origin) as port:
                with socket.create_connection(("127.0.0.1", port), timeout=3) as stream:
                    try:
                        stream.sendall(preamble(version, port) + b"GET / HTTP/1.1\r\nHost: app.example.test\r\n\r\n")
                        assert stream.recv(1024) == b""
                    except ConnectionResetError:
                        pass
                assert events.empty(), "untrusted peer contacted origin"
        (root / "site").mkdir()
        (root / "site/index.html").write_bytes(b"tls-guide-ok\n")
        generate(root, "server", ["site.example.test"])
        (root / "server-trust.pem").write_bytes((root / "server.pem").read_bytes())
        source = (ROOT / "examples/tls/static.toml").read_text()
        source = replace_once(source, '[server]', '[server]\ntrusted_proxies = ["192.0.2.10"]\nproxy_protocol = "v1"')
        # documented contract: TLS directly accepts an untrusted peer without a preamble.
        run_case(root, "rustls", "PROXY-on HTTPS currently accepts direct TLS", source,
                 lambda port: exchange(root, port, "site.example.test", ssl.TLSVersion.TLSv1_3, ["http/1.1"]))
    print("protocol guides: WebSocket echo/rejection, PROXY v1/v2 trust/forwarding, HTTPS mismatch: ok")


if __name__ == "__main__":
    main()
