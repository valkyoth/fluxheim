#!/usr/bin/env python3
"""Bounded TCP guide qualification against the trusted local Fluxheim binary."""

import argparse
from contextlib import contextmanager
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time

from smoke_geoip_examples import replace_once
from smoke_tls_examples import generate

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/stream/local.toml"


def prepare(source, port, upstream):
    source = replace_once(source, 'listen = ["127.0.0.1:18080"]',
                          f'listen = ["127.0.0.1:{port}"]')
    return replace_once(source, '"127.0.0.1:19001"', f'"127.0.0.1:{upstream}"')


def exact(stream, length):
    result = b""
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            break
        result += part
    return result


@contextmanager
def origin(label=b"", context=None, proxy=0):
    hits = []
    failures = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            stream = self.request
            stream.settimeout(4)
            try:
                if context:
                    stream = context.wrap_socket(stream, server_side=True)
                if proxy == 1:
                    header = b""
                    while len(header) < 108 and not header.endswith(b"\r\n"):
                        part = stream.recv(1)
                        if not part:
                            return
                        header += part
                    hits.append(header)
                elif proxy == 2:
                    header = exact(stream, 16)
                    if len(header) != 16:
                        return
                    size = int.from_bytes(header[14:16], "big")
                    if size > 4096:
                        raise AssertionError("oversized test PROXY header")
                    hits.append(header + exact(stream, size))
                for _ in range(32):
                    data = stream.recv(4096)
                    if not data:
                        return
                    hits.append(data)
                    stream.sendall(label + data)
            except (ssl.SSLError, ConnectionError, TimeoutError):
                # Negative TLS cases and explicit client aborts are intentional.
                pass
            except Exception as error:
                failures.append(error)
            finally:
                if stream is not self.request:
                    stream.close()

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield server.server_address[1], hits
        finally:
            server.shutdown()
            worker.join(timeout=5)
            assert not worker.is_alive()
    assert not failures, failures


@contextmanager
def gateway(root, source, upstream):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config = root / "fluxheim.toml"
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
                    raise AssertionError("stream gateway exited before readiness")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AssertionError("stream readiness deadline") from None
                    time.sleep(0.05)
            # The readiness connection must release its admission slot first.
            time.sleep(0.1)
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


def exchange(port, payload=b"ping", expected=b"ping"):
    with socket.create_connection(("127.0.0.1", port), timeout=4) as stream:
        try:
            stream.sendall(payload)
            stream.shutdown(socket.SHUT_WR)
            received = exact(stream, len(expected) + 1)
        except ConnectionError:
            received = b""
    assert received == expected, (received, expected)


def routing(root, source):
    with origin(b"a:") as (first, _), origin(b"b:") as (second, _):
        with gateway(root, source, first) as port:
            exchange(port, expected=b"a:ping")
        multiple = replace_once(source, 'upstream = "127.0.0.1:19001"',
            f'upstreams = ["127.0.0.1:19001", "127.0.0.1:{second}"]\n'
            'upstream_weights = [2, 1]\nupstream_aliases = ["a", "b"]')
        with gateway(root, multiple, first) as port:
            outcomes = []
            for _ in range(6):
                with socket.create_connection(("127.0.0.1", port), timeout=4) as stream:
                    stream.sendall(b"ping")
                    outcomes.append(exact(stream, 6))
            assert outcomes.count(b"a:ping") == 4 and outcomes.count(b"b:ping") == 2, outcomes
        drained = multiple + f'\ndrain_upstreams = ["127.0.0.1:{first}"]\n'
        with gateway(root, drained, first) as port:
            exchange(port, expected=b"b:ping")
        # A reserved, non-listening socket is a deterministic refused primary.
        with socket.socket() as unavailable:
            unavailable.bind(("127.0.0.1", 0))
            dead = unavailable.getsockname()[1]
            fallback = multiple + f'\nbackup_upstreams = ["127.0.0.1:{second}"]\n'
            with gateway(root, fallback, dead) as port:
                exchange(port, expected=b"b:ping")
    print("streams: forwarding, half-close, weights, drain and refused-primary backup: ok")


def policies(root, source):
    with origin() as (upstream, hits):
        denied = replace_once(source, 'deny_sources = []', 'deny_sources = ["127.0.0.1"]')
        with gateway(root, denied, upstream) as port:
            exchange(port, expected=b"")
        assert not hits
        limited = replace_once(source, "max_connections = 32", "max_connections = 1")
        with gateway(root, limited, upstream) as port:
            with socket.create_connection(("127.0.0.1", port), timeout=4) as held:
                held.sendall(b"held")
                assert exact(held, 4) == b"held"
                exchange(port, expected=b"")
            time.sleep(0.1)
            exchange(port)
        bounded = replace_once(source, "max_connection_bytes = 1048576", "max_connection_bytes = 4")
        with gateway(root, bounded, upstream) as port:
            exchange(port)
            exchange(port, payload=b"large", expected=b"")
        idle = replace_once(source, "idle_timeout_secs = 5", "idle_timeout_secs = 1")
        with gateway(root, idle, upstream) as port:
            with socket.create_connection(("127.0.0.1", port), timeout=4) as stream:
                stream.sendall(b"ping")
                assert exact(stream, 4) == b"ping"
                started = time.monotonic()
                assert stream.recv(1) == b""
                assert 0.5 < time.monotonic() - started < 3
    print("streams: deny precedence, admission/recovery, byte and idle limits: ok")


def proxy_cases(root, source):
    receiving = replace_once(source, 'downstream_proxy_protocol = "off"', 'downstream_proxy_protocol = "v1"')
    receiving = replace_once(receiving, 'trusted_proxies = []', 'trusted_proxies = ["127.0.0.1"]')
    receiving = replace_once(receiving, 'allow_sources = ["127.0.0.1/32"]', 'allow_sources = []')
    receiving = replace_once(receiving, 'deny_sources = []', 'deny_sources = ["192.0.2.0/24"]')
    with origin() as (upstream, _):
        with gateway(root, receiving, upstream) as port:
            exchange(port, b"PROXY TCP4 192.0.2.1 127.0.0.1 5000 80\r\nping", b"")
            # documented contract: no client identity bypasses deny-only source policy.
            exchange(port, b"PROXY UNKNOWN\r\nping")
            # documented contract: raw stream matching does not normalize mapped clients.
            exchange(port, b"PROXY TCP6 ::ffff:192.0.2.1 ::1 5000 80\r\nping")
        positive = replace_once(receiving, 'allow_sources = []', 'allow_sources = ["198.51.100.0/24"]')
        with gateway(root, positive, upstream) as port:
            exchange(port, b"PROXY UNKNOWN\r\nping", b"")
            exchange(port, b"PROXY TCP4 198.51.100.1 127.0.0.1 5000 80\r\nping")
        untrusted = replace_once(receiving, 'trusted_proxies = ["127.0.0.1"]', 'trusted_proxies = ["192.0.2.10"]')
        with gateway(root, untrusted, upstream) as port:
            exchange(port, b"PROXY UNKNOWN\r\nping", b"")
        lifetime = replace_once(receiving, "max_connection_secs = 30", "max_connection_secs = 1")
        with gateway(root, lifetime, upstream) as port:
            with socket.create_connection(("127.0.0.1", port), timeout=4) as stream:
                started = time.monotonic()
                stream.sendall(b"PROXY ")
                time.sleep(1.3)
                stream.sendall(b"UNKNOWN\r\nping")
                assert exact(stream, 4) == b"ping"
                assert time.monotonic() - started > 1
                # The copy-phase cap does eventually close this connection.
                assert stream.recv(1) == b""
    for version in (1, 2):
        sending = replace_once(source, 'upstream_proxy_protocol = "off"', f'upstream_proxy_protocol = "v{version}"')
        with origin(proxy=version) as (upstream, hits), gateway(root, sending, upstream) as port:
            exchange(port)
        headers = [hit for hit in hits if hit != b"ping"]
        assert headers
        if version == 1:
            assert all(header.startswith(b"PROXY TCP4 127.0.0.1 127.0.0.1 ") for header in headers)
        else:
            assert all(header[:12] == b"\r\n\r\n\x00\r\nQUIT\n" and header[12:14] == b"\x21\x11" for header in headers)
    v2 = replace_once(receiving, 'downstream_proxy_protocol = "v1"', 'downstream_proxy_protocol = "v2"')
    signature = b"\r\n\r\n\x00\r\nQUIT\n"
    addresses = socket.inet_aton("198.51.100.1") + socket.inet_aton("127.0.0.1") + struct.pack("!HH", 5000, 80)
    with origin() as (upstream, _), gateway(root, v2, upstream) as port:
        exchange(port, signature + b"\x21\x11\x00\x0c" + addresses + b"ping")
        exchange(port, signature + b"\x20\x00\x00\x00ping")
    print("streams: PROXY v1/v2, unknown/mapped source and copy-only lifetime gaps: reproduced")


def tls_cases(root, source, backend):
    generate(root, "backend", ["backend.example.test"])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(root / "backend.pem", root / "backend-key.pem")
    secured = replace_once(source, "upstream_tls = false", "upstream_tls = true")
    secured += '\nupstream_sni = "backend.example.test"\nupstream_ca_path = "backend.pem"\n'
    with origin(context=context) as (upstream, _):
        with gateway(root, secured, upstream) as port:
            exchange(port)
        wrong = replace_once(secured, 'upstream_sni = "backend.example.test"', 'upstream_sni = "wrong.example.test"')
        with gateway(root, wrong, upstream) as port:
            exchange(port, expected=b"")
        with gateway(root, secured + 'upstream_alternative_cn = "wrong.example.test"\n', upstream) as port:
            exchange(port, expected=b"ping" if backend == "rustls" else b"")
        with gateway(root, wrong + 'upstream_alternative_cn = "backend.example.test"\n', upstream) as port:
            exchange(port, expected=b"" if backend == "rustls" else b"ping")
    generate(root, "client", ["client.example.test"], client=True)
    context.load_verify_locations(cafile=str(root / "client.pem"))
    context.verify_mode = ssl.CERT_REQUIRED
    mutual = secured + 'upstream_client_cert_path = "client.pem"\nupstream_client_key_path = "client-key.pem"\n'
    with origin(context=context) as (upstream, _):
        with gateway(root, secured, upstream) as port:
            exchange(port, expected=b"")
        with gateway(root, mutual, upstream) as port:
            exchange(port)
    print(f"streams: verified TLS/mTLS, wrong identity rejection and {backend} alternative-name contract: ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("rustls", "openssl"), default="rustls")
    args = parser.parse_args()
    parent = subprocess.check_output(["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")], text=True, timeout=10).strip()
    with tempfile.TemporaryDirectory(prefix="stream-guide-", dir=parent) as directory:
        root = Path(directory)
        source = EXAMPLE.read_text()
        routing(root, source)
        policies(root, source)
        proxy_cases(root, source)
        tls_cases(root, source, args.backend)


if __name__ == "__main__":
    main()
