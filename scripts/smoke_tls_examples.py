#!/usr/bin/env python3
"""Trusted local binary/guide qualification; not an arbitrary executable sandbox."""

import argparse
import hashlib
import http.client
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time

from smoke_geoip_examples import replace_once

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples/tls"


def generate(root, name, names, client=False):
    command = ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
               "ec_paramgen_curve:P-256", "-nodes", "-sha256", "-days", "1",
               "-subj", f"/CN={names[0]}", "-addext",
               "subjectAltName=" + ",".join(f"DNS:{item}" for item in names),
               "-addext", "basicConstraints=critical,CA:FALSE",
               "-addext", "extendedKeyUsage=" + ("clientAuth" if client else "serverAuth"),
               "-keyout", str(root / f"{name}-key.pem"), "-out", str(root / f"{name}.pem")]
    subprocess.run(command, check=True, timeout=20, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (root / f"{name}-key.pem").chmod(0o600)
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert((root / f"{name}.pem").read_text())).digest()


def exchange(root, port, host, version, protocols, client=None, send_http=True):
    context = ssl.create_default_context(cafile=str(root / "server-trust.pem"))
    context.minimum_version = version
    context.maximum_version = version
    context.set_alpn_protocols(protocols)
    if client:
        context.load_cert_chain(root / f"{client}.pem", root / f"{client}-key.pem")
    with socket.create_connection(("127.0.0.1", port), timeout=3) as tcp:
        with context.wrap_socket(tcp, server_hostname=host) as stream:
            selected = stream.selected_alpn_protocol()
            fingerprint = hashlib.sha256(stream.getpeercert(binary_form=True)).digest()
            if send_http:
                stream.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                response = http.client.HTTPResponse(stream)
                response.begin()
                assert response.status == 200, response.status
                assert response.read(4097) == b"tls-guide-ok\n"
            return selected, fingerprint


def rejected(operation):
    try:
        operation()
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected):
        return
    raise AssertionError("expected TLS/application rejection")


def run_case(root, backend, name, source, checks):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    source = replace_once(source, 'tls_listen = ["127.0.0.1:8443"]',
                          f'tls_listen = ["127.0.0.1:{port}"]')
    source = replace_once(source, 'backend = "rustls"', f'backend = "{backend}"')
    config = root / "fluxheim.toml"
    config.write_text(source)
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
            checks(port)
            print(f"TLS guide: {backend}: {name}: ok")
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("rustls", "openssl"), default="rustls")
    args = parser.parse_args()
    parent = subprocess.check_output(["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")],
                                     text=True, timeout=10).strip()
    with tempfile.TemporaryDirectory(prefix="tls-guide-", dir=parent) as directory:
        root = Path(directory)
        root.chmod(0o700)
        (root / "site").mkdir()
        (root / "site/index.html").write_bytes(b"tls-guide-ok\n")
        default = generate(root, "server", ["site.example.test", "deep.one.api.example.test"])
        api = generate(root, "api", ["api.example.test", "*.api.example.test"])
        generate(root, "client", ["client.example.test"], client=True)
        generate(root, "untrusted", ["untrusted.example.test"], client=True)
        (root / "client-ca.pem").write_bytes((root / "client.pem").read_bytes())
        (root / "server-trust.pem").write_bytes((root / "server.pem").read_bytes() + (root / "api.pem").read_bytes())
        static = (EXAMPLES / "static.toml").read_text()

        def get(port, version=ssl.TLSVersion.TLSv1_3, protocols=("http/1.1",), client=None):
            return exchange(root, port, "site.example.test", version, protocols, client)

        def compatible(port):
            for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                assert get(port, version) == ("http/1.1", default)
            assert get(port, protocols=()) == (None, default)
        run_case(root, args.backend, "intermediate and no-ALPN HTTP", static, compatible)

        def modern(port):
            assert get(port) == ("http/1.1", default)
            rejected(lambda: get(port, ssl.TLSVersion.TLSv1_2))
        run_case(root, args.backend, "modern minimum", replace_once(static, 'profile = "intermediate"', 'profile = "modern"'), modern)

        def h2(port):
            assert exchange(root, port, "site.example.test", ssl.TLSVersion.TLSv1_3, ["h2"], send_http=False) == ("h2", default)
            rejected(lambda: get(port))
            rejected(lambda: get(port, protocols=()))
        run_case(root, args.backend, "HTTP/2-only dispatch", replace_once(static, 'alpn = "http1-and-http2"', 'alpn = "http2"'), h2)

        def sni(port):
            for host, expected in (("site.example.test", default), ("api.example.test", api),
                                   ("one.api.example.test", api), ("deep.one.api.example.test", default)):
                assert exchange(root, port, host, ssl.TLSVersion.TLSv1_3, ["http/1.1"]) == ("http/1.1", expected)
        run_case(root, args.backend, "exact/wildcard/fallback SNI", (EXAMPLES / "sni.toml").read_text(), sni)

        def mtls(port, optional=False):
            assert get(port, client="client") == ("http/1.1", default)
            if optional:
                assert get(port) == ("http/1.1", default)
            else:
                rejected(lambda: get(port))
            rejected(lambda: get(port, client="untrusted"))
        mutual = (EXAMPLES / "mtls.toml").read_text()
        run_case(root, args.backend, "required client authentication", mutual, mtls)
        run_case(root, args.backend, "optional client authentication",
                 replace_once(mutual, 'mode = "required"', 'mode = "optional"'),
                 lambda port: mtls(port, optional=True))


if __name__ == "__main__":
    main()
