#!/usr/bin/env python3
"""Local access-policy proof using real HTTP and verified TLS connections."""

import http.client
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile

from smoke_cors_examples import gateway, origin, request
from smoke_geoip_examples import replace_once
from smoke_tls_examples import generate, rejected, run_case

ROOT = Path(__file__).resolve().parents[1]
IP_EXAMPLE = ROOT / "examples/access/ip.toml"
TLS_EXAMPLE = ROOT / "examples/access/mtls.toml"


def expect(port, hits, status, method="GET", path="/", extra=None):
    before = len(hits)
    actual, _, _ = request(port, method, path, origin_value=None, extra=extra)
    assert actual == status, (method, path, actual, status)
    assert len(hits) == before + (status == 200), (path, hits[before:])


def ip_checks():
    source = IP_EXAMPLE.read_text()
    with origin() as (upstream, hits):
        with gateway(source, upstream) as port:
            expect(port, hits, 200)
            expect(port, hits, 200, path="/administrator")
            for path in ("/admin", "/admin/secret", "/%61dmin", "/%61dmin/secret"):
                for method in ("GET", "POST", "HEAD", "OPTIONS"):
                    expect(port, hits, 403, method, path)
            expect(port, hits, 403, path="/admin", extra={"X-Forwarded-For": "192.0.2.10"})
        disabled = replace_once(source, '[vhosts.routes.access]', '[vhosts.routes.access]\nenabled = false')
        with gateway(disabled, upstream) as port:
            expect(port, hits, 200, path="/admin")
        denied = replace_once(disabled, "deny = []", 'deny = ["127.0.0.1"]')
        with gateway(denied, upstream) as port:
            expect(port, hits, 403)
            expect(port, hits, 403, path="/admin")
        # documented contract: exact mapped IP works, its equivalent /128 CIDR does not.
        exact_mapped = replace_once(source, "deny = []", 'deny = ["::ffff:127.0.0.1"]')
        with gateway(exact_mapped, upstream) as port:
            expect(port, hits, 403)
        mapped_cidr = replace_once(source, "deny = []", 'deny = ["::ffff:127.0.0.1/128"]')
        with gateway(mapped_cidr, upstream) as port:
            expect(port, hits, 200)
        # Only a loopback fixture may assert the documentation client address.
        trusted = replace_once(source, "trusted_proxies = []", 'trusted_proxies = ["127.0.0.1"]')
        trusted = replace_once(trusted, 'allow = ["127.0.0.1/32", "::1/128"]', 'allow = ["192.0.2.10"]')
        with gateway(trusted, upstream) as port:
            expect(port, hits, 403, path="/admin")
            expect(port, hits, 200, path="/admin", extra={"X-Forwarded-For": "192.0.2.10"})
            expect(port, hits, 403, path="/admin", extra={"X-Forwarded-For": "192.0.2.10, broken"})
        cert = replace_once(source, "deny = []", "deny = []\nrequire_client_cert = true")
        with gateway(cert, upstream) as port:
            expect(port, hits, 403, extra={"X-Forwarded-Client-Cert": "ab" * 32})
        # A method filter limits route selection, not the fallback's methods.
        filtered = replace_once(source, 'path_prefix = "/admin"', 'path_prefix = "/admin"\nmethods = ["GET"]')
        with gateway(filtered, upstream) as port:
            expect(port, hits, 403, path="/admin")
            expect(port, hits, 200, method="POST", path="/admin")
        # A more-specific route is independent, not an ACL child of a prefix route.
        nested = source + '\n[[vhosts.routes]]\nname = "health"\npath_exact = "/admin/health"\n' \
            '[vhosts.routes.redirect]\nto = "https://api.example.test/health"\nstatus = 302\n'
        with gateway(nested, upstream) as port:
            expect(port, hits, 302, path="/admin/health")
            expect(port, hits, 403, path="/admin/secret")
    print("access guide: IP precedence, scopes, methods, encoded policy, trusted peer and spoof rejection: ok")


def tls_status(root, port, client=None):
    context = ssl.create_default_context(cafile=str(root / "server.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    if client:
        context.load_cert_chain(root / f"{client}.pem", root / f"{client}-key.pem")
    with socket.create_connection(("127.0.0.1", port), timeout=3) as tcp:
        with context.wrap_socket(tcp, server_hostname="site.example.test") as stream:
            stream.sendall(b"GET / HTTP/1.1\r\nHost: site.example.test\r\nConnection: close\r\n\r\n")
            response = http.client.HTTPResponse(stream)
            response.begin()
            assert len(response.read(4097)) <= 4096
            return response.status


def tls_checks():
    parent = subprocess.check_output(["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")],
                                     text=True, timeout=10).strip()
    with tempfile.TemporaryDirectory(prefix="acl-guide-", dir=parent) as directory:
        root = Path(directory)
        root.chmod(0o700)
        (root / "site").mkdir()
        (root / "site/index.html").write_text("access guide\n")
        generate(root, "server", ["site.example.test"])
        allowed = generate(root, "client", ["client.example.test"], client=True).hex()
        generate(root, "other", ["other.example.test"], client=True)
        generate(root, "untrusted", ["untrusted.example.test"], client=True)
        (root / "client-ca.pem").write_bytes((root / "client.pem").read_bytes() + (root / "other.pem").read_bytes())
        source = replace_once(TLS_EXAMPLE.read_text(), "0" * 64, allowed.upper())

        def pinned(port):
            assert tls_status(root, port, "client") == 200
            assert tls_status(root, port, "other") == 403
            assert tls_status(root, port) == 403
            rejected(lambda: tls_status(root, port, "untrusted"))
        run_case(root, "rustls", "verified client fingerprint allowlist", source, pinned)
        no_require = replace_once(source, "require_client_cert = true", "require_client_cert = false")
        run_case(root, "rustls", "allowlist alone rejects missing identity", no_require, pinned)
        both = replace_once(source, '[vhosts.access]',
                            f'[vhosts.access]\ndeny_client_cert_sha256 = ["{allowed}"]')

        def denied(port):
            assert tls_status(root, port, "client") == 403
        run_case(root, "rustls", "deny wins over allow", both, denied)
        deny_only = replace_once(no_require, "allow_client_cert_sha256", "deny_client_cert_sha256")

        def optional(port):
            assert tls_status(root, port) == 200
            assert tls_status(root, port, "other") == 200
            assert tls_status(root, port, "client") == 403
        run_case(root, "rustls", "denylist alone permits absent certificates", deny_only, optional)


def main():
    ip_checks()
    tls_checks()


if __name__ == "__main__":
    main()
