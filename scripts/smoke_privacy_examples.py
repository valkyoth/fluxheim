#!/usr/bin/env python3
"""Qualify privacy documentation with synthetic data and a trusted privacy binary."""
import argparse
from contextlib import closing
import http.client
import json
from pathlib import Path
import socket
import ssl

from smoke_admin_examples import request, server, CONTROL
from smoke_cli_examples import invoke
from smoke_log_file_rotation import fixture_parent, private_fixture, wait_for
from smoke_logging_examples import replace_once
from smoke_operational_events import ROOT, port
from smoke_request_headers import origin
from smoke_tls_examples import generate

EXAMPLE = ROOT / "examples/privacy/local.toml"
STRIPPED = (
    "x-forwarded-for", "x-real-ip", "forwarded", "x-forwarded-host", "x-forwarded-proto",
    "cf-connecting-ip", "true-client-ip", "x-client-ip", "client-ip", "x-cluster-client-ip",
    "fastly-client-ip", "x-envoy-external-address", "x-original-forwarded-for", "x-azure-clientip",
    "fly-client-ip", "x-proxyuser-ip", "x-forwarded-client-cert",
)
CANARY = "privacy-guide-request-canary"


def check_log(path):
    with path.open("rb") as stream:
        content = stream.read(1024 * 1024 + 1)
    assert len(content) <= 1024 * 1024, "privacy fixture log exceeded bound"
    assert CANARY.encode() not in content, "request canary reached process output"
    records = [json.loads(line) for line in content.decode().splitlines() if line.startswith("{")]
    assert not any(record.get("data", {}).get("kind") == "access" for record in records)
    return records


def proxy_exchange(public, *, context=None, remove_diagnostics=False):
    connection = (http.client.HTTPSConnection("localhost", public, timeout=3, context=context)
                  if context else http.client.HTTPConnection("127.0.0.1", public, timeout=3))
    fields = {name: CANARY for name in STRIPPED}
    fields.update({"Host": "app.example.test", "Cookie": "session=" + CANARY,
                   "Authorization": "Bearer " + CANARY, "User-Agent": CANARY,
                   "X-Request-ID": CANARY, "X-Correlation-ID": CANARY,
                   "Referer": CANARY, "X-Custom-Identity": CANARY,
                   "traceparent": "00-" + "a" * 32 + "-" + "b" * 16 + "-01",
                   "tracestate": "vendor=" + CANARY, "baggage": "identity=" + CANARY})
    with closing(connection) as client:
        client.request("GET", "/" + CANARY + "?id=" + CANARY, headers=fields)
        response = client.getresponse()
        body = response.read(8193)
        assert response.status == 200 and len(body) <= 8192
        assert not any(name.lower() in ("x-request-id", "x-correlation-id")
                       for name, _ in response.getheaders())
    payload = json.loads(body)
    assert payload["path"] == "/" + CANARY + "?id=" + CANARY
    headers = payload["headers"]
    for name in (*STRIPPED, "traceparent", "tracestate", "baggage", "x-peer"):
        assert name not in headers, "unexpected privacy forwarding"
    for name in ("user-agent", "x-custom-identity"):
        assert headers[name] == [CANARY], "ordinary application header was unexpectedly anonymized"
    for name in ("x-request-id", "x-correlation-id", "referer"):
        if remove_diagnostics:
            assert name not in headers, "explicit removal did not take effect"
        else:
            assert headers[name] == [CANARY], "ordinary diagnostic header unexpectedly removed"
    assert headers["cookie"] == ["session=" + CANARY]
    assert headers["authorization"] == ["Bearer " + CANARY]


def run(binary, tls=False):
    with private_fixture(fixture_parent(False)) as root, origin() as upstream:
        (root / "public").mkdir()
        (root / "public/index.html").write_text("ready")
        public = port()
        source = replace_once(EXAMPLE.read_text(), "127.0.0.1:8080", f"127.0.0.1:{public}")
        source = replace_once(source, "127.0.0.1:3000", f"127.0.0.1:{upstream}")
        config = root / "check.toml"
        config.write_text(source)
        invoke(binary, root, "--config", config, "--validate-config")
        for changed, marker in (
            (replace_once(source, "[logging.access]\nenabled = false", "[logging.access]\nenabled = true"), "privacy-mode"),
            (replace_once(source, "[logging.file]\nenabled = false", ' [logging.file]\nenabled = true\npath = "forbidden.log"'), "privacy-mode"),
            (replace_once(source, '[logging]\n', '[logging]\ncrash_file = "forbidden-crash.log"\n'), "privacy-mode"),
            (replace_once(source, "[tracing]\nenabled = false", "[tracing]\nenabled = true"), "otel-tracing feature"),
            (replace_once(source, "[cache]\nenabled = false", "[cache]\nenabled = true\n[cache.memory]\nenabled = true"), "cache module not compiled"),
            (source + "\n[privacy]\nenabled = true\n", "unknown field"),
        ):
            config.write_text(changed)
            _, error = invoke(binary, root, "--config", config, "--validate-config", success=False)
            assert marker in error, f"unexpected validation rejection (expected {marker})"
        assert not (root / "forbidden.log").exists()
        assert not (root / "forbidden-crash.log").exists()

        # Privacy stripping survives a disabled policy and attempted re-addition.
        for policy, remove in (("", False),
                       ('\n[vhosts.headers.request]\nenabled = false\nstrip_inbound_client_ip_headers = false\n', False),
                       ('\n[vhosts.headers.request]\nenabled = true\nx_forwarded_for = "append"\nx_real_ip = true\nforwarded = true\n'
                        '[vhosts.headers.request.set]\nx-real-ip = "attempted-addition"\nx-peer = "{remote_addr}"\n', False),
                       ('\n[vhosts.headers.request]\nenabled = true\nunset = ["x-request-id", "x-correlation-id", "referer"]\n', True)):
            with server(binary, root, source + policy, public):
                status, headers, body = request(public, "/", headers={"Host": "private.example.test"})
                assert status == 200 and body == b"ready"
                assert {key.lower(): value for key, value in headers.items()}["cache-control"] == "no-store"
                proxy_exchange(public, remove_diagnostics=remove)
            check_log(root / "process.log")

        if tls:
            generate(root, "server", ["localhost"])
            secure = port()
            while secure == public:
                secure = port()
            secure_source = replace_once(source, "[server]\n", f'[server]\ntls_listen = ["127.0.0.1:{secure}"]\n')
            secure_source += '''
[vhosts.tls]
enabled = true
[vhosts.tls.certificate]
cert_path = "server.pem"
key_path = "server-key.pem"
[tls]
enabled = true
backend = "rustls"
[[tls.certificates]]
cert_path = "server.pem"
key_path = "server-key.pem"
'''
            context = ssl.create_default_context(cafile=str(root / "server.pem"))
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            with server(binary, root, secure_source, public):
                proxy_exchange(secure, context=context)
            check_log(root / "process.log")

        # documented contract: a missing metrics feature is silently accepted by the main binary.
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            metrics_port = reservation.getsockname()[1]
            metrics_source = replace_once(source, "[metrics]\nenabled = false",
                                           f'[metrics]\nenabled = true\nlisten = "127.0.0.1:{metrics_port}"')
            config.write_text(metrics_source)
            invoke(binary, root, "--config", config, "--validate-config")
            # The port is reserved but not listening: startup can only succeed if it skips metrics.
            with server(binary, root, metrics_source, public):
                try:
                    connection = socket.create_connection(("127.0.0.1", metrics_port), timeout=1)
                except ConnectionRefusedError:
                    pass
                else:
                    connection.close()
                    raise AssertionError("unexpected metrics listener")

        # Admin and local snapshot operations are opt-in, not removed by this profile.
        admin = port()
        while admin == public:
            admin = port()
        (root / "control-token").write_text(CONTROL)
        (root / "control-token").chmod(0o600)
        admin_source = replace_once(source, "[admin]\nenabled = false", f'''[admin]
enabled = true
listen = "127.0.0.1:{admin}"
token_file = "control-token"
snapshot_store = "snapshots"''')
        with server(binary, root, admin_source, public):
            status, _, body = request(admin, token=CONTROL)
            assert status == 200 and b'"privacy_mode":true' in body
            assert request(admin, "/_fluxheim/snapshot", CONTROL, "POST")[0] == 201
            wait_for(lambda: b'"kind":"audit"' in (root / "process.log").read_bytes())
        assert (root / "snapshots/current").is_file()
        records = check_log(root / "process.log")
        audits = [record for record in records if record.get("data", {}).get("kind") == "audit"]
        assert audits and all(not record.get("correlation") and "resource" not in record for record in audits)
    print("Privacy guide: static/proxy, header boundaries, rejection and opt-in audit checks passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--tls", action="store_true", help="Also test verified TLS; requires OpenSSL")
    args = parser.parse_args()
    run(args.binary.resolve(strict=True), args.tls)
