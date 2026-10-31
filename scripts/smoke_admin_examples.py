#!/usr/bin/env python3
"""Check the admin guide using a trusted local binary and private loopback fixtures."""
import argparse
from contextlib import closing, contextmanager
import http.client
import os
from pathlib import Path
import socket
import stat
import subprocess
import time

from smoke_log_file_rotation import fixture_parent, private_fixture
from smoke_logging_examples import replace_once
from smoke_operational_events import ROOT, port

EXAMPLE = ROOT / "examples/admin/local.toml"
CONTROL = "admin-guide-control-private-canary"
OBSERVER = "admin-guide-observer-private-canary"
ROTATED = "admin-guide-replaced-private-canary"
STATUS = "/_fluxheim/operational-status"
MAX_RESPONSE = 1024 * 1024


def request(admin, path=STATUS, token=None, method="GET", *, unix=None, headers=None):
    with closing(http.client.HTTPConnection("127.0.0.1", admin, timeout=2)) as client:
        if unix is not None:
            client.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.sock.settimeout(2)
            client.sock.connect(str(unix))
        fields = {"Host": "admin.example.test", "Connection": "close"}
        if token is not None:
            fields["Authorization"] = f"Bearer {token}"
        fields.update(headers or {})
        client.request(method, path, headers=fields)
        response = client.getresponse()
        body = response.read(MAX_RESPONSE + 1)
        assert len(body) <= MAX_RESPONSE, "admin fixture response exceeded bound"
        assert all(secret.encode() not in body for secret in (CONTROL, OBSERVER, ROTATED))
        return response.status, dict(response.getheaders()), body


@contextmanager
def server(binary, root, source, public, *, rejected=False):
    config = root / "fluxheim.toml"
    config.write_text(source)
    env = {name: value for name, value in os.environ.items()
           if name.casefold() not in {"rust_log", "fluxheim_config"}}
    log = root / "process.log"
    with log.open("wb") as output:
        child = subprocess.Popen([str(binary), "--config", str(config)], cwd=root,
                                 env=env, stdout=output, stderr=output)
        try:
            if rejected:
                assert child.wait(timeout=15) != 0, "unsafe observer token unexpectedly accepted"
                assert any(message in log.read_bytes() for message in (
                    b"confidential file has untrusted permissions",
                    b"file has an untrusted owner, symlink, or writable path component",
                )), "unexpected startup failure"
            else:
                deadline = time.monotonic() + 15
                while True:
                    assert child.poll() is None, "admin guide server exited before readiness"
                    try:
                        assert request(public, "/")[2] == b"ready"
                        break
                    except ConnectionRefusedError:
                        assert time.monotonic() < deadline, "admin guide startup timed out"
                        time.sleep(0.05)
            yield
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
    contents = log.read_bytes()
    assert all(secret.encode() not in contents for secret in (CONTROL, OBSERVER, ROTATED))


def exercise(binary):
    with private_fixture(fixture_parent(False)) as root:
        (root / "public").mkdir()
        (root / "public/index.html").write_text("ready")
        for name, value in (("control-token", CONTROL), ("observer-token", OBSERVER),
                            ("snapshot-integrity.key", "0123456789abcdef0123456789abcdef")):
            (root / name).write_text(value)
            (root / name).chmod(0o600)
        public, admin = port(), port()
        while admin == public:
            admin = port()
        source = replace_once(EXAMPLE.read_text(), "127.0.0.1:8080", f"127.0.0.1:{public}")
        source = replace_once(source, "127.0.0.1:9090", f"127.0.0.1:{admin}")
        unix = root / "ops.sock" if os.name == "posix" else None
        if unix is not None:
            source += '\n[admin.ops_socket]\nenabled = true\npath = "ops.sock"\nmode = "0660"\nrequire_bearer_token = false\n'
        with server(binary, root, source, public):
            assert request(admin)[0] == 401
            for token in (CONTROL, OBSERVER):
                status, headers, _ = request(admin, token=token)
                assert status == 200
                assert {key.lower(): value for key, value in headers.items()}["cache-control"] == "no-store"
            for route, method in (("status", "GET"), ("snapshots", "GET"),
                                  ("reload", "POST"), ("health", "GET")):
                assert request(admin, "/_fluxheim/" + route, OBSERVER, method)[0] == 403
            assert request(admin, token=CONTROL, method="POST")[0] == 405
            assert request(admin, STATUS + "/", CONTROL)[0] == 404
            assert request(admin, STATUS + "?query=ignored", CONTROL)[0] == 400
            assert request(admin, "/_fluxheim/health", CONTROL)[2] == b'{"status":"ok"}'
            if unix is not None:
                # documented contract: accepted 0660 is ignored; invert with the follow-up.
                assert stat.S_IMODE(unix.stat().st_mode) == 0o600
                assert request(admin, "/_fluxheim/status", unix=unix)[0] == 200
                assert request(admin, "/_fluxheim/status", OBSERVER, unix=unix)[0] == 200
                assert request(admin, unix=unix)[0] == 401
                assert request(admin, token=OBSERVER, unix=unix)[0] == 200
                assert request(admin, "/_fluxheim/snapshots", unix=unix)[0] == 401
                assert request(admin, "/_fluxheim/reload", CONTROL, "POST", unix=unix)[0] == 404
            (root / "control-token").write_text(ROTATED)
            assert request(admin, token=CONTROL)[0] == 200
            assert request(admin, token=ROTATED)[0] == 401

        public_health = replace_once(source, "unauthenticated = false", "unauthenticated = true")
        public_health = replace_once(public_health, 'response = "status"', 'response = "minimal"')
        if unix is not None:
            public_health = replace_once(public_health, "require_bearer_token = false", "require_bearer_token = true")
        with server(binary, root, public_health, public):
            assert request(admin, token=CONTROL)[0] == 401
            assert request(admin, token=ROTATED)[0] == 200
            assert request(admin, "/_fluxheim/health")[0] == 204
            assert request(admin, "/_fluxheim/health", method="POST")[0] == 405
            if unix is not None:
                assert request(admin, "/_fluxheim/status", unix=unix)[0] == 401
                assert request(admin, "/_fluxheim/status", OBSERVER, unix=unix)[0] == 403
                assert request(admin, "/_fluxheim/status", ROTATED, unix=unix)[0] == 200

        # This is a header-policy test, not a real TLS client-certificate handshake.
        assertion = source + '\n[admin.client_certificate]\nrequired = true\nallow_sha256 = ["' + "a" * 64 + '"]\n'
        with server(binary, root, assertion, public):
            assert request(admin, token=ROTATED)[0] == 403
            assert request(admin, token=ROTATED, headers={"x-client-cert-sha256": "a" * 64})[0] == 200
            assert request(admin, token=OBSERVER, headers={"x-client-cert-sha256": "A" * 64})[0] == 200
            assert request(admin, token=ROTATED, headers={"x-client-cert-sha256": "b" * 64})[0] == 403

        if os.name == "posix":
            for mode in (0o644, 0o660):
                # documented contract: invert control acceptance with the follow-up.
                (root / "control-token").chmod(mode)
                with server(binary, root, source, public):
                    assert request(admin, token=ROTATED)[0] == 200
                (root / "control-token").chmod(0o600)
                (root / "observer-token").chmod(mode)
                with server(binary, root, source, public, rejected=True):
                    pass
                (root / "observer-token").chmod(0o600)
    print("admin guide: roles, transport, methods, restart and assertion checks passed")
    if os.name == "posix":
        print("documented contract/002: socket mode and control-token permission gaps characterized")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    exercise(parser.parse_args().binary.resolve(strict=True))
