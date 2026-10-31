#!/usr/bin/env python3
"""Run trusted configuration-loading examples and their documented boundaries."""

from contextlib import contextmanager
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import tomllib

from smoke_geoip_examples import replace_once
from smoke_routing_examples import origin, request

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples/configuration"
BINARY = ROOT / "target/debug/fluxheim"


def prepare(source, port):
    document = tomllib.loads(source)
    if document["server"]["listen"] != ["127.0.0.1:8080"]:
        raise ValueError("unexpected configuration guide listener")
    return replace_once(source, 'listen = ["127.0.0.1:8080"]',
                        f'listen = ["127.0.0.1:{port}"]')


def port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def validate(source, *, env=None, expected=True):
    command = [str(BINARY)]
    if source is not None:
        command += ["--config", str(source)]
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(command + ["--validate-config"], timeout=20,
                                env=env, stdin=subprocess.DEVNULL, stdout=output,
                                stderr=subprocess.STDOUT, check=False)
        assert (result.returncode == 0) == expected, "unexpected validation outcome"


@contextmanager
def running(source, public):
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen([str(BINARY), "--config", str(source)],
                                   stdin=subprocess.DEVNULL, stdout=output, stderr=output)
        try:
            deadline = time.monotonic() + 10
            while True:
                assert process.poll() is None, "configuration guide server exited"
                try:
                    with socket.create_connection(("127.0.0.1", public), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AssertionError("configuration guide readiness deadline") from None
                    time.sleep(0.05)
            yield
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def layout_checks(root):
    for folder in ("site", "split/conf.d/site", "split/site"):
        (root / folder).mkdir(parents=True, exist_ok=True)
    for name in ("site/index.html", "split/conf.d/site/index.html", "split/conf.d/10-site.toml"):
        (root / name).write_bytes((EXAMPLES / name).read_bytes())
    # A conflicting root makes incorrect config-relative resolution observable.
    (root / "split/site/index.html").write_bytes(b"wrong-relative-root\n")
    single, split = root / "single.toml", root / "split/fluxheim.toml"
    single_port, split_port = port(), port()
    single.write_text(prepare((EXAMPLES / "single.toml").read_text(), single_port))
    split.write_text(prepare((EXAMPLES / "split/fluxheim.toml").read_text(), split_port))
    (root / "split/.ignored.toml").write_text("not valid TOML")
    (root / "split/conf.d/ignored.toml.bak").write_text("not valid TOML")
    for source, public, body in ((single, single_port, b"configuration-single-ok\n"),
                                 (split, split_port, b"configuration-split-ok\n"),
                                 (split.parent, split_port, b"configuration-split-ok\n")):
        validate(source)
        with running(source, public):
            status, _, actual = request(public, "/", host="configuration.example.test")
            assert (status, actual) == (200, body), "configuration recipe response mismatch"
    environment = dict(os.environ, FLUXHEIM_CONFIG=str(single))
    validate(None, env=environment)
    environment["FLUXHEIM_CONFIG"] = str(root / "missing.toml")
    validate(split, env=environment)
    original = split.read_text()
    split.write_text(replace_once(original, "include_conf_d = true", "include_conf_d = false"))
    validate(split, expected=False)
    validate(split.parent)  # Directory loading includes conf.d irrespective of the flag.
    split.write_text(original)
    invalid = root / "split/conf.d/99-invalid.toml"
    invalid.write_text("misspelled_option = true\n")
    validate(split, expected=False)
    invalid.unlink()
    validate(split)


def limit_fragment_contract(root):
    # documented contract: pin today's behavior; invert after the merge correction.
    directory = root / "limit-contract"
    (directory / "conf.d").mkdir(parents=True)
    public = port()
    with origin() as upstream:
        source = directory / "fluxheim.toml"
        source.write_text(f'''include_conf_d = true
[server]
listen = ["127.0.0.1:{public}"]
[server.limits]
max_request_body_bytes = 4
[server.process]
threads = 1
pid_file = "fluxheim.pid"
upgrade_sock = "upgrade.sock"
certificate_reload_sock = "reload.sock"
[cache]
enabled = false
[proxy]
upstreams = ["127.0.0.1:{upstream}"]
''')
        with running(source, public):
            assert request(public, "/", "POST", b"12345")[0] == 413
        extra = directory / "conf.d/10-headers.toml"
        extra.write_text("[server.limits]\nmax_request_headers = 25\n")
        validate(source)
        with running(source, public):
            assert request(public, "/", "POST", b"12345")[0] == 200
        extra.unlink()
        with running(source, public):
            assert request(public, "/", "POST", b"12345")[0] == 413


def main():
    parent = subprocess.check_output(
        ["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")], text=True, timeout=10,
    ).strip()
    with tempfile.TemporaryDirectory(prefix="configuration-guide-", dir=parent) as temporary:
        root = Path(temporary)
        layout_checks(root)
        limit_fragment_contract(root)
    print("configuration guide: layouts, selection, rejection/recovery and merge contract: ok")


if __name__ == "__main__":
    main()
