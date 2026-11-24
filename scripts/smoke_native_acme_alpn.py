"""Exercise native background and external ACME clients against real loopback Pebble."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from acme_activation_smoke import assert_served, pinned_tls
from acme_alpn_smoke import config
from acme_pebble_frontend import frontend
from smoke_acme_scope import configuration
from smoke_log_file_rotation import protect_directory


@contextmanager
def running(argv, log, env=None):
    with log.open("ab") as output:
        child = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT, env=env)
        try:
            yield child
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=10)


def wait(child, log, check, timeout=60):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if child.poll() is not None:
            break
        try:
            if check():
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise AssertionError("native fixture failed: " + log.read_text(errors="replace")[-3000:])


def ready(port):
    with socket.create_connection(("127.0.0.1", port), timeout=1):
        return True


def presented(chain, hostname, protocols):
    # A normal browser trusts the installed leaf only. A verification error
    # means a different certificate was presented; a TLS alert means none was.
    context, _ = pinned_tls(chain)
    context.check_hostname = hostname is not None
    context.set_alpn_protocols(protocols)
    with socket.create_connection(("127.0.0.1", 5443), timeout=3) as conn:
        try:
            with context.wrap_socket(conn, server_hostname=hostname):
                return "ordinary"
        except ssl.SSLCertVerificationError:
            return "different"
        except ssl.SSLError:
            return "refused"


def cancellation(root, gateway, companion, settings, chain, paused):
    log = root / "cancel.log"
    conf = root / "cancel.toml"
    conf.write_text(settings.read_text().replace("alpn-external-2", "alpn-cancel")
                    .replace(":14000/dir", ":14000/pause-challenge"))
    only = ["acme-tls/1"]
    with running(gateway, log) as server:
        wait(server, log, lambda: assert_served(5443, chain, "localhost") is None)
        with running([companion[0], "--config", conf, "renew", "--no-reload", "--force-renew"], log) as client:
            wait(client, log, paused.is_set)
            assert presented(chain, "localhost", only) == "different"
            assert presented(chain, "elsewhere.test", only) == "refused"
            assert presented(chain, None, only) == "refused"
            assert presented(chain, "localhost", ["http/1.1", *only]) == "refused"
            assert_served(5443, chain, "localhost")
        wait(server, log, lambda: presented(chain, "localhost", only) == "refused", timeout=5)
        assert_served(5443, chain, "localhost")
    with running(gateway, log) as server:
        wait(server, log, lambda: assert_served(5443, chain, "localhost") is None)
        assert presented(chain, "localhost", only) == "refused"
    print("external cancellation, scoped ALPN/SNI, concurrent browser and clean restart passed", flush=True)


def test_mode(root, bins, suffix, mode, paused):
    storage = root / mode
    if os.name == "nt":
        storage.mkdir()
        protect_directory(storage)
    settings = root / "gateway.toml"
    log = root / (mode + ".log")
    gateway = [bins / ("fluxheim" + suffix), "--config", settings]
    companion = [bins / ("fluxheim-acme" + suffix), "--config", settings]
    state = f'[server.process]\npid_file = "{root.as_posix()}/p"\nupgrade_sock = "{root.as_posix()}/u"\ncertificate_reload_sock = "{root.as_posix()}/r"\n'
    before = None
    for order in (1, 2):
        settings.write_text(config(configuration, mode, order)
            .replace("/var/lib/fluxheim/acme/" + mode, storage.as_posix())
            .replace("/etc/fluxheim/ca.pem", (root / "ca.pem").as_posix())
            .replace('scope.example.test', 'localhost')
            .replace("0.0.0.0:", "127.0.0.1:")
            .replace('["127.0.0.1:5443"]', '["127.0.0.1:5443", "[::1]:5443"]')
            .replace("[tls]\n", state + "[tls]\n"), encoding="utf-8")
        if os.name == "posix" and mode == "external" and order == 1:
            # Running doctor first must leave a private directory, not an active endpoint.
            subprocess.run([*companion, "doctor"], check=True, timeout=30, stdout=subprocess.DEVNULL)
            for path in (storage, storage / ".alpn"):
                info = path.stat()
                assert info.st_uid == os.geteuid() and (info.st_mode & 0o777) == 0o700
            assert not (storage / ".alpn" / "s").exists()
        with running(gateway, log) as child:
            wait(child, log, lambda: ready(5443))
            if mode == "external":
                result = subprocess.run([*companion, "renew", "--no-reload", "--force-renew"],
                                        capture_output=True, text=True, timeout=90)
                if result.returncode or "challenges=1" not in result.stdout:
                    raise AssertionError(result.stdout + result.stderr)

            def installed():
                found = list(storage.glob("certificates/*/fullchain.pem"))
                return len(found) == 1 and found[0].read_text() != before

            wait(child, log, installed)
            chain = next(storage.glob("certificates/*/fullchain.pem")).read_text()
            if mode == "background":
                wait(child, log, lambda: assert_served(5443, chain, "localhost") is None)
        if mode == "external":
            # External installation and ordinary certificate activation are distinct.
            with running(gateway, log) as child:
                wait(child, log, lambda: assert_served(5443, chain, "localhost") is None)
        before = chain
    print(mode + ": Pebble first issuance, new-account renewal and served identities passed", flush=True)
    if mode == "external":
        cancellation(root, gateway, companion, settings, before, paused)


def run(bins, pebble, fixture):
    suffix = ".exe" if os.name == "nt" else ""
    with tempfile.TemporaryDirectory(prefix="fa", dir=None if os.name == "nt" else Path.home()) as name:
        root = Path(name)
        protect_directory(root)
        for file in ("ca.pem", "server.pem", "server.key"):
            shutil.copyfile(fixture / file, root / file)
        options = root / "pebble.json"
        options.write_text(json.dumps({"pebble": {
            "listenAddress": "127.0.0.1:14001", "managementListenAddress": "127.0.0.1:15000",
            "certificate": str(root / "server.pem"), "privateKey": str(root / "server.key"),
            "httpPort": 5002, "tlsPort": 5443,
        }}))
        log = root / "pebble.log"
        paused = threading.Event()
        with running([pebble, "-config", options], log, {
            **os.environ, "PEBBLE_VA_NOSLEEP": "1", "PEBBLE_WFE_NONCEREJECT": "0",
            "PEBBLE_AUTHZREUSE": "0", "PEBBLE_VA_ALWAYS_VALID": "0",
        }) as ca, frontend(root, "127.0.0.1", paused) as adapter:
            wait(ca, log, lambda: ready(14001))
            thread = threading.Thread(target=adapter.serve_forever, daemon=True)
            thread.start()
            try:
                for mode in ("external", "background"):
                    test_mode(root, bins, suffix, mode, paused)
            finally:
                adapter.shutdown()
                thread.join(3)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--pebble", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True, help="Disposable local CA adapter credentials")
    args = parser.parse_args()
    run(args.bin_dir.resolve(strict=True), args.pebble.resolve(strict=True), args.fixture.resolve(strict=True))
