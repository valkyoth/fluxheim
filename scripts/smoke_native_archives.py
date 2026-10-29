#!/usr/bin/env python3
"""Run the shipped native profiles. This is qualification, not release signing."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import re
import socket
import ssl
import subprocess
import threading

from native_archive import extract_pair, executable
from portable_release_plan import PROFILES, TARGET_LABELS, release_plan
from smoke_log_file_rotation import fixture_parent, private_fixture, request, wait_for, run as rotation
from smoke_operational_events import ROOT, port

COMMON = {"proxy", "acme", "tls_rustls"}
CAPABILITIES = {
    "full": COMMON | {"web", "cache", "load_balancer", "stream", "metrics", "metrics_otlp", "traces_otlp"},
    "wasm": COMMON | {"web", "cache", "load_balancer", "stream", "metrics", "metrics_otlp", "traces_otlp", "wasm"},
    "cache": COMMON | {"cache"},
    "proxy": COMMON,
    "load-balancer": COMMON | {"load_balancer"},
    "php": COMMON | {"web", "php"},
}


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "20")
        self.send_header("Cache-Control", "max-age=120")
        self.send_header("Content-Type", "image/png")
        self.send_header("X-Origin-Port", str(self.server.server_port))
        self.end_headers()
        self.wfile.write(b"native-archive-proof")

    def log_message(self, *_):
        pass


def configuration(root, public, tls, admin, upstream):
    for source, dest in (("localhost-cert.pem", "cert.pem"), ("localhost-key.pem", "key.pem")):
        (root / dest).write_bytes((ROOT / "tests/fixtures/tls" / source).read_bytes())
        (root / dest).chmod(0o600)
    for name, value in (("token", "native-archive-control-token"), ("key", "0123456789abcdef0123456789abcdef")):
        (root / name).write_text(value)
        (root / name).chmod(0o600)
    return f'''[server]
listen = ["127.0.0.1:{public}"]
tls_listen = ["127.0.0.1:{tls}"]
trusted_proxies = ["127.0.0.1"]
[server.process]
threads = 2
pid_file = "fluxheim.pid"
upgrade_sock = "upgrade.sock"
certificate_reload_sock = "reload.sock"
grace_period_seconds = 1
graceful_shutdown_timeout_seconds = 3
[logging]
format = "json"
[logging.access]
enabled = true
[logging.file]
enabled = true
path = "{(root / 'events.log').as_posix()}"
[proxy]
upstreams = ["127.0.0.1:{upstream}"]
[tls]
enabled = true
backend = "rustls"
[[tls.certificates]]
cert_path = "{(root / 'cert.pem').as_posix()}"
key_path = "{(root / 'key.pem').as_posix()}"
[admin]
enabled = true
listen = "127.0.0.1:{admin}"
token_file = "{(root / 'token').as_posix()}"
snapshot_store = "{(root / 'snapshots').as_posix()}"
snapshot_integrity_key_file = "{(root / 'key').as_posix()}"
'''


def exchange(number, context=None, host="localhost", path="/"):
    client = (http.client.HTTPSConnection("localhost", number, context=context, timeout=5)
              if context else http.client.HTTPConnection("127.0.0.1", number, timeout=5))
    try:
        client.request("GET", path, headers={"Host": host, "Connection": "close"})
        response = client.getresponse()
        assert (response.status, response.read(1024)) == (200, b"native-archive-proof")
        return {key.lower(): value for key, value in response.getheaders()}
    finally:
        client.close()


def validate(binary, config, success):
    flags = [] if binary.stem == "fluxheim-config-tester" else ["--validate-config"]
    result = subprocess.run([str(binary), "--config", str(config), *flags],
                            capture_output=True, timeout=20)
    assert (result.returncode == 0) == success, result.stderr.decode(errors="replace")
    return result.stderr.decode(errors="replace")


def live(binary, profile):
    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    second = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    other = threading.Thread(target=second.serve_forever, daemon=True)
    thread.start()
    other.start()
    try:
        with private_fixture(fixture_parent(False)) as root:
            public, tls, admin = port(), port(), port()
            text = configuration(root, public, tls, admin, origin.server_port)
            metrics_port = port()
            if "metrics" not in CAPABILITIES[profile]:
                # Feature-off builds accept shared config, but must not open a listener.
                text += f'\n[metrics]\nenabled = true\nlisten = "127.0.0.1:{metrics_port}"\n'
            if "web" in CAPABILITIES[profile]:
                (root / "index.html").write_text("native-archive-proof")
                text += f'\n[[vhosts]]\nname = "web"\nhosts = ["web.test"]\n[vhosts.web]\nroot = "{root.as_posix()}"\n'
            if "cache" in CAPABILITIES[profile]:
                for tier in ("memory", "disk"):
                    text += f'\n[[vhosts]]\nname = "{tier}"\nhosts = ["{tier}.test"]\n[vhosts.proxy]\nupstreams = ["127.0.0.1:{origin.server_port}"]\n[vhosts.cache]\nenabled = true\nstatus_header = "X-Cache-Status"\nmax_object_bytes = "256KiB"\n[vhosts.cache.{tier}]\nenabled = true\nmax_size_bytes = "4MiB"\n'
                    if tier == "disk":
                        text += f'path = "{(root / "disk-cache").as_posix()}"\n'
            if "load_balancer" in CAPABILITIES[profile]:
                text += f'\n[[vhosts]]\nname = "lb"\nhosts = ["lb.test"]\n[vhosts.proxy]\nupstreams = ["127.0.0.1:{origin.server_port}", "127.0.0.1:{second.server_port}"]\n[vhosts.proxy.load_balance]\nselection = "round-robin"\n'
            config = root / "fluxheim.toml"
            config.write_text(text)
            validate(binary, config, True)
            with (root / "process.log").open("wb") as output:
                command = [str(binary), "--config", str(config)]
                if os.name == "nt":
                    command = ["pwsh.exe", "-NoProfile", "-NonInteractive", "-File",
                               str(ROOT / "scripts/windows_console_signal_helper.ps1"),
                               "-Binary", str(binary), "-Config", str(config)]
                process = subprocess.Popen(command, cwd=root, stdin=subprocess.PIPE,
                                           stdout=output, stderr=output)
                try:
                    def ready():
                        assert process.poll() is None, (root / "process.log").read_text()
                        try:
                            return request(admin, "/_fluxheim/operational-status", "native-archive-control-token")[0] == 200
                        except OSError:
                            return False
                    wait_for(ready)
                    status, body = request(admin, "/_fluxheim/operational-status", "native-archive-control-token")
                    document = json.loads(body)
                    enabled = {name for name, value in document["capabilities"].items() if value}
                    assert enabled == CAPABILITIES[profile], (profile, enabled)
                    if "metrics" not in enabled:
                        try:
                            with socket.create_connection(("127.0.0.1", metrics_port), timeout=5):
                                raise AssertionError("feature-off metrics listener started")
                        except ConnectionRefusedError:
                            pass
                    context = ssl.create_default_context(cafile=str(root / "cert.pem"))
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    with ThreadPoolExecutor(max_workers=4) as pool:
                        list(pool.map(lambda _: exchange(public), range(12)))
                        list(pool.map(lambda _: exchange(tls, context), range(12)))
                    if "web" in enabled:
                        assert "x-origin-port" not in exchange(tls, context, "web.test")
                    if "cache" in enabled:
                        for tier in ("memory", "disk"):
                            first = exchange(public, host=tier + ".test", path="/asset.png")
                            assert first.get("x-cache-status") == "MISS", first
                            wait_for(lambda: exchange(tls, context, tier + ".test", "/asset.png").get("x-cache-status") == "HIT")
                    if "load_balancer" in enabled:
                        observed = {exchange(tls, context, "lb.test").get("x-origin-port") for _ in range(8)}
                        assert observed == {str(origin.server_port), str(second.server_port)}, observed
                finally:
                    stopping = threading.Event()
                    traffic_errors = []
                    def traffic_until_stopped():
                        while not stopping.is_set():
                            try:
                                exchange(public)
                            except (OSError, http.client.HTTPException):
                                stopping.wait(0.01)
                            except AssertionError as error:
                                traffic_errors.append(error)
                                return
                    traffic = threading.Thread(target=traffic_until_stopped, daemon=True)
                    traffic.start()
                    try:
                        if process.poll() is None:
                            if os.name == "nt":
                                process.stdin.write(b"stop\n")
                                process.stdin.flush()
                            else:
                                process.terminate()
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                        raise AssertionError("native server did not stop within deadline")
                    finally:
                        stopping.set()
                        traffic.join(timeout=6)
                        process.stdin.close()
                    assert not traffic.is_alive(), "shutdown traffic worker did not finish"
                    assert not traffic_errors, traffic_errors
                assert process.returncode == 0, (root / "process.log").read_text()
            if profile == "php":
                config.write_text(text + '\n[cache]\nenabled = true\n')
                assert "cache" in validate(binary, config, False).lower()
            else:
                config.write_text(text + f'\n[[vhosts]]\nname = "php.test"\nhosts = ["php.test"]\n[vhosts.php]\nenabled = true\nroot = "{root.as_posix()}"\n[vhosts.php.fpm]\nmode = "external"\ntcp = "127.0.0.1:9000"\nallow_private_tcp_upstreams = true\n')
                assert "php" in validate(binary, config, False).lower()
            return document["platform"]
    finally:
        origin.shutdown()
        second.shutdown()
        origin.server_close()
        second.server_close()
        thread.join(timeout=5)
        other.join(timeout=5)


def run(args):
    label = TARGET_LABELS[args.target]
    host = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}[platform.system()]
    machine = {"AMD64": "x86_64", "arm64": "aarch64"}.get(platform.machine(), platform.machine())
    if label != f"{machine}-{host}":
        raise ValueError("qualification must run on the matching native host")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        raise ValueError("expected full candidate commit")
    rows = release_plan(args.version, host, args.target)
    report = {"commit": args.commit, "version": args.version, "target": args.target,
              "host": platform.platform(), "profiles": {}}
    with private_fixture(fixture_parent(False)) as root:
        for profile, (bundle, _, binaries) in zip(PROFILES, rows):
            tar, zip_ = args.dist / (bundle + ".tar.gz"), args.dist / (bundle + ".zip")
            extracted = extract_pair(tar, zip_, bundle, root / profile)
            identities = {}
            for name in binaries.split(","):
                binary = executable(extracted, name, label)
                result = subprocess.run([str(binary), "--version"], check=True, text=True,
                                        capture_output=True, timeout=20)
                identity = result.stdout.strip()
                if (not identity.startswith(f"fluxheim {args.version} (") or "dirty" in identity
                        or not re.search(r"g" + args.commit[:8] + r"(?:[)-]|$)", identity)):
                    raise ValueError("archive version or commit identity mismatch: " + identity)
                identities[name] = identity
            if profile == "config-tester":
                config = root / "test.toml"
                config.write_text('[server]\nlisten = ["127.0.0.1:8080"]\n[server.process]\n'
                                  f'pid_file = "{(root / "test.pid").as_posix()}"\n'
                                  f'upgrade_sock = "{(root / "u.sock").as_posix()}"\n'
                                  f'certificate_reload_sock = "{(root / "r.sock").as_posix()}"\n')
                validate(binary, config, True)
                config.write_text("not valid = [")
                validate(binary, config, False)
                proof = {"config_validation": True}
            else:
                binary = extracted / ("fluxheim.exe" if host == "windows" else "fluxheim")
                proof = {"platform": live(binary, profile), "http_https": True,
                         "capabilities": True, "unsupported_config": True,
                         "graceful_stop_with_traffic": True,
                         "static_memory_disk_round_robin_when_compiled": True}
                rotation(binary)
                proof["file_rotation"] = True
            checksums = {}
            for archive in (tar, zip_):
                with archive.open("rb") as stream:
                    checksums[archive.name] = hashlib.file_digest(stream, "sha256").hexdigest()
            report["profiles"][profile] = {"checks": proof, "identities": identities, "sha256": checksums}
            print(f"native archive {label} {profile}: ok", flush=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")


def main():
    if not __debug__:
        raise SystemExit("native qualification requires Python assertions")
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--target", choices=TARGET_LABELS, required=True)
    parser.add_argument("--report", type=Path, required=True)
    run(parser.parse_args())


if __name__ == "__main__":
    main()
