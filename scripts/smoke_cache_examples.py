#!/usr/bin/env python3
"""Exercise checked-in cache guide recipes using the trusted local debug binary."""

import argparse
from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import secrets
import subprocess
import tempfile
import threading
import time

from smoke_log_file_rotation import private_fixture, protect_directory


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples/cache"
BODY = (EXAMPLES / "site/asset.css").read_bytes()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"example no longer contains exactly one {old!r}")
    return text.replace(old, new, 1)


def prepare(public, origin, backend=None, disk_only=False, static=False, operations=False):
    source = (EXAMPLES / ("static.toml" if static else "local.toml")).read_text()
    source = replace_once(source, '"127.0.0.1:8088"', f'"127.0.0.1:{public}"')
    if not static:
        source = replace_once(source, '"127.0.0.1:9001"', f'"127.0.0.1:{origin}"')
    if backend is not None:
        if static or backend not in ("filesystem", "storage-bin"):
            raise ValueError("unsupported guide backend")
        source += "\n" + (EXAMPLES / f"{backend}.toml").read_text()
    if disk_only:
        if backend is None:
            raise ValueError("disk-only recipe requires a disk backend")
        source = replace_once(source, "[cache.memory]\nenabled = true",
                              "[cache.memory]\nenabled = false")
    if operations:
        if static:
            raise ValueError("operations recipe requires a proxy")
        source += "\n" + replace_once((EXAMPLES / "operations.toml").read_text(),
                                    '"127.0.0.1:9001"', f'"127.0.0.1:{origin}"')
    return source


@contextmanager
def origin_server():
    counts = {}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                counts[self.path] = counts.get(self.path, 0) + 1
            self.send_response(200)
            self.send_header("Content-Length", str(len(BODY)))
            self.send_header("Content-Type", "text/css")
            self.send_header("Surrogate-Key", "guide")
            if self.path == "/variant.css":
                self.send_header("Vary", "Accept-Language")
                self.send_header("Content-Language", self.headers.get("Accept-Language", "none"))
            # Like the guide's Python file server, ordinary assets have no TTL.
            # The checked-in status_ttls setting must supply their freshness.
            if self.path == "/private.css":
                self.send_header("Cache-Control", "no-store")
            if self.path == "/cookie.css":
                self.send_header("Set-Cookie", "session=fixture")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(BODY)

        do_HEAD = do_GET

        def log_message(self, *_args):
            pass

    def count(path):
        with lock:
            return counts.get(path, 0)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_address[1], count
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def request(port, path="/asset.css", headers=None, method="GET"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request(method, path, headers={"Host": "cache.test", **(headers or {})})
        response = connection.getresponse()
        payload = response.read(4097)
        assert response.status == 200, (response.status, payload)
        assert payload == (b"" if method == "HEAD" else BODY), payload
        return response.getheader("x-cache-status")
    finally:
        connection.close()


def check_cli_operations(config, public, count, backend, disk_only, operations):
    command = [str(ROOT / "target/debug/fluxheim"), "--config", str(config)]
    tiers = str(int(not disk_only) + int(backend is not None))
    checks = [
        ["cache-key", "--host", "cache.test", "--path", "/asset.css",
         "--expect-eligible", "--expect-scope", "vhost" if operations else "root",
         "--expect-storage-tiers", tiers],
        ["cache-key", "--host", "cache.test", "--path", "/asset.css",
         "--method", "HEAD", "--expect-ineligible"],
    ]
    if backend != "storage-bin":
        for path in ("/asset.css", "/asset.css?v=one", "/asset.css?v=two"):
            checks.append(["cache-lookup", "--host", "cache.test", "--path", path,
                           "--expect-objects", "1" if backend else "0"])
        for language in ("en", "sv"):
            arguments = ["cache-lookup", "--host", "cache.test", "--path", "/variant.css",
                         "--header", f"Accept-Language: {language}",
                         "--expect-objects", "1" if backend else "0"]
            if backend:
                arguments.extend(["--expect-header", f"Content-Language: {language}"])
            checks.append(arguments)
    else:
        result = subprocess.run(command + ["cache-lookup", "--host", "cache.test", "--path", "/asset.css"],
                                capture_output=True, timeout=20, check=False)
        assert result.returncode != 0
        assert b"standalone storage-bin lookup is unsupported" in result.stderr, result.stderr
        # The serving allocator must remain intact after the failed CLI lookup.
        assert request(public) == "HIT"
    for header, reason in (("Authorization: Bearer fixture", "request-authorization"),
                           ("Cookie: session=fixture", "request-header")):
        checks.append(["cache-key", "--host", "cache.test", "--path", "/asset.css",
                       "--header", header, "--expect-ineligible", "--expect-reason", reason])
    checks.append(["cache-key", "--host", "cache.test", "--path", "/asset.css",
                   "--header", "Cache-Control: no-store", "--header", "Cache-Control: public",
                   "--expect-ineligible", "--expect-reason", "request-no-store"])
    counts_before = {path: count(path) for path in ("/asset.css", "/asset.css?v=one", "/asset.css?v=two", "/variant.css")}
    warm = ["cache-warm", "--listen", f"127.0.0.1:{public}", "--host", "cache.test",
            "--path", "/warm.css", "--repeat", "2",
            "--expect-cache-status-sequence", "MISS,HIT"]
    checks.extend([warm + ["--dry-run"], warm])
    for arguments in checks:
        with tempfile.TemporaryFile() as log:
            result = subprocess.run(command + arguments, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=log, timeout=20, check=False)
            if result.returncode:
                log.seek(0)
                raise AssertionError(log.read(8192).decode("utf-8", errors="replace"))
        if "--dry-run" in arguments:
            assert count("/warm.css") == 0
    assert count("/warm.css") == 1
    assert all(count(path) == previous for path, previous in counts_before.items()), "inspection contacted origin"
    assert request(public, "/warm.css", headers={"Host": "cache.test"}) == "HIT"
    assert count("/warm.css") == 1


@contextmanager
def running(config, port):
    with tempfile.TemporaryFile() as log:
        command = [str(ROOT / "target/debug/fluxheim"), "--config", str(config)]
        try:
            subprocess.run(command + ["--validate-config"], check=True, timeout=20,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
        except subprocess.CalledProcessError:
            log.seek(0)
            print(log.read(8192).decode("utf-8", errors="replace"))
            raise
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=log)
        try:
            deadline = time.monotonic() + 20
            while True:
                if process.poll() is not None:
                    raise AssertionError(f"guide server exited {process.returncode}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AssertionError("guide server did not start") from None
                    time.sleep(0.1)
            yield
        except Exception:
            log.seek(0)
            print(log.read(8192).decode("utf-8", errors="replace"))
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def wait_for_storage_index(root, encrypted=False):
    # Windows terminate() does not run Rust destructors. Observe the normal
    # debounced checkpoint before stopping the fixture for a restart test.
    index = root / ".fluxheim-storage-bin-index-v1"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with index.open("rb") as handle:
                contents = handle.read(1024 * 1024)
            if encrypted:
                # Encrypted identities deliberately hide URL keys. All six
                # independently warmed entries must reach the atomic checkpoint.
                lines = contents.splitlines()
                ready = (lines[:1] == [b"FLUXHEIM-STORAGE-BIN-INDEX-v1"]
                         and len(lines) == 7
                         and all(len(line.split(b"\t")) == 5 for line in lines[1:]))
            else:
                ready = b"/asset.css".hex().encode("ascii") in contents
            if ready:
                return
        except (FileNotFoundError, PermissionError):
            # An atomic Windows index replacement temporarily denies sharing.
            # Persistent ACL errors still fail at the bounded deadline.
            pass
        time.sleep(0.05)
    raise AssertionError("storage-bin asset checkpoint did not become visible")


def inspection_configuration(source, named=False, encrypted=False):
    if encrypted:
        source += '''
[cache.disk.encryption]
enabled = true
provider = "local"
algorithm = "aes-256-gcm"
key_id = "inspection-fixture"
key_file = "cache-key"
'''
    if named:
        source = replace_once(source, "[proxy]", '[[vhosts]]\nname = "assets"\nhosts = ["cache.test"]\n\n[vhosts.proxy]')
        source = source.replace("[cache", "[vhosts.cache")
    return source


def run_case(parent, backend=None, disk_only=False, static=False, operations=False,
             named=False, encrypted=False):
    with origin_server() as (origin, count), private_fixture(parent) as directory:
        root = Path(directory)
        for relative in ("state", "state/cache", "site"):
            directory = root / relative
            directory.mkdir()
            protect_directory(directory)
        (root / "site/asset.css").write_bytes(BODY)
        if encrypted:
            key = root / "cache-key"
            key.write_text(secrets.token_hex(32), encoding="ascii")
            key.chmod(0o600)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            public = reservation.getsockname()[1]
        config = root / "fluxheim.toml"
        source = prepare(public, origin, backend, disk_only, static, operations)
        config.write_text(inspection_configuration(source, named, encrypted), encoding="utf-8")
        with running(config, public):
            assert request(public) == "MISS"
            assert request(public) == "HIT"
            if not static:
                assert count("/asset.css") == 1
                assert request(public, method="HEAD") == "BYPASS"
                for headers in ({"Authorization": "Bearer fixture"},
                                {"Proxy-Authorization": "Basic fixture"},
                                {"Cookie": "session=fixture"}):
                    assert request(public, headers=headers) == "BYPASS"
                assert count("/asset.css") == 5
                assert request(public) == "HIT"
                assert count("/asset.css") == 5
                for query in ("one", "two"):
                    path = f"/asset.css?v={query}"
                    assert request(public, path) == "MISS"
                    assert request(public, path) == "HIT"
                    assert count(path) == 1
                for language in ("en", "sv"):
                    assert request(public, "/variant.css", headers={"Accept-Language": language}) == "MISS"
                    assert request(public, "/variant.css", headers={"Accept-Language": language}) == "HIT"
                assert count("/variant.css") == 2
                for path in ("/asset.css?preview=1", "/asset.css?%70review=1"):
                    assert request(public, path) == "BYPASS"
                for path in ("/private.css", "/cookie.css"):
                    for _ in range(2):
                        assert request(public, path) != "HIT"
                    assert count(path) == 2
                check_cli_operations(config, public, count, backend, disk_only, operations or named)
            if backend == "storage-bin":
                wait_for_storage_index(root / "state/cache", encrypted)
        before_restart = count("/asset.css")
        with running(config, public):
            assert request(public) == ("HIT" if backend else "MISS")
            if backend:
                assert count("/asset.css") == before_restart
        mode = "static memory" if static else f"{backend or 'memory'} {'disk-only' if disk_only else 'memory-enabled'}"
        if operations or named:
            mode += " explicit-vhost operations"
        if encrypted:
            mode += " encrypted"
        print(f"cache guide {mode}: ok")


def run_migration(parent):
    with origin_server() as (origin, count), private_fixture(parent) as directory:
        root = Path(directory)
        (root / "state").mkdir()
        protect_directory(root / "state")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            public = reservation.getsockname()[1]
        config = root / "fluxheim.toml"
        retained = {}
        generations = (
            ("filesystem", "state/filesystem", False),
            ("storage-bin", "state/bin-v1", False),
            ("storage-bin", "state/bin-v2", True),
        )
        for expected_fills, (backend, relative, resize) in enumerate(generations, start=1):
            cache_root = root / relative
            cache_root.mkdir()
            protect_directory(cache_root)
            source = replace_once(prepare(public, origin, backend, disk_only=True),
                                  'path = "state/cache"', f'path = "{relative}"')
            if resize:
                source = replace_once(source, 'bin_size_bytes = "1MiB"',
                                      'bin_size_bytes = "2MiB"')
            config.write_text(source, encoding="utf-8")
            with running(config, public):
                assert request(public) == "MISS"
                assert request(public) == "HIT"
                assert count("/asset.css") == expected_fills
                if backend == "storage-bin":
                    wait_for_storage_index(cache_root)
            # Stop/start is deliberate: never bypass a live allocator's lease.
            with running(config, public):
                assert request(public) == "HIT"
                assert count("/asset.css") == expected_fills
            for path, contents in retained.items():
                assert path.read_bytes() == contents, "retired cache file changed"
            if backend == "filesystem":
                objects = list(cache_root.glob("*/*.fhc"))
                assert len(objects) == 1
                retained[objects[0]] = objects[0].read_bytes()
            else:
                for name in (".fluxheim-storage-bin-v1", ".fluxheim-storage-bin-index-v1"):
                    path = cache_root / name
                    retained[path] = path.read_bytes()
        print("cache guide stop/start backend and layout migration: ok")


def run_selection_case(parent):
    with origin_server() as (origin, count), private_fixture(parent) as directory:
        root = Path(directory)
        for relative in ("state", "state/cache"):
            path = root / relative
            path.mkdir()
            protect_directory(path)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            public = reservation.getsockname()[1]
        source = prepare(public, origin, "filesystem", operations=True)
        source = replace_once(source, "[server]", "[server]\nregex_enabled = true")
        for name, matcher, cache in (
            ("regex", 'path_regex = "^/regex/.*"', True),
            ("prefix", 'path_prefix = "/assets"', True),
            ("exact", 'path_exact = "/assets/exact.css"', True),
            ("uncached", 'path_exact = "/assets/uncached.css"', False),
        ):
            source += f'''
[[vhosts.routes]]
name = "{name}"
{matcher}
[vhosts.routes.proxy]
upstream = "127.0.0.1:{origin}"
upstream_tls = false
'''
            if cache:
                source += f'''
[vhosts.routes.cache]
enabled = true
extensions = ["css"]
content_types = ["text/css"]
status_header = "x-cache-status"
status_ttls = {{ "200" = 120 }}
key_namespace = "{name}"
[vhosts.routes.cache.disk]
enabled = true
backend = "filesystem"
path = "state/{name}"
max_size_bytes = "32MiB"
'''
                path = root / "state" / name
                path.mkdir()
                protect_directory(path)
        source += '\n[server.host_routing]\nstrict = true\n'
        config = root / "fluxheim.toml"
        config.write_text(source, encoding="utf-8")
        command = [str(ROOT / "target/debug/fluxheim"), "--config", str(config)]
        def cli(arguments):
            result = subprocess.run(command + arguments, capture_output=True, timeout=20, check=False)
            assert result.returncode == 0, (result.stdout, result.stderr)
        with running(config, public):
            for path, route in (("/asset.css", None), ("/regex/a.css", "regex"),
                                ("/assets/a.css", "prefix"), ("/assets/exact.css", "exact")):
                assert request(public, path) == "MISS"
                assert request(public, path) == "HIT"
                identity = ["--expect-scope", "route" if route else "vhost", "--expect-vhost", "assets"]
                if route:
                    identity += ["--expect-route", route]
                cli(["cache-key", "--host", "cache.test", "--path", path, "--expect-eligible"] + identity)
                cli(["cache-lookup", "--host", "cache.test", "--path", path, "--require-object"] + identity)
                cli(["cache-lookup", "--host", "unknown.test", "--path", path,
                     "--expect-ineligible", "--expect-reason", "no matching vhost", "--expect-objects", "0"])
                assert count(path) == 1, "inspection contacted origin"
            path = "/assets/uncached.css"
            for _ in range(2):
                assert request(public, path) != "HIT"
            cli(["cache-key", "--host", "cache.test", "--path", path,
                 "--expect-ineligible", "--expect-reason", "cache disabled", "--expect-route", "uncached"])
            assert count(path) == 2
        print("cache inspection route precedence, namespace and strict-host isolation: ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work_root", type=Path)
    parent = parser.parse_args().work_root.resolve(strict=True)
    run_case(parent)
    for backend in ("filesystem", "storage-bin"):
        for disk_only in (False, True):
            run_case(parent, backend, disk_only)
    run_case(parent, static=True)
    run_case(parent, backend="filesystem", operations=True)
    for named in (False, True):
        for backend in ("filesystem", "storage-bin"):
            for disk_only in (False, True):
                run_case(parent, backend, disk_only, named=named, encrypted=True)
    run_migration(parent)
    run_selection_case(parent)


if __name__ == "__main__":
    main()
