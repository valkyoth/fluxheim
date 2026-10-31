#!/usr/bin/env python3
"""Exercise checked-in cache guide recipes using the trusted local debug binary."""

import argparse
from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time


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
         "--expect-eligible" if operations else "--expect-ineligible",
         "--expect-storage-tiers", tiers],
        ["cache-key", "--host", "cache.test", "--path", "/asset.css",
         "--method", "HEAD", "--expect-ineligible"],
        ["cache-lookup", "--host", "cache.test", "--path", "/asset.css",
         "--expect-objects", "1" if backend and operations else "0"],
    ]
    if not operations:
        # Current mismatch, not desired behavior: HTTP fills the root cache,
        # but offline preview refuses it. Keep until documented contract is fixed.
        checks[0].extend(["--expect-reason", "no matching vhost"])
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
    assert request(public, "/warm.css", headers={"Host": "cache.test"}) == "HIT"
    assert count("/warm.css") == 1


@contextmanager
def running(config, port):
    with tempfile.TemporaryFile() as log:
        command = [str(ROOT / "target/debug/fluxheim"), "--config", str(config)]
        subprocess.run(command + ["--validate-config"], check=True, timeout=20,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
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


def run_case(parent, backend=None, disk_only=False, static=False, operations=False):
    with origin_server() as (origin, count), tempfile.TemporaryDirectory(
            prefix="cache-guide-", dir=parent) as directory:
        root = Path(directory)
        (root / "state/cache").mkdir(parents=True, mode=0o700)
        (root / "site").mkdir(mode=0o700)
        (root / "site/asset.css").write_bytes(BODY)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            public = reservation.getsockname()[1]
        config = root / "fluxheim.toml"
        config.write_text(prepare(public, origin, backend, disk_only, static, operations), encoding="utf-8")
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
                for path in ("/asset.css?preview=1", "/asset.css?%70review=1"):
                    assert request(public, path) == "BYPASS"
                for path in ("/private.css", "/cookie.css"):
                    for _ in range(2):
                        assert request(public, path) != "HIT"
                    assert count(path) == 2
                check_cli_operations(config, public, count, backend, disk_only, operations)
        before_restart = count("/asset.css")
        with running(config, public):
            assert request(public) == ("HIT" if backend else "MISS")
            if backend:
                assert count("/asset.css") == before_restart
        mode = "static memory" if static else f"{backend or 'memory'} {'disk-only' if disk_only else 'memory-enabled'}"
        if operations:
            mode += " explicit-vhost operations"
        print(f"cache guide {mode}: ok")


def run_migration(parent):
    with origin_server() as (origin, count), tempfile.TemporaryDirectory(
            prefix="cache-migration-", dir=parent) as directory:
        root = Path(directory)
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
            cache_root.mkdir(parents=True, mode=0o700)
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
    run_migration(parent)


if __name__ == "__main__":
    main()
