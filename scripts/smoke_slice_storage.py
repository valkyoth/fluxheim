#!/usr/bin/env python3
"""Real slice persistence checks using a trusted binary or non-root local image."""

import argparse
from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import tempfile
import threading

import smoke_cache_examples as cache
import smoke_load_balancer_tcp_health as runner


@contextmanager
def origin():
    calls = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            # This origin has exactly two fixture representations. Never reflect
            # request header text (including obsolete line folding) into ETags.
            language = "en" if self.headers.get("Accept-Language", "en") == "en" else "sv"
            body = b"01234567" if language == "en" else b"abcdefgh"
            requested = self.headers.get("Range")
            with lock:
                calls.append((language, requested))
            start, end = 0, len(body) - 1
            if requested:
                start, end = map(int, requested.removeprefix("bytes=").split("-"))
            self.send_response(206 if requested else 200)
            self.send_header("Content-Type", "text/css")
            self.send_header("Cache-Control", "max-age=120")
            self.send_header("ETag", '"en-v1"' if language == "en" else '"sv-v1"')
            self.send_header("Vary", "Accept-Language")
            if requested:
                self.send_header("Content-Range", f"bytes {start}-{end}/{len(body)}")
            body = body[start:end + 1]
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    def count():
        with lock:
            return len(calls)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_address[1], count
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()


def configuration(public, upstream, backend, disk_only, guest):
    source = cache.prepare(public, upstream, backend, disk_only)
    source = cache.replace_once(source, "[cache]\n", '[cache]\nvary_request_headers = ["accept-language"]\n')
    source += '\n[cache.range]\nenabled = true\nmax_bytes = 8\n[cache.range.slice]\nenabled = true\nsize_bytes = 4\nmax_slices = 2\n'
    if guest:
        for name in ("fluxheim.pid", "upgrade.sock", "reload.sock"):
            source = cache.replace_once(source, f'"{name}"', f'"/run/fluxheim/{name}"')
        if backend:
            source = cache.replace_once(source, '"state/cache"', '"/var/cache/fluxheim/slices"')
    return source


def request(port, language, ranged=True):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Host": "cache.test", "Accept-Language": language}
    if ranged:
        headers["Range"] = "bytes=2-5"
    try:
        connection.request("GET", "/asset.css", headers=headers)
        response = connection.getresponse()
        body = response.read(4097)
        expected = b"01234567" if language == "en" else b"abcdefgh"
        assert response.status == (206 if ranged else 200), (response.status, body)
        assert body == (expected[2:6] if ranged else expected), body
        return response.getheader("x-cache-status"), response.getheader("x-cache-reason")
    finally:
        connection.close()


def warm(public, count):
    for language in ("en", "sv"):
        assert request(public, language) == ("MISS", "slice-fill")
        assert request(public, language) == ("HIT", "slice")
    assert count() == 4, "expected exactly two slices per representation"


def recovered(public, count, backend):
    for language in ("en", "sv"):
        expected = ("HIT", "slice") if backend else ("MISS", "slice-fill")
        assert request(public, language) == expected
    assert count() == (4 if backend else 8), "restart did not reuse disk slices"
    # A full GET must not accidentally return the stored 206 fragment.
    for language in ("en", "sv"):
        assert request(public, language, ranged=False)[0] == "MISS"
        assert request(public, language, ranged=False)[0] == "HIT"
    assert count() == (6 if backend else 10)


def run_case(parent, backend, disk_only, digest):
    with origin() as (upstream, count), cache.private_fixture(None if os.name == "nt" else parent) as directory:
        root = Path(directory)
        for path in (root / "state", root / "state/cache"):
            path.mkdir()
            cache.protect_directory(path)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            public = reservation.getsockname()[1]
        config = root / "fluxheim.toml"
        config.write_text(configuration(public, upstream, backend, disk_only, digest is not None), encoding="utf-8")
        with tempfile.TemporaryFile() as log:
            try:
                with runner.server(config, log, digest) as process:
                    runner.smoke.wait_for(process, lambda: runner.smoke.listener_ready(public), "slice listener")
                    warm(public, count)
                    if digest:
                        # Keep the same container's private writable layer, not a
                        # writable host mount. Restart still loses all process memory.
                        runner.container.engine("restart", "--time", "15", process.name)
                        runner.smoke.wait_for(process, lambda: runner.smoke.listener_ready(public), "slice restart")
                        recovered(public, count, backend)
                    elif backend == "storage-bin":
                        cache.wait_for_storage_index(root / "state/cache")
                if digest is None:
                    with runner.server(config, log, None) as process:
                        runner.smoke.wait_for(process, lambda: runner.smoke.listener_ready(public), "slice restart")
                        recovered(public, count, backend)
            except Exception:
                log.seek(0)
                print(log.read(8192).decode("utf-8", errors="replace"))
                raise
    print(f"slice storage {backend or 'memory'}, disk_only={disk_only}, {'container' if digest else 'native'}: ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work_root", type=Path)
    parser.add_argument("--container", action="store_true")
    args = parser.parse_args()
    digest = None
    if args.container:
        assert runner.container.engine("info", "--format", "{{.Host.Security.Rootless}}") == "true"
        image = json.loads(runner.container.engine("image", "inspect", "localhost/fluxheim:slice-storage-smoke"))[0]
        assert image["Config"]["User"] == "65532:65532"
        digest = image["Id"]
    root = args.work_root.resolve(strict=True)
    run_case(root, None, False, digest)
    for backend in ("filesystem", "storage-bin"):
        for disk_only in (False, True):
            run_case(root, backend, disk_only, digest)
    if digest:
        print(f"slice storage container identity: {digest}")


if __name__ == "__main__":
    main()
