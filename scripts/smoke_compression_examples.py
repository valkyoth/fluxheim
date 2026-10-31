#!/usr/bin/env python3
"""Exercise compression recipes against a real binary and bounded loopback origin."""

from contextlib import contextmanager
import gzip
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from smoke_geoip_examples import replace_once

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/compression/local.toml"
BODY = b"public compression guide response\n" * 64


def prepare(source, port, upstream):
    source = replace_once(source, 'listen = ["127.0.0.1:8080"]',
                          f'listen = ["127.0.0.1:{port}"]')
    return replace_once(source, 'upstreams = ["127.0.0.1:9001"]',
                        f'upstreams = ["127.0.0.1:{upstream}"]')


@contextmanager
def origin():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status = 404 if self.path.endswith("/error") else 200
            self.send_response(status)
            mime = "image/png" if self.path.endswith("/image") else "text/plain"
            self.send_header("Content-Type", mime)
            directive = next((value for value in ("private", "no-store", "no-transform")
                              if self.path.endswith("/" + value)), "public, max-age=60")
            self.send_header("Cache-Control", directive)
            self.send_header("ETag", '"origin-tag"')
            if self.path.endswith("/cookie"):
                self.send_header("Set-Cookie", "fixture=1")
            if self.path.endswith("/vary"):
                self.send_header("Vary", "Origin")
            if not self.path.endswith("/unknown-length"):
                self.send_header("Content-Length", str(len(BODY)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(BODY)

        def log_message(self, *_args):
            pass

    class Server(HTTPServer):
        def get_request(self):
            stream, peer = super().get_request()
            stream.settimeout(3)
            return stream, peer

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@contextmanager
def gateway(source, upstream):
    parent = subprocess.check_output(["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")],
                                     text=True, timeout=10).strip()
    with tempfile.TemporaryDirectory(prefix="compression-guide-", dir=parent) as directory:
        root = Path(directory)
        (root / "site").mkdir(mode=0o700)
        (root / "site/asset.txt").write_bytes(BODY)
        (root / "site/small.txt").write_bytes(b"small")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config = root / "fluxheim.toml"
        config.write_text(prepare(source, port, upstream))
        command = [str(ROOT / "target/debug/fluxheim"), "--config", str(config)]
        subprocess.run(command + ["--validate-config"], check=True, timeout=20,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        with tempfile.TemporaryFile() as log:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=log)
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
                yield port
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


def request(port, path, encoding="gzip", extra=None, method="GET"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, headers={"Host": "compress.example.test",
                           "Accept-Encoding": encoding, **(extra or {})})
        response = connection.getresponse()
        body = response.read(8193)
        assert len(body) <= 8192
        headers = {}
        for name, value in response.getheaders():
            name = name.lower()
            headers[name] = headers[name] + ", " + value if name in headers else value
        return response.status, headers, body
    finally:
        connection.close()


def gzip_response(result):
    status, headers, body = result
    assert status == 200 and headers["content-encoding"] == "gzip"
    assert "accept-encoding" in headers["vary"].lower()
    assert "etag" not in headers
    assert int(headers["content-length"]) == len(body)
    with gzip.GzipFile(fileobj=io.BytesIO(body)) as decoder:
        assert decoder.read(len(BODY) + 1) == BODY


def checks(port):
    for path in ("/asset.txt", "/origin/text", "/origin/unknown-length"):
        gzip_response(request(port, path))
    _, headers, _ = request(port, "/origin/vary")
    assert {part.strip().lower() for part in headers["vary"].split(",")} == {"origin", "accept-encoding"}
    for path in ("/plain/asset.txt", "/small.txt", "/origin/private", "/origin/no-store",
                 "/origin/no-transform", "/origin/cookie", "/origin/image", "/origin/error"):
        assert "content-encoding" not in request(port, path)[1], path
    for extra in ({"Cookie": "fixture=1"}, {"Authorization": "Bearer fixture"}, {"Range": "bytes=0-9"}):
        assert "content-encoding" not in request(port, "/asset.txt", extra=extra)[1]
    _, headers, body = request(port, "/asset.txt", method="HEAD")
    assert body == b"" and "content-encoding" not in headers and "vary" not in headers
    for encoding in ("gzip;q=0, *;q=1", "gzip;q=invalid", "gzip;other=1", "gzip,,br"):
        assert "content-encoding" not in request(port, "/asset.txt", encoding)[1]

    # documented contract/002 characterize open gaps, not desired cache/client policy.
    for encoding in ("identity", "gzip;q=0, identity;q=0, *;q=0", "*;q=0"):
        status, headers, body = request(port, "/asset.txt", encoding)
        assert status == 200 and body == BODY and "vary" not in headers
    etag = request(port, "/asset.txt", "identity")[1]["etag"]
    status, headers, _ = request(port, "/asset.txt", extra={"If-None-Match": etag})
    assert status == 304 and "vary" not in headers
    print("compression: gzip roundtrip, scopes, buffered origin, safety exclusions and known gaps: ok")


def main():
    source = EXAMPLE.read_text()
    with origin() as upstream:
        with gateway(source, upstream) as port:
            checks(port)
        all_codecs = replace_once(source, "zstd = false", "zstd = true")
        all_codecs = replace_once(all_codecs, "brotli = false", "brotli = true")
        with gateway(all_codecs, upstream) as port:
            for accept, expected in (("gzip, zstd, br", "br"), ("gzip, zstd", "zstd"),
                                     ("br;q=0.1, zstd;q=0.2, gzip;q=1", "gzip")):
                status, headers, body = request(port, "/asset.txt", accept)
                assert status == 200 and headers["content-encoding"] == expected
                assert 0 < len(body) < len(BODY)
        small_output = replace_once(source, 'min_bytes = "1KiB"', "min_bytes = 1")
        small_output = replace_once(small_output, 'max_output_bytes = "2MiB"', "max_output_bytes = 1")
        with gateway(small_output, upstream) as port:
            status, headers, body = request(port, "/asset.txt", "gzip, identity;q=0")
            assert status == 200 and body == BODY and "content-encoding" not in headers
        print("compression: three-codec wire selection and bounded-output identity fallback: ok")


if __name__ == "__main__":
    main()
