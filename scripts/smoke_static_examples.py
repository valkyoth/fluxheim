#!/usr/bin/env python3
"""Bounded local-binary static guide proof, including known-gap characterizations."""

from contextlib import contextmanager
from pathlib import Path
import os
import re
import socket
import subprocess
import tempfile
import time
from urllib.parse import urljoin

from smoke_geoip_examples import replace_once
from smoke_proxy_transport import request

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = b"0123456789"


def prepare(source, port):
    return replace_once(source, 'listen = ["127.0.0.1:8080"]',
                        f'listen = ["127.0.0.1:{port}"]')


def fixture(root):
    site = root / "site"
    site.mkdir(mode=0o700)
    (site / "asset.txt").write_bytes(PAYLOAD)
    (site / "manual.pdf").write_bytes(b"%PDF-fixture")
    (site / ".secret").write_bytes(b"not public")
    (site / "docs").mkdir()
    (site / "docs/index.html").write_text('<a href="child.txt">child</a>')
    (site / "docs/child.txt").write_bytes(b"child")
    (site / "downloads").mkdir()
    (site / "downloads/file.txt").write_bytes(PAYLOAD)
    (site / "large.bin").touch()
    with (site / "large.bin").open("r+b") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    # '?' is not a Windows filename: keep this spelling test Unix-only.
    if os.name == "posix":
        (site / "q?x").mkdir()
        (site / "q?x/file.txt").write_bytes(PAYLOAD)
        (site / "linked.txt").symlink_to(site / "asset.txt")


@contextmanager
def gateway(source):
    parent = subprocess.check_output(["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")],
                                     text=True, timeout=10).strip()
    with tempfile.TemporaryDirectory(prefix="static-guide-", dir=parent) as directory:
        root = Path(directory)
        fixture(root)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config = root / "fluxheim.toml"
        config.write_text(prepare(source, port))
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


def static_checks(port):
    status, headers, body = request(port, "/asset.txt")
    assert status == 200 and body == PAYLOAD
    assert headers["content-type"] == "text/plain; charset=utf-8"
    assert headers["cache-control"] == "public, max-age=60"
    etag = headers["etag"]
    assert etag.startswith('W/"')
    assert request(port, "/asset.txt", "HEAD")[2] == b""
    assert request(port, "/asset.txt", headers={"If-None-Match": etag})[0] == 304
    assert request(port, "/asset.txt", headers={"If-Modified-Since": headers["last-modified"]})[0] == 304
    assert request(port, "/asset.txt", headers={"If-Match": etag})[0] == 412
    assert request(port, "/asset.txt", headers={"If-Match": "*"})[0] == 200
    for value, expected in (("bytes=2-4", b"234"), ("bytes=-3", b"789"), ("bytes=8-", b"89")):
        status, headers, body = request(port, "/asset.txt", headers={"Range": value})
        assert status == 206 and body == expected and "content-range" in headers
    assert request(port, "/asset.txt", headers={"Range": "bytes=20-"})[0] == 416
    assert request(port, "/asset.txt", headers={"Range": "bytes=0-1,4-5"})[0] == 200
    assert request(port, "/asset.txt", headers={"Range": "bytes=0-1", "If-Range": etag})[0] == 200
    assert request(port, "/large.bin")[0] == 413
    assert request(port, "/large.bin", "HEAD")[0] == 200
    assert request(port, "/large.bin", headers={"Range": "bytes=0-1"})[2] == b"\0\0"
    assert request(port, "/missing")[0] == 404
    assert request(port, "/downloads/")[0] == 404
    assert request(port, "/.secret")[0] in (400, 403, 404)
    assert request(port, "/%2e%2e/secret")[0] in (400, 403, 404)
    assert request(port, "/asset.txt", "POST")[0] == 404
    if os.name == "posix":
        assert request(port, "/linked.txt")[0] == 404

    # documented contract/002: invert these when implementing the queued corrections.
    status, headers, body = request(port, "/docs")
    assert status == 200 and "location" not in headers and b'child.txt' in body
    assert urljoin("http://example.test/docs", "child.txt") == "http://example.test/child.txt"
    assert request(port, "/child.txt")[0] == 404
    assert request(port, "/docs/child.txt")[0] == 200
    for name, value in (("Cache-Control", "no-cache"), ("Cache-Control", "no-store"), ("Pragma", "no-cache")):
        assert request(port, "/asset.txt", headers={"If-None-Match": etag, name: value})[0] == 200
    assert request(port, "/asset.txt", "HEAD", {"Range": "bytes=0-1"})[0] == 206
    assert request(port, "/asset.txt", headers={"Range": "items=0-1"})[0] == 416
    print("static guide: files, limits, path rejection, validators/ranges and known gaps: ok")


def listing_checks(port, prefix=""):
    status, headers, body = request(port, prefix + "/downloads/", headers={"Host": "files.example.test"})
    assert status == 200 and headers["cache-control"] == "private, no-store"
    assert b'href="/downloads/file%2Etxt"' in body
    assert b"file.txt</a></td><td>10</td>" in body
    assert request(port, prefix + "/downloads/file.txt", headers={"Host": "files.example.test"})[2] == PAYLOAD
    if prefix:
        assert (prefix + "/downloads/file.txt").encode() not in body
        assert request(port, "/downloads/file.txt", headers={"Host": "files.example.test"})[0] == 404
    if os.name == "posix":
        status, _, body = request(port, prefix + "/q%3Fx/", headers={"Host": "files.example.test"})
        assert status == 200 and b'href="/q?x/file%2Etxt"' in body
        assert request(port, prefix + "/q%3Fx/file.txt", headers={"Host": "files.example.test"})[0] == 200
    print("static listing: no-store, file links and directory URL gaps: ok")


def routed_listing(source):
    source = replace_once(source, "[vhosts.web]", '''[[vhosts.routes]]
name = "assets"
path_prefix = "/assets"
strip_prefix = "/assets"
[vhosts.routes.web]''')
    return replace_once(source, "[vhosts.web.directory_listing]", "[vhosts.routes.web.directory_listing]")


def option_checks(source):
    source = replace_once(source, "deny_dotfiles = true", "deny_dotfiles = false")
    source = replace_once(source, "exact_size = true", "exact_size = false")
    source = replace_once(source, "local_time = false", "local_time = true")
    source = replace_once(source, 'cache_control = "no-store"',
                          'cache_control = "no-store"\nexpires = "Thu, 01 Jan 1970 00:00:00 GMT"')
    # Exercise the actual guide's narrow MIME override, substituting only its root.
    guide = (ROOT / "docs/guides/static-files.md").read_text()
    marker = '[[vhosts.routes]]\nname = "manual"'
    if guide.count(marker) != 1:
        raise ValueError("ambiguous manual route recipe")
    route = marker + guide.split(marker, 1)[1].split("```", 1)[0]
    source += "\n" + replace_once(route, 'root = "/srv/sites/example/public"', 'root = "site"')
    with gateway(source) as port:
        headers = {"Host": "files.example.test"}
        status, response, body = request(port, "/.secret", headers=headers)
        assert status == 200 and body == b"not public"
        assert response["expires"] == "Thu, 01 Jan 1970 00:00:00 GMT"
        status, _, body = request(port, "/downloads/", headers=headers)
        assert status == 200 and b"file.txt</a></td><td>-</td>" in body
        assert re.search(rb"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}</td>", body)
        status, response, body = request(port, "/manual.pdf", headers=headers)
        assert status == 200 and body == b"%PDF-fixture"
        assert response["content-type"] == "application/pdf"
        assert response["x-content-type-options"] == "nosniff"
    print("static options: dotfile opt-in, expiry, hidden sizes, local time and MIME override: ok")


def main():
    with gateway((ROOT / "examples/web/static.toml").read_text()) as port:
        static_checks(port)
    source = (ROOT / "examples/web/listing.toml").read_text()
    with gateway(source) as port:
        listing_checks(port)
    with gateway(routed_listing(source)) as port:
        listing_checks(port, "/assets")
    option_checks(source)


if __name__ == "__main__":
    main()
