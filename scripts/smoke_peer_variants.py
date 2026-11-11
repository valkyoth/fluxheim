#!/usr/bin/env python3
"""Qualify variant-aware peer fills with two real peers and a counted origin.

Uses the trusted local binary or a locally built, non-root Wolfi image. All
listeners are numeric loopback; this is not an untrusted-payload sandbox.
"""

import argparse
from contextlib import contextmanager, ExitStack
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import tempfile
import threading

import smoke_cache_examples as cache
import smoke_load_balancer_tcp_health as runner


@contextmanager
def origin(declared):
    counts = {"calls": 0}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                counts["calls"] += 1
            values = self.headers.get_all("x-edition") or []
            body = json.dumps(values).encode("ascii")
            self.send_response(200)
            self.send_header("Content-Type", "text/css")
            self.send_header("Cache-Control", "max-age=120")
            self.send_header("Content-Length", str(len(body)))
            if declared:
                self.send_header("Vary", "X-Edition")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    def count():
        with lock:
            return counts["calls"]

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_address[1], count
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive(), "origin did not stop"


def configuration(public, upstream, tier, configured, peers, guest, authenticated=False):
    if tier not in ("memory", "filesystem", "storage-bin"):
        raise ValueError("unsupported storage tier")
    source = cache.prepare(public, upstream, None if tier == "memory" else tier,
                           disk_only=tier != "memory")
    if configured:
        source = cache.replace_once(source, '[cache]\n',
                                    '[cache]\nvary_request_headers = ["x-edition"]\n')
    if peers or authenticated:
        source += f'\n[cache.peer_fill]\nenabled = {str(bool(peers)).lower()}\nfail_open = true\n'
        if authenticated:
            source += 'shared_secret_file = "peer.secret"\n'
        for index, peer in enumerate(peers):
            if not isinstance(peer, int) or not 1 <= peer <= 65535:
                raise ValueError("invalid peer port")
            source += (f'\n[[cache.peer_fill.peers]]\nname = "peer-{index}"\n'
                       f'base_url = "http://127.0.0.1:{peer}"\n')
    if guest:
        for name in ("fluxheim.pid", "upgrade.sock", "reload.sock"):
            source = cache.replace_once(source, f'"{name}"', f'"/run/fluxheim/{name}"')
        if tier != "memory":
            source = cache.replace_once(source, '"state/cache"', '"/var/cache/fluxheim/peer"')
    return source


@contextmanager
def node(parent, upstream, tier, configured, peers, digest, secret=None):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        public = reservation.getsockname()[1]
    with cache.private_fixture(None if os.name == "nt" else parent) as directory:
        root = Path(directory)
        if digest is None:
            for path in (root / "state", root / "state/cache"):
                path.mkdir()
                cache.protect_directory(path)
        config = root / "fluxheim.toml"
        if secret is not None:
            with os.fdopen(os.open(root / "peer.secret", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="ascii") as stream:
                stream.write(secret)
        config.write_text(configuration(public, upstream, tier, configured, peers, digest is not None, secret is not None), encoding="utf-8")
        with tempfile.TemporaryFile() as log:
            try:
                with runner.server(config, log, digest) as process:
                    runner.smoke.wait_for(process, lambda: runner.smoke.listener_ready(public), "peer listener")
                    yield public
            except Exception:
                log.seek(0)
                print(log.read(8192).decode("utf-8", errors="replace"))
                raise


def request(port, values, path="/asset.css"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", "cache.test")
        for value in values:
            connection.putheader("X-Edition", value)
        connection.endheaders()
        response = connection.getresponse()
        body = response.read(4097)
        assert response.status == 200 and body == json.dumps(values).encode("ascii"), (response.status, body, values)
        assert not any(name.lower().startswith("x-fluxheim-peer-fill") for name, _ in response.getheaders())
        return response.getheader("x-cache-status")
    finally:
        connection.close()


def run_case(parent, tier, declared, digest):
    with origin(declared) as (upstream, count), ExitStack() as stack:
        # Native fixtures exercise actual secret-file loading on every OS. The
        # non-root container fixture uses the permitted numeric-loopback mode.
        secret = secrets.token_hex(32) if digest is None else None
        cold = stack.enter_context(node(parent, upstream, tier, True, (), digest, secret))
        warm = stack.enter_context(node(parent, upstream, tier, not declared, (), digest, secret))
        variants = [[], [""], ["special"], ["one", "two"], ["two", "one"]]
        for values in variants:
            assert request(warm, values) == "MISS"
        assert count() == len(variants)
        front = stack.enter_context(node(parent, upstream, tier, True, (cold, warm), digest, secret))
        for values in variants:
            assert request(front, values) == "PEER-HIT"
            assert request(front, values) == "HIT"
        assert count() == len(variants), "peer lookup contacted origin"
        assert request(front, ["cold"], "/cold.css") == "MISS"
        assert request(front, ["cold"], "/cold.css") == "HIT"
        assert count() == len(variants) + 1
    print(f"peer variants {tier}, origin Vary={declared}, {'container' if digest else 'native'}: ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work_root", type=Path)
    parser.add_argument("--container", action="store_true")
    args = parser.parse_args()
    digest = None
    if args.container:
        assert runner.container.engine("info", "--format", "{{.Host.Security.Rootless}}") == "true"
        image = json.loads(runner.container.engine("image", "inspect", "localhost/fluxheim:peer-variants-smoke"))[0]
        assert image["Config"]["User"] == "65532:65532"
        digest = image["Id"]
    for tier in ("memory", "filesystem", "storage-bin"):
        for declared in (False, True):
            run_case(args.work_root.resolve(strict=True), tier, declared, digest)
    if digest:
        print(f"peer-variant container image: {digest}")


if __name__ == "__main__":
    main()
