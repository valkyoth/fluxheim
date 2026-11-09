#!/usr/bin/env python3
"""Prove HTTP health connection reuse and failover with loopback-only fixtures."""

import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time

import smoke_load_balancer_examples as smoke
import smoke_load_balancer_tcp_health as tcp


class Counts:
    def __init__(self):
        self.lock = threading.Lock()
        self.accepted = 0
        self.probes = 0
        self.active = 0
        self.ready = True

    def sample(self):
        with self.lock:
            return self.accepted, self.probes, self.active

    def readiness(self, ready):
        with self.lock:
            self.ready = ready


def counts_prove_policy(sample, reuse):
    accepted, probes, _ = sample
    return probes >= 8 and accepted == (2 if reuse else probes)


@contextmanager
def readiness():
    counts = Counts()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(10)
            with counts.lock:
                counts.accepted += 1
                counts.active += 1

        def finish(self):
            try:
                super().finish()
            finally:
                with counts.lock:
                    counts.active -= 1

        def do_GET(self):
            with counts.lock:
                counts.probes += 1
                healthy = counts.ready
            self.send_response(200 if healthy else 503)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            # Chunk termination and trailers must be consumed before the next probe.
            self.wfile.write(b"5\r\nready\r\n0\r\nx-health: complete\r\n\r\n")
            self.wfile.flush()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_address[1], counts
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        if worker.is_alive():
            raise AssertionError("reuse readiness fixture did not stop")


def configuration(public, first, second, ready, reuse, guest=False):
    source = tcp.configuration(public, first, second, ready, guest)
    source = smoke.replace_once(source, 'protocol = "tcp"', 'protocol = "http"')
    return source + f"\nreuse_connection = {str(reuse).lower()}\npath = \"/healthz\"\n"


def run_case(parent, reuse, digest=None):
    with readiness() as (port, counts), smoke.origin("origin-a") as (first, _), smoke.origin("origin-b") as (second, _):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            public = reservation.getsockname()[1]
        with smoke.private_fixture(None if os.name == "nt" else parent) as directory, tempfile.TemporaryFile() as log:
            config = Path(directory) / "fluxheim.toml"
            config.write_text(configuration(public, first, second, port, reuse, digest is not None), encoding="utf-8")
            with tcp.server(config, log, digest) as process:
                smoke.wait_for(process, lambda: counts_prove_policy(counts.sample(), reuse), "health connection counts")
                assert {smoke.request(public) for _ in range(6)} == {(200, b"origin-a"), (200, b"origin-b")}
                counts.readiness(False)
                smoke.wait_for(process, lambda: smoke.request(public)[0] == 503, "reuse failover")
                counts.readiness(True)
                smoke.wait_for(process, lambda: smoke.request(public)[0] == 200, "reuse recovery")
                baseline = counts.sample()[0]
                probes = counts.sample()[1]
                smoke.wait_for(process, lambda: counts.sample()[1] >= probes + 6, "post-recovery probes")
                # At most one residual failure per backend may finish after readiness flips.
                if reuse:
                    assert counts.sample()[0] <= baseline + 2, "recovery did not restore reuse"
            deadline = time.monotonic() + 5
            while counts.sample()[2] and time.monotonic() < deadline:
                time.sleep(0.05)
            assert counts.sample()[2] == 0, "health connections survived server shutdown"
            print(f"HTTP health reuse={reuse}, {'container' if digest else 'native'}: connection counts, trailers, failover, recovery, shutdown: ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work_root", type=Path)
    parser.add_argument("--container", action="store_true")
    args = parser.parse_args()
    digest = None
    if args.container:
        assert tcp.container.engine("info", "--format", "{{.Host.Security.Rootless}}") == "true"
        image = os.environ.get("FLUXHEIM_LB_CONTAINER_SMOKE_IMAGE", tcp.container.IMAGE)
        inspected = json.loads(tcp.container.engine("image", "inspect", "--", image))[0]
        assert inspected["Config"]["User"] == "65532:65532"
        digest = inspected["Id"]
    for reuse in (False, True):
        run_case(args.work_root.resolve(strict=True), reuse, digest)


if __name__ == "__main__":
    main()
