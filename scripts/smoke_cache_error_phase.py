#!/usr/bin/env python3
"""Exercise stale-error selection using a trusted binary or local Wolfi image.

Numeric loopback fixtures only. Container mode inherits the existing bounded,
non-root test controls and is not an untrusted-image sandbox.
"""

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
import time

import smoke_cache_examples as cache
import smoke_load_balancer_tcp_health as runner


@contextmanager
def origin():
    state = {"fault": None, "body": b"trusted"}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                fault, body = state["fault"], state["body"]
            if fault == "connection-closed":
                self.close_connection = True
                return
            if fault == "protocol":
                self.wfile.write(b"NOT-HTTP\r\n\r\n")
                return
            if fault == "timeout":
                time.sleep(1.5)
                return
            self.send_response(503 if fault == "http-status" else 200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "text/css")
            self.send_header("Cache-Control", "max-age=1")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    def set_state(fault, body):
        with lock:
            state.update(fault=fault, body=body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_address[1], set_state
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive(), "origin did not stop"


def configuration(public, upstream, fault, allowed, guest):
    if fault not in ("connection-closed", "protocol", "timeout", "http-status"):
        raise ValueError("unsupported fault")
    source = cache.prepare(public, upstream)
    source = cache.replace_once(source, 'status_ttls = { "200" = 120 }',
        f'status_ttls = {{ "200" = 1 }}\nstale_if_error_secs = 2\n'
        f'stale_if_error_on = ["{fault if allowed else "read"}"]\n'
        'stale_if_error_statuses = [503]')
    source = cache.replace_once(source, "read_timeout_secs = 3", "read_timeout_secs = 1")
    if guest:
        for name in ("fluxheim.pid", "upgrade.sock", "reload.sock"):
            source = cache.replace_once(source, f'"{name}"', f'"/run/fluxheim/{name}"')
    return source


def request(port, path="/asset.css"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
    try:
        connection.request("GET", path, headers={"Host": "cache.test"})
        response = connection.getresponse()
        return response.status, response.getheader("x-cache-status"), response.read(4097)
    finally:
        connection.close()


def run_case(parent, fault, allowed, digest):
    with origin() as (upstream, set_state):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            public = reservation.getsockname()[1]
        with runner.smoke.private_fixture(None if os.name == "nt" else parent) as directory, tempfile.TemporaryFile() as log:
            config = Path(directory) / "fluxheim.toml"
            config.write_text(configuration(public, upstream, fault, allowed, digest is not None), encoding="utf-8")
            with runner.server(config, log, digest) as process:
                runner.smoke.wait_for(process, lambda: runner.smoke.listener_ready(public), "cache listener")
                assert request(public) == (200, "MISS", b"trusted")
                time.sleep(1.1)
                set_state(fault, b"untrusted")
                status, label, body = request(public)
                if allowed:
                    assert (status, label, body) == (200, "STALE", b"trusted"), (status, label, body)
                else:
                    assert status in (502, 503, 504) and label != "STALE" and body != b"trusted", (status, label, body)
                # A stale permission never manufactures a cache entry on a cold key.
                cold_status, cold_label, _ = request(public, "/cold.css")
                assert cold_status in (502, 503, 504) and cold_label != "STALE"
                time.sleep(2.1)
                expired_status, expired_label, expired_body = request(public)
                assert expired_status in (502, 503, 504) and expired_label != "STALE" and expired_body != b"trusted"
                set_state(None, b"renewed")
                assert request(public) == (200, "MISS", b"renewed")
                assert request(public) == (200, "HIT", b"renewed")
        print(f"cache stale {fault}, allowed={allowed}, {'container' if digest else 'native'}: ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work_root", type=Path)
    parser.add_argument("--container", action="store_true")
    args = parser.parse_args()
    digest = None
    if args.container:
        assert runner.container.engine("info", "--format", "{{.Host.Security.Rootless}}") == "true"
        inspected = json.loads(runner.container.engine("image", "inspect", "localhost/fluxheim:cache-phase-smoke"))[0]
        assert inspected["Config"]["User"] == "65532:65532"
        digest = inspected["Id"]
    for fault in ("connection-closed", "protocol", "timeout", "http-status"):
        for allowed in (False, True):
            run_case(args.work_root.resolve(strict=True), fault, allowed, digest)
    if digest:
        print(f"cache stale container identity: {digest}")


if __name__ == "__main__":
    main()
