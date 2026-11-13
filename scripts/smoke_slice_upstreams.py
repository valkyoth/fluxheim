#!/usr/bin/env python3
"""Count real balanced slice fills, health transitions and discovery refreshes."""

import argparse
from contextlib import contextmanager, ExitStack
from concurrent.futures import ThreadPoolExecutor
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import tempfile
import threading

import smoke_slice_storage as storage


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.calls = 0
        self.healthy = True
        self.members = []

    def count(self):
        with self.lock:
            return self.calls

    def health(self, healthy):
        with self.lock:
            self.healthy = healthy

    def membership(self, ports):
        with self.lock:
            self.members = [f"127.0.0.1:{port}" for port in ports]


@contextmanager
def endpoint(state, alternate=False):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with state.lock:
                healthy, members = state.healthy, list(state.members)
                if self.path != "/healthz":
                    state.calls += 1
            if self.path == "/members":
                body = json.dumps({"upstreams": members}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
            elif self.path == "/healthz":
                body = b"ready"
                self.send_response(200 if healthy else 503)
            else:
                body = b"abcdefgh" if alternate else b"01234567"
                # Fixture requests are bounded ranges; reject other syntax rather
                # than reflecting request data into response headers.
                requested = self.headers.get("Range")
                ranges = {"bytes=0-3": (0, 3), "bytes=4-7": (4, 7), "bytes=2-5": (2, 5)}
                if requested not in ranges:
                    self.send_error(400)
                    return
                start, end = ranges[requested]
                self.send_response(206)
                self.send_header("Content-Type", "text/css")
                self.send_header("Cache-Control", "max-age=120")
                self.send_header("ETag", '"revision-b"' if alternate else '"revision-a"')
                self.send_header("Content-Range", f"bytes {start}-{end}/8")
                body = body[start:end + 1]
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()


def configuration(public, ports, discovery, mode, guest):
    source = storage.configuration(public, ports[0], None, False, guest)
    old = f'upstreams = ["127.0.0.1:{ports[0]}"]'
    if mode == "discovery":
        new = f'upstreams_http_url = "http://127.0.0.1:{discovery}/members"\nupstreams_http_refresh_secs = 1\nupstreams_http_allow_private_backends = true'
    elif mode == "file":
        new = 'upstreams_file = "members.txt"\nupstreams_file_refresh_secs = 1'
    else:
        new = "upstreams = " + json.dumps([f"127.0.0.1:{port}" for port in ports[:2]])
        if mode == "health":
            new += f'\ndrain_upstreams = ["127.0.0.1:{ports[0]}"]'
    source = storage.cache.replace_once(source, old, new)
    source += '\n[cache.lock]\nenabled = true\n'
    source += '\n[proxy.load_balance]\nselection = "round-robin"\nall_down_status = 503\n'
    source += '[proxy.load_balance.health_check]\n'
    source += ('enabled = true\nprotocol = "http"\npath = "/healthz"\ninterval_secs = 1\nconsecutive_success = 1\nconsecutive_failure = 1\n' if mode == "health" else 'enabled = false\n')
    return source


def request(port, number):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", f"/asset.css?case={number}", headers={"Host": "cache.test", "Range": "bytes=2-5"})
        response = connection.getresponse()
        return response.status, response.read(4097), response.getheader("x-cache-reason")
    finally:
        connection.close()


def run_case(parent, mode, digest):
    states = [State() for _ in range(3)]
    control = State()
    with ExitStack() as stack:
        ports = [stack.enter_context(endpoint(state, mode == "mismatch" and i == 1)) for i, state in enumerate(states)]
        control.membership(ports[:2])
        discovery = stack.enter_context(endpoint(control))
        directory = stack.enter_context(storage.cache.private_fixture(None if os.name == "nt" else parent))
        log = stack.enter_context(tempfile.TemporaryFile())
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            public = reservation.getsockname()[1]
        config = Path(directory) / "fluxheim.toml"
        members = Path(directory) / "members.txt"
        if mode == "file":
            members.write_text("\n".join(f"127.0.0.1:{port}" for port in ports[:2]) + "\n", encoding="utf-8")
        config.write_text(configuration(public, ports, discovery, mode, digest is not None), encoding="utf-8")
        try:
            with storage.runner.server(config, log, digest) as process:
                wait = lambda predicate, label: storage.runner.smoke.wait_for(process, predicate, label)
                wait(lambda: storage.runner.smoke.listener_ready(public), "slice upstream listener")
                if mode == "mismatch":
                    status, body, reason = request(public, 0)
                    assert status == 206 and body in (b"2345", b"cdef"), (status, body, reason)
                    assert reason not in ("slice", "slice-fill"), reason
                    assert sum(s.count() for s in states) == 3, "expected two conflicting slices then one intact fallback"
                else:
                    assert request(public, 0) == (206, b"2345", "slice-fill")
                    assert request(public, 0) == (206, b"2345", "slice")
                    assert sum(s.count() for s in states) == 2
                    with ThreadPoolExecutor(max_workers=8) as clients:
                        responses = list(clients.map(lambda _: request(public, 7), range(32)))
                    assert all(status == 206 and body == b"2345" and reason in ("slice", "slice-fill") for status, body, reason in responses)
                    assert sum(s.count() for s in states) == 4, "concurrent fills were not collapsed"
                    if mode == "health":
                        assert states[0].count() == 0, "drained origin contacted"
                        states[1].health(False)
                        counter = iter(range(10, 10000))
                        wait(lambda: request(public, next(counter))[0] == 503, "slice all-down")
                        before = [s.count() for s in states]
                        assert all(request(public, i)[0] == 503 for i in range(2, 6))
                        assert before == [s.count() for s in states], "unhealthy origin contacted"
                        states[1].health(True)
                        wait(lambda: request(public, 6) == (206, b"2345", "slice-fill"), "slice recovery")
                        assert states[0].count() == 0
                    else:
                        control.membership(ports[1:])
                        if mode == "file":
                            members.write_text("\n".join(f"127.0.0.1:{port}" for port in ports[1:]) + "\n", encoding="utf-8")
                        counter = iter(range(10, 10000))
                        def refreshed():
                            assert request(public, next(counter)) == (206, b"2345", "slice-fill")
                            return states[2].count() > 0
                        wait(refreshed, "slice discovery replacement")
                        removed = states[0].count()
                        for i in range(10001, 10005):
                            assert request(public, i) == (206, b"2345", "slice-fill")
                        assert states[0].count() == removed, "removed member contacted"
                        assert states[1].count() > 0 and states[2].count() > 0
        except Exception:
            log.seek(0)
            print(log.read(8192).decode("utf-8", errors="replace"))
            raise
    print(f"slice upstream {mode}, {'container' if digest else 'native'}: ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work_root", type=Path)
    parser.add_argument("--container", action="store_true")
    args = parser.parse_args()
    digest = None
    if args.container:
        engine = storage.runner.container.engine
        assert engine("info", "--format", "{{.Host.Security.Rootless}}") == "true"
        image = json.loads(engine("image", "inspect", "localhost/fluxheim:slice-storage-smoke"))[0]
        assert image["Config"]["User"] == "65532:65532"
        digest = image["Id"]
    for mode in ("health", "discovery", "mismatch"):
        run_case(args.work_root.resolve(strict=True), mode, digest)
    if digest is None:
        run_case(args.work_root.resolve(strict=True), "file", None)


if __name__ == "__main__":
    main()
