#!/usr/bin/env python3
"""Bounded local admission tests; includes explicit known-limit characterizations."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, ExitStack
from pathlib import Path
import queue
import socket
import socketserver
import threading
import time

from smoke_cors_examples import gateway, origin, request
from smoke_geoip_examples import replace_once
from smoke_protocol_examples import ACCEPT, FRAME, exact, head, websocket_request

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/limits/local.toml"


def get(port, path="/", headers=None):
    return request(port, path=path, origin_value=None, extra=headers)


@contextmanager
def held_origin(websocket=False):
    entered = threading.Event()
    release = threading.Event()
    failures = queue.Queue(maxsize=8)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            try:
                received = head(self.request)
                entered.set()
                if websocket:
                    self.request.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: " + ACCEPT + b"\r\n\r\n")
                    assert exact(self.request, len(FRAME)) == FRAME
                    self.request.sendall(b"\x81\x04pong")
                else:
                    if b" /hold " in received:
                        assert release.wait(10), "fixture release deadline"
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            except Exception as error:
                failures.put_nowait(error)

    # Only the fixed local test opens connections; all handler I/O is bounded.
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield server.server_address[1], entered, release
        finally:
            release.set()
            server.shutdown()
            worker.join(timeout=5)
            assert not worker.is_alive()
            server.server_close()
            if not failures.empty():
                raise failures.get_nowait()


def rates(source):
    with origin() as (upstream, hits):
        with gateway(source, upstream) as port:
            assert get(port, "/limited")[0] == 200
            count = len(hits)
            status, headers, _ = get(port, "/limited/second", {"X-Forwarded-For": "198.51.100.1"})
            assert status == 429 and headers["retry-after"] == "1"
            assert len(hits) == count
            assert get(port, "/other")[0] == 200
            time.sleep(1.05)
            assert get(port, "/limited")[0] == 200
        global_rate = replace_once(source, "[vhosts.rate_limit]\nenabled = false", "[vhosts.rate_limit]\nenabled = true")
        global_rate = replace_once(global_rate, "[vhosts.routes.rate_limit]\nenabled = true", "[vhosts.routes.rate_limit]\nenabled = false")
        with gateway(global_rate, upstream) as port:
            assert get(port, "/")[0] == 200
            assert get(port, "/limited")[0] == 429
        # Keep the disabled global policy unchanged; change only the route mode.
        delayed = replace_once(source, 'mode = "nodelay"\nmax_delay_ms = 1200', 'mode = "delay"\nmax_delay_ms = 1200')
        with gateway(delayed, upstream) as port:
            assert get(port, "/limited")[0] == 200
            started = time.monotonic()
            assert get(port, "/limited")[0] == 200
            assert time.monotonic() - started >= 0.5
        # documented contract: the configured one-entry total is rounded across shards.
        tiny = replace_once(global_rate, "table_max_entries = 65536", "table_max_entries = 1")
        tiny = replace_once(tiny, "trusted_proxies = []", 'trusted_proxies = ["127.0.0.1"]')
        with gateway(tiny, upstream) as port:
            statuses = [get(port, headers={"X-Forwarded-For": f"192.0.2.{last}"})[0]
                        for last in range(1, 33)]
            assert statuses.count(200) == 16, statuses
            assert statuses.count(429) == 16, statuses
    print("admission: rate rejection/refill, scopes, delay, spoof resistance and rounded table cap: ok")


def concurrency(source):
    for timeout in (0, 150):
        variant = replace_once(source, "max_queue = 0\nqueue_timeout_ms = 0", f"max_queue = 1\nqueue_timeout_ms = {timeout}")
        with held_origin() as (upstream, entered, release), gateway(variant, upstream) as port:
            with ThreadPoolExecutor(max_workers=1) as pool:
                first = pool.submit(get, port, "/hold")
                try:
                    assert entered.wait(3)
                    status, headers, _ = get(port)
                    assert status == 503 and headers["retry-after"] == "1"
                finally:
                    release.set()
                assert first.result(timeout=5)[0] == 200
            assert get(port)[0] == 200
    queued = replace_once(source, "max_queue = 0\nqueue_timeout_ms = 0", "max_queue = 1\nqueue_timeout_ms = 2000")
    with held_origin() as (upstream, entered, release), gateway(queued, upstream) as port:
        with ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(get, port, "/hold")
            assert entered.wait(3)
            timer = threading.Timer(0.2, release.set)
            timer.start()
            try:
                assert get(port)[0] == 200
            finally:
                release.set()
                timer.cancel()
                timer.join(timeout=3)
            assert first.result(timeout=5)[0] == 200
    print("admission: active rejection, bounded queue timeout, queued success and release recovery: ok")


def tunnels(source):
    source = replace_once(source, 'path_prefix = "/limited"', 'path_prefix = "/socket/"')
    source = replace_once(source, "[vhosts.routes.rate_limit]\nenabled = true", "[vhosts.routes.rate_limit]\nenabled = false")
    source = replace_once(source, '[vhosts.routes.proxy]', '[vhosts.routes.proxy]\nwebsocket = true')
    with held_origin(websocket=True) as (upstream, _, _), gateway(source, upstream) as port:
        with ExitStack() as stack:
            streams = []
            for _ in range(2):
                stream = stack.enter_context(socket.create_connection(("127.0.0.1", port), timeout=3))
                stream.sendall(websocket_request("/socket/echo").replace(b"app.example.test", b"api.example.test"))
                assert head(stream).startswith(b"HTTP/1.1 101 ")
                streams.append(stream)
            # Both tunnels are open despite vhost and route max_in_flight = 1.
            for stream in streams:
                stream.sendall(FRAME)
                assert exact(stream, 6) == b"\x81\x04pong"
    print("admission: documented contract concurrent tunnels exceed the configured one-request budget: reproduced")


def main():
    source = EXAMPLE.read_text()
    rates(source)
    concurrency(source)
    tunnels(source)


if __name__ == "__main__":
    main()
