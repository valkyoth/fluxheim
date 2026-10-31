#!/usr/bin/env python3
"""Bounded loopback UDP guide checks against the trusted local executable."""

from contextlib import contextmanager
import http.client
from pathlib import Path
import queue
import socket
import subprocess
import tempfile
import threading
import time

from smoke_geoip_examples import replace_once

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/udp/local.toml"
SYSLOG_EXAMPLE = ROOT / "examples/udp/syslog.toml"


def syslog_recipe():
    source = replace_once(SYSLOG_EXAMPLE.read_text(), "127.0.0.1:15514", "127.0.0.1:15353")
    return replace_once(source, "127.0.0.1:19514", "127.0.0.1:19053")


def prepare(source, port, upstream, metrics_port, ipv6=False):
    host = "[::1]" if ipv6 else "127.0.0.1"
    source = replace_once(source, 'listen = ["127.0.0.1:15353"]', f'listen = ["{host}:{port}"]')
    source = replace_once(source, '"127.0.0.1:19053"', f'"{host}:{upstream}"')
    return source + f'\n[metrics]\nenabled = true\nlisten = "127.0.0.1:{metrics_port}"\nrequire_loopback = true\n'


@contextmanager
def datagram(ipv6=False):
    with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.bind(("::1" if ipv6 else "127.0.0.1", 0))
        stream.settimeout(3)
        yield stream


def metrics(port):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", "/metrics")
        response = connection.getresponse()
        assert response.status == 200
        body = response.read(262145)
        assert len(body) <= 262144
        return body.decode()
    finally:
        connection.close()


def silent(stream, timeout=0.2):
    previous = stream.gettimeout()
    stream.settimeout(timeout)
    try:
        try:
            data = stream.recvfrom(65535)
        except TimeoutError:
            return
        raise AssertionError(f"unexpected datagram: {len(data[0])} bytes")
    finally:
        stream.settimeout(previous)


@contextmanager
def gateway(source, upstream, ipv6=False):
    parent = subprocess.check_output(["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")],
                                     text=True, timeout=10).strip()
    with tempfile.TemporaryDirectory(prefix="udp-guide-", dir=parent) as directory:
        with datagram(ipv6) as reservation:
            port = reservation.getsockname()[1]
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            metrics_port = reservation.getsockname()[1]
        config = Path(directory) / "fluxheim.toml"
        config.write_text(prepare(source, port, upstream, metrics_port, ipv6))
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
                        raise AssertionError("UDP gateway exited before readiness")
                    try:
                        metrics(metrics_port)
                        break
                    except (OSError, http.client.HTTPException):
                        if time.monotonic() >= deadline:
                            raise AssertionError("metrics readiness deadline") from None
                        time.sleep(0.05)
                # No readiness datagram: preserve the selector's first slot.
                time.sleep(0.1)
                yield ("::1" if ipv6 else "127.0.0.1", port), metrics_port
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


@contextmanager
def echo(label):
    errors = []
    hits = queue.Queue(maxsize=64)
    stop = threading.Event()
    with datagram() as server:
        server.settimeout(0.1)

        def run():
            try:
                while not stop.is_set():
                    try:
                        payload, peer = server.recvfrom(65535)
                    except TimeoutError:
                        continue
                    hits.put_nowait(payload)
                    server.sendto(label + payload, peer)
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        try:
            yield server.getsockname()[1], hits
        finally:
            stop.set()
            worker.join(timeout=5)
            assert not worker.is_alive()
            assert not errors, errors


def forwarding(source):
    with echo(b"a:") as (first, _), echo(b"b:") as (second, _):
        weighted = replace_once(source, 'upstream = "127.0.0.1:19053"',
            f'upstreams = ["127.0.0.1:19053", "127.0.0.1:{second}"]\n'
            'upstream_weights = [2, 1]\nupstream_aliases = ["a", "b"]')
        with gateway(weighted, first) as (address, _), datagram() as client:
            replies = []
            for _ in range(6):
                client.sendto(b"opaque", address)
                replies.append(client.recvfrom(65535)[0])
            assert replies == [b"a:opaque", b"a:opaque", b"b:opaque"] * 2, replies
    with datagram() as backend, datagram() as client:
        one_way = syslog_recipe()
        with gateway(one_way, backend.getsockname()[1]) as (address, _):
            client.sendto(b"<13>test message", address)
            payload, peer = backend.recvfrom(65535)
            assert payload == b"<13>test message"
            backend.sendto(b"not forwarded", peer)
            silent(client)
    print("UDP: per-datagram weights, opaque request/response and one-way syslog: ok")


def limits(source):
    with datagram() as backend, datagram() as client:
        with gateway(source, backend.getsockname()[1]) as (address, port):
            client.sendto(b"x" * 1233, address)
            silent(backend)
            assert 'reason="oversized_downstream"' in metrics(port)
            client.sendto(b"query", address)
            assert backend.recvfrom(65535)[0] == b"query"
            # A second query uses a separate socket, not a persistent flow.
            client.sendto(b"large-reply", address)
            payload, peer = backend.recvfrom(65535)
            assert payload == b"large-reply"
            backend.sendto(b"x" * 1233, peer)
            silent(client)
            assert 'reason="oversized_upstream"' in metrics(port)
    for field, reason in (("max_sessions", "max_sessions"),
                          ("max_sessions_per_source", "max_sessions_per_source")):
        original = 32 if field == "max_sessions" else 8
        limited = replace_once(source, f"{field} = {original}", f"{field} = 1")
        with datagram() as backend, datagram() as first, datagram() as second:
            with gateway(limited, backend.getsockname()[1]) as (address, port):
                first.sendto(b"hold", address)
                assert backend.recvfrom(65535)[0] == b"hold"
                second.sendto(b"excess", address)
                silent(backend)
                assert f'reason="{reason}"' in metrics(port)
                # No response: timeout must release both budgets.
                time.sleep(1.1)
                second.sendto(b"recovered", address)
                payload, peer = backend.recvfrom(65535)
                assert payload == b"recovered"
                backend.sendto(b"ok", peer)
                assert second.recvfrom(65535)[0] == b"ok"
    print("UDP: ingress/response size caps, route/source admission and timeout recovery: ok")


def health(source):
    with datagram() as blackhole, echo(b"good:") as (good, _):
        configured = replace_once(source, 'upstream = "127.0.0.1:19053"',
            f'upstreams = ["127.0.0.1:19053", "127.0.0.1:{good}"]')
        configured = replace_once(configured, "passive_health_failures = 3", "passive_health_failures = 1")
        with gateway(configured, blackhole.getsockname()[1]) as (address, _), datagram() as client:
            client.sendto(b"lost", address)
            assert blackhole.recvfrom(65535)[0] == b"lost"
            silent(client, 1.3)
            # No replay of the lost packet; subsequent packets skip the ejected member.
            for _ in range(2):
                client.sendto(b"next", address)
                assert client.recvfrom(65535)[0] == b"good:next"
            silent(blackhole)
    print("UDP: passive ejection applies to subsequent packets, not failed-packet replay: ok")


def gauge_gap(source):
    for cap in (32, 0):
        configured = replace_once(source, "max_sessions = 32", f"max_sessions = {cap}")
        with datagram() as backend, datagram() as client:
            with gateway(configured, backend.getsockname()[1]) as (address, port):
                client.sendto(b"pending", address)
                payload, peer = backend.recvfrom(65535)
                assert payload == b"pending"
                expected = 1 if cap else 0
                assert f'fluxheim_udp_active_sessions{{route="local-datagrams"}} {expected}\n' in metrics(port)
                backend.sendto(b"ok", peer)
                assert client.recvfrom(65535)[0] == b"ok"
    print("UDP: documented contract unlimited route reports zero while an exchange is active: reproduced")


def response_rate(source):
    configured = replace_once(source, "max_responses_per_source_per_second = 64", "max_responses_per_source_per_second = 1")
    configured = replace_once(configured, "response_timeout_secs = 1", "response_timeout_secs = 3")
    with datagram() as backend, datagram() as client:
        with gateway(configured, backend.getsockname()[1]) as (address, port):
            peers = []
            for index in range(3):
                client.sendto(bytes([index]), address)
                payload, peer = backend.recvfrom(65535)
                assert payload == bytes([index])
                peers.append(peer)
            # Release replies together early in one wall-clock window; the
            # runtime's rate policy uses epoch seconds rather than a token bucket.
            deadline = time.monotonic() + 2
            while time.time() % 1 > 0.1:
                assert time.monotonic() < deadline
                time.sleep(0.01)
            for peer in peers:
                backend.sendto(b"reply", peer)
            assert client.recvfrom(65535)[0] == b"reply"
            silent(client)
            assert 'reason="response_rate_limited"' in metrics(port)
            time.sleep(1.05)
            client.sendto(b"again", address)
            _, peer = backend.recvfrom(65535)
            backend.sendto(b"recovered", peer)
            assert client.recvfrom(65535)[0] == b"recovered"
    print("UDP: downstream response-rate cap and next-window recovery: ok")


def ipv6_size_gap(source):
    # This qualification requires real IPv6; do not silently pass without it.
    configured = replace_once(source, "max_datagram_bytes = 1232", "max_datagram_bytes = 65507")
    with datagram(True) as backend, datagram(True) as client:
        with gateway(configured, backend.getsockname()[1], ipv6=True) as (address, _):
            client.sendto(b"e" * 65507, address)
            payload, peer = backend.recvfrom(65535)
            assert payload == b"e" * 65507
            backend.sendto(b"exact", peer)
            assert client.recvfrom(65535)[0] == b"exact"
            client.sendto(b"x" * 65508, address)
            payload, peer = backend.recvfrom(65535)
            assert payload == b"x" * 65507, len(payload)
            backend.sendto(b"truncated", peer)
            assert client.recvfrom(65535)[0] == b"truncated"
        smaller = replace_once(configured, "max_datagram_bytes = 65507", "max_datagram_bytes = 65506")
        with gateway(smaller, backend.getsockname()[1], ipv6=True) as (address, port):
            client.sendto(b"x" * 65508, address)
            silent(backend)
            assert 'reason="oversized_downstream"' in metrics(port)
            client.sendto(b"recovered", address)
            payload, peer = backend.recvfrom(65535)
            assert payload == b"recovered"
            backend.sendto(b"ok", peer)
            assert client.recvfrom(65535)[0] == b"ok"
    print("UDP: documented contract oversized IPv6 packet forwarded as a truncated datagram: reproduced")


def main():
    source = EXAMPLE.read_text()
    forwarding(source)
    limits(source)
    health(source)
    response_rate(source)
    gauge_gap(source)
    ipv6_size_gap(source)


if __name__ == "__main__":
    main()
