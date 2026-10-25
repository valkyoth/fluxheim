#!/usr/bin/env python3
"""Live HTTP/1.1 + multiplexed TLS HTTP/2 access/OTLP correlation proof.

Requires hyper-h2 (CI pins it). FastCGI is a protocol fixture, not a PHP interpreter.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import http.client
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamEnded, StreamReset

from smoke_log_file_rotation import fixture_parent, private_fixture, records, wait_for, request as admin_request
from smoke_operational_events import ROOT, port

CANARY = "correlation-secret-canary"
PARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


class Collector(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        assert length < 65536
        self.server.payloads.append(json.loads(self.rfile.read(length)))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_):
        pass


class Origin(Collector):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.seen.append(dict(self.headers))
        if self.headers.get("Upgrade") == "websocket":
            key = self.headers["Sec-WebSocket-Key"]
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode(), usedforsecurity=False).digest()).decode()
            self.send_response(101)
            self.send_header("Connection", "Upgrade")
            self.send_header("Upgrade", "websocket")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            frame = self.rfile.read(6 + len(CANARY))
            assert frame[:2] == bytes([0x81, 0x80 | len(CANARY)])
            self.wfile.write(bytes([0x81, len(CANARY)]) + CANARY.encode())
            self.wfile.flush()
            self.close_connection = True
            return
        if self.path.startswith("/retry") and not self.server.retried:
            self.server.retried = True
            self.close_connection = True
            return
        if self.path.startswith("/cancel"):
            self.server.cancel_started.set()
            assert self.server.cancel_release.wait(5)
        time.sleep(0.02)
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.end_headers()
        self.wfile.write(b"proxy")


def exactly(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise EOFError("FastCGI fixture connection ended")
        data.extend(chunk)
    return data


def fcgi_params(data):
    offset, result = 0, {}
    while offset < len(data):
        lengths = []
        for _ in range(2):
            size = data[offset]
            if size & 128:
                size = int.from_bytes(data[offset:offset + 4], "big") & 0x7fffffff
                offset += 4
            else:
                offset += 1
            lengths.append(size)
        name, value = lengths
        result[bytes(data[offset:offset + name]).decode()] = bytes(data[offset + name:offset + name + value]).decode()
        offset += name + value
    return result


class FastCGI(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        while True:
            params, keep_alive = bytearray(), False
            while True:
                try:
                    head = exactly(self.request, 8)
                except (EOFError, TimeoutError):
                    return
                version, type_, id_, size, padding, _ = struct.unpack("!BBHHBB", head)
                assert version == 1 and size <= 65535
                content = exactly(self.request, size)
                exactly(self.request, padding)
                if type_ == 1:
                    keep_alive = bool(content[2] & 1)
                if type_ == 4:
                    params.extend(content)
                if type_ == 5 and size == 0:
                    break
            self.server.seen.append(fcgi_params(params))
            output = b"Content-Type: text/plain\r\nContent-Length: 3\r\n\r\nphp"
            for type_, payload in [(6, output), (6, b""), (3, bytes(8))]:
                self.request.sendall(struct.pack("!BBHHBB", 1, type_, id_, len(payload), 0, 0) + payload)
            if not keep_alive:
                # Drain any final empty records after half-closing the reply.
                # Closing with unread input can reset TCP on macOS/Windows and
                # discard a perfectly valid response before the client reads it.
                self.request.shutdown(socket.SHUT_WR)
                drained = 0
                while chunk := self.request.recv(4096):
                    drained += len(chunk)
                    assert drained <= 65536
                return


class FastCGIServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


def request_http1(listen, host, id_, extra=(), path=None):
    connection = http.client.HTTPConnection("127.0.0.1", listen, timeout=10)
    path = path or ("/index.php" if host == "php.test" else "/index.html")
    try:
        connection.putrequest("GET", f"{path}?token={CANARY}", skip_host=True)
        for name, value in [("Host", host), ("Connection", "close"), ("x-request-id", id_), ("traceparent", PARENT), ("baggage", CANARY), ("Authorization", f"Bearer {CANARY}"), *extra]:
            connection.putheader(name, value)
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 200, (response.status, response.read())
        assert response.read() == {"static.test": b"static", "proxy.test": b"proxy", "php.test": b"php"}[host]
    finally:
        connection.close()


def request_http2(listen, origin):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Local fixed fixture; upstream verification has its own smoke.
    context.set_alpn_protocols(["h2"])
    with socket.create_connection(("127.0.0.1", listen), timeout=10) as tcp:
        with context.wrap_socket(tcp, server_hostname="static.test") as stream:
            assert stream.version() in ("TLSv1.2", "TLSv1.3")
            assert stream.selected_alpn_protocol() == "h2"
            h2 = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
            h2.initiate_connection()
            expected, bodies = {}, {}
            for index in range(12):
                host = ("static.test", "proxy.test", "php.test")[index % 3]
                id_ = h2.get_next_available_stream_id()
                expected[id_] = {"static.test": b"static", "proxy.test": b"proxy", "php.test": b"php"}[host]
                bodies[id_] = bytearray()
                h2.send_headers(id_, [
                    (":method", "GET"), (":scheme", "https"), (":authority", host),
                    (":path", "/index.php" if host == "php.test" else "/index.html"),
                    ("x-request-id", f"h2-{index}"), ("traceparent", PARENT), ("baggage", CANARY),
                ], end_stream=True)
            stream.sendall(h2.data_to_send())
            completed = set()
            while len(completed) < len(expected):
                data = stream.recv(65536)
                assert data, "HTTP/2 ended before all streams"
                for event in h2.receive_data(data):
                    if isinstance(event, ResponseReceived):
                        assert dict(event.headers)[":status"] == "200", event
                    elif isinstance(event, DataReceived):
                        bodies[event.stream_id].extend(event.data)
                        h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded):
                        assert bodies[event.stream_id] == expected[event.stream_id]
                        completed.add(event.stream_id)
                    elif isinstance(event, StreamReset):
                        raise AssertionError(event)
                pending = h2.data_to_send()
                if pending:
                    stream.sendall(pending)
            id_ = h2.get_next_available_stream_id()
            h2.send_headers(id_, [(":method", "GET"), (":scheme", "https"), (":authority", "proxy.test"), (":path", "/cancel"), ("x-request-id", "cancel-h2"), ("traceparent", PARENT)], end_stream=True)
            stream.sendall(h2.data_to_send())
            assert origin.cancel_started.wait(5)
            h2.reset_stream(id_)
            stream.sendall(h2.data_to_send())
            time.sleep(0.1)
            origin.cancel_release.set()
            time.sleep(0.1)


def request_websocket(listen):
    with socket.create_connection(("127.0.0.1", listen), timeout=10) as stream:
        stream.sendall(("GET /ws HTTP/1.1\r\nHost: proxy.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nx-request-id: ws\r\ntraceparent: " + PARENT + "\r\n\r\n").encode())
        head = bytearray()
        while not head.endswith(b"\r\n\r\n"):
            head.extend(exactly(stream, 1))
            assert len(head) <= 8192
        assert head.startswith(b"HTTP/1.1 101 ")
        mask = bytes([1, 2, 3, 4])
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(CANARY.encode()))
        stream.sendall(bytes([0x81, 0x80 | len(CANARY)]) + mask + masked)
        assert exactly(stream, 2 + len(CANARY)) == bytes([0x81, len(CANARY)]) + CANARY.encode()


def request_keep_alive(listen):
    connection = http.client.HTTPConnection("127.0.0.1", listen, timeout=10)
    try:
        for index in range(2):
            headers = {"Host": "static.test", "x-request-id": f"keep-{index}"}
            if index == 0:
                headers["traceparent"] = PARENT
            connection.request("GET", "/index.html", headers=headers)
            response = connection.getresponse()
            assert response.status == 200 and response.read() == b"static"
    finally:
        connection.close()


def validate_container_image(image):
    if image is None:
        return None
    # Restrict the argument alphabet, not the registry choice. Podman validates
    # the full image-reference grammar and --pull=never requires a local image.
    if len(image) > 256 or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9./:@_-]*", image):
        raise ValueError("invalid container image reference")
    return image


def server_command(binary, config_path, root, container_image=None):
    image = validate_container_image(container_image)
    if image is None:
        return [str(binary), "--config", str(config_path)]
    return ["podman", "run", "--rm", "--pull=never", "--network=host",
            "--userns=keep-id", "--user", f"{os.getuid()}:{os.getgid()}",
            "--ulimit", "core=0:0", "--workdir", str(root),
            "--volume", f"{root}:{root}:Z",
            "--volume", f"{binary}:/fluxheim:ro,Z",
            "--entrypoint", "/fluxheim", "--", image,
            "--config", str(config_path)]


def run(binary, container_image=None):
    container_image = validate_container_image(container_image)
    collector = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    php = FastCGIServer(("127.0.0.1", 0), FastCGI)
    collector.payloads, origin.seen, php.seen = [], [], []
    origin.retried = False
    origin.cancel_started, origin.cancel_release = threading.Event(), threading.Event()
    servers = [collector, origin, php]
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()
    try:
        with private_fixture(fixture_parent(False)) as root:
            public, tls, admin, metrics = port(), port(), port(), port()
            (root / "token").write_text("correlation-test-secret")
            (root / "token").chmod(0o600)
            (root / "snapshot.key").write_bytes(b"k" * 32)
            (root / "snapshot.key").chmod(0o600)
            (root / "index.html").write_bytes(b"static")
            (root / "index.php").write_text("<?php echo 'php';")
            for source, dest in [("localhost-cert.pem", "cert.pem"), ("localhost-key.pem", "key.pem")]:
                shutil.copyfile(ROOT / "tests/fixtures/tls" / source, root / dest)
                (root / dest).chmod(0o600)
            config = root / "fluxheim.toml"
            def command(config_path):
                return server_command(binary, config_path, root, container_image)
            config.write_text(f'''[server]
listen = ["127.0.0.1:{public}"]
tls_listen = ["127.0.0.1:{tls}"]
trusted_proxies = ["127.0.0.1"]
[server.process]
# Interleave requests/streams without intentional cross-worker admission drops.
# The separate backpressure smoke qualifies bounded loss under contention.
threads = 1
upstream_keepalive_pool_size = 16
pid_file = "fluxheim.pid"
upgrade_sock = "upgrade.sock"
certificate_reload_sock = "reload.sock"
grace_period_seconds = 1
graceful_shutdown_timeout_seconds = 2
[logging]
format = "json"
[metrics]
enabled = true
listen = "127.0.0.1:{metrics}"
[admin]
enabled = true
listen = "127.0.0.1:{admin}"
token_file = "token"
snapshot_store = "snapshots"
snapshot_integrity_key_file = "snapshot.key"
[logging.file]
enabled = true
path = "events.log"
[tracing]
enabled = true
[tracing.otlp]
enabled = true
endpoint = "http://127.0.0.1:{collector.server_port}/v1/traces"
queue_size = 128
[tls]
enabled = true
backend = "rustls"
alpn = "http1-and-http2"
[[tls.certificates]]
cert_path = "cert.pem"
key_path = "key.pem"
[[vhosts]]
name = "static"
hosts = ["static.test"]
[vhosts.web]
root = "{root.as_posix()}"
[[vhosts]]
name = "proxy"
hosts = ["proxy.test"]
[vhosts.proxy]
upstreams = ["127.0.0.1:{origin.server_port}"]
upstream_tls = false
websocket = true
[[vhosts]]
name = "php"
hosts = ["php.test"]
[vhosts.php]
enabled = true
root = "{root.as_posix()}"
[vhosts.php.fpm]
mode = "external"
tcp = "127.0.0.1:{php.server_address[1]}"
allow_private_tcp_upstreams = true
''')
            # The real startup validator must reject identity-header clobbering,
            # even when access output is disabled but request IDs remain enabled.
            for header in ("x-authenticated-user", "x-ssl-client-cert", "x-client-ip", "x-envoy-external-address", "x-proxyuser-ip"):
                rejected = root / "rejected.toml"
                rejected.write_text(config.read_text() + f'\n[logging.access]\nenabled = false\nrequest_id_header = "{header}"\n')
                validation = subprocess.run(
                    command(rejected) + ["--validate-config"],
                    cwd=root, capture_output=True, timeout=30,
                )
                assert validation.returncode != 0, header
                assert b"logging.access.request_id_header" in validation.stdout + validation.stderr, validation.stderr
            with (root / "process.log").open("wb") as output:
                process = subprocess.Popen(command(config), cwd=root,
                    env=dict(os.environ, RUST_LOG="info"), stdout=output, stderr=output)
                try:
                    def ready():
                        assert process.poll() is None, (root / "process.log").read_text()
                        try:
                            with socket.create_connection(("127.0.0.1", public), timeout=0.2):
                                return True
                        except OSError:
                            return False
                    wait_for(ready)
                    with ThreadPoolExecutor(max_workers=12) as pool:
                        futures = [pool.submit(request_http1, public, ("static.test", "proxy.test", "php.test")[i % 3], f"h1-{i}") for i in range(12)]
                        h2_future = pool.submit(request_http2, tls, origin)
                        for future in futures:
                            future.result()
                        h2_future.result()
                    request_http1(public, "proxy.test", "retry-h1", path="/retry")
                    request_websocket(public)
                    request_keep_alive(public)
                    # Duplicate values are invalid even when identical; no concatenation or first-wins.
                    request_http1(public, "static.test", "duplicate", [("X-Request-ID", "duplicate"), ("TraceParent", PARENT)])
                    request_http1(public, "static.test", "a" * 4096, [("traceparent", "malformed")])
                    def access():
                        return [record for record in records(root / "events.log") if record.get("data", {}).get("kind") == "access"]
                    wait_for(lambda: len(access()) == 31)
                    def spans():
                        return [span for payload in collector.payloads for resource in payload["resourceSpans"] for scope in resource["scopeSpans"] for span in scope["spans"]]
                    try:
                        wait_for(lambda: len(spans()) == 48)  # Plus cancellation, retry and upgrade.
                    except AssertionError as error:
                        raise AssertionError((len(spans()), [(event["correlation"].get("request_id"), sum(span["spanId"] == event["correlation"].get("span_id") for span in spans()), sum(span.get("parentSpanId") == event["correlation"].get("span_id") for span in spans()), event["data"]["attempts"]) for event in access()])) from error
                    events = access()
                    by_id = {event["correlation"]["request_id"]: event for event in events}
                    assert len(by_id) == 31
                    trace_spans = spans()
                    assert len({span["spanId"] for span in trace_spans}) == 48
                    assert by_id["cancel-h2"]["data"]["outcome"] in ("cancelled", "failed")
                    assert by_id["retry-h1"]["data"]["attempts"] == 2
                    errors = [event for event in records(root / "events.log") if event.get("data", {}).get("kind") == "error"]
                    assert any(event.get("correlation") == by_id["retry-h1"]["correlation"] for event in errors), errors
                    assert by_id["ws"]["data"]["outcome"] == "completed"
                    assert by_id["ws"]["data"]["attempts"] == 1
                    assert by_id["keep-0"]["correlation"]["trace_id"] != by_id["keep-1"]["correlation"]["trace_id"]
                    for protocol in ("h1", "h2"):
                        for i in range(12):
                            event = by_id[f"{protocol}-{i}"]
                            assert event["data"]["outcome"] == "completed"
                            assert event["data"]["attempts"] == (0 if i % 3 == 0 else 1), event
                            correlation = event["correlation"]
                            matched = [span for span in trace_spans if span["spanId"] == correlation["span_id"]]
                            assert len(matched) == 1
                            assert matched[0]["traceId"] == correlation["trace_id"] == PARENT[3:35]
                            assert matched[0]["parentSpanId"] == PARENT[36:52]
                    for event in events:
                        if event["correlation"]["request_id"].startswith("fh-"):
                            assert event["correlation"]["trace_id"] != PARENT[3:35]
                            assert not any(span["spanId"] == event["correlation"]["span_id"] for span in trace_spans)
                    for headers in origin.seen:
                        headers = {key.lower(): value for key, value in headers.items()}
                        assert "baggage" not in headers
                        event = by_id[headers["x-request-id"]]
                        child = next(span for span in trace_spans if span["spanId"] == headers["traceparent"][36:52])
                        assert child["kind"] == "SPAN_KIND_CLIENT"
                        assert child["parentSpanId"] == event["correlation"]["span_id"]
                    for params in php.seen:
                        assert "HTTP_BAGGAGE" not in params
                        event = by_id[params["HTTP_X_REQUEST_ID"]]
                        child = next(span for span in trace_spans if span["spanId"] == params["HTTP_TRACEPARENT"][36:52])
                        assert child["parentSpanId"] == event["correlation"]["span_id"]
                    assert CANARY not in json.dumps(events) + json.dumps(collector.payloads)
                    status_code, status_body = admin_request(admin, "/_fluxheim/status", "correlation-test-secret")
                    assert status_code == 200
                    lane = json.loads(status_body)["operational_events"]["ordinary"]
                    assert lane["rate_limited"] == lane["queue_full"] == lane["unavailable"] == 0, lane
                    connection = http.client.HTTPConnection("127.0.0.1", metrics, timeout=5)
                    try:
                        connection.request("GET", "/metrics")
                        response = connection.getresponse()
                        assert response.status == 200
                        exposition = response.read().decode()
                    finally:
                        connection.close()
                    def total(name):
                        return sum(float(line.rsplit(" ", 1)[1]) for line in exposition.splitlines()
                                   if line.startswith(name + "{") or line.startswith(name + " "))
                    assert total("fluxheim_http_requests_total") == len(events), exposition
                    assert total("fluxheim_http_request_duration_seconds_count") == len(events)
                    assert total("fluxheim_upstream_attempts_total") == sum(e["data"]["attempts"] for e in events)
                    assert total("fluxheim_upstream_attempt_duration_seconds_count") == total("fluxheim_upstream_attempts_total")
                    assert total("fluxheim_http_requests_active") == total("fluxheim_upstream_attempts_active") == 0
                    assert total("fluxheim_http_response_body_bytes_total") == sum(e["data"]["bytes_sent"] for e in events if e["data"]["outcome"] == "completed")
                    # Multiplexed traffic and the reset share one TLS connection.
                    assert total("fluxheim_downstream_tls_handshakes_total") == 1
                    assert total("fluxheim_metric_series_overflow_total") == 0
                    assert len([line for line in exposition.splitlines() if line and not line.startswith("#")]) < 20000
                    assert CANARY not in exposition and PARENT not in exposition
                    assert 'fluxheim_log_dispatch_state{lane="ordinary",state="available"} 1' in exposition
                    print("request correlation: concurrent HTTP/1.1 + TLS HTTP/2 static/proxy/FastCGI, actual JSON/OTLP/errors, safe retry, reset, WebSocket, keep-alive, duplicate/oversized context, unsampled IDs: ok")
                    print("operational metrics: exact request/attempt/byte deltas, cancellation, histograms, TLS and dispatch health: ok")
                except Exception:
                    if process.poll() is None:
                        print("dispatcher status:", admin_request(admin, "/_fluxheim/status", "correlation-test-secret"))
                    print("correlation fixture diagnostics:", (root / "process.log").read_text(), [event for event in records(root / "events.log") if event.get("level") in ("ERROR", "WARN")])
                    print("access outcomes:", [(event.get("correlation"), event.get("data")) for event in records(root / "events.log") if event.get("data", {}).get("kind") == "access"])
                    print("FastCGI requests received:", len(php.seen))
                    raise
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--container-image", help="Optional already-pulled compatible Linux runtime image; runs the supplied binary in rootless Podman")
    args = parser.parse_args()
    run(args.binary.resolve(strict=True), args.container_image)
