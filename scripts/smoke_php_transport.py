#!/usr/bin/env python3
"""Actual Fluxheim HTTP against a bounded loopback FastCGI protocol fixture.

This captures wire behavior; it is not PHP interpreter/application qualification.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time

from smoke_geoip_examples import replace_once
from smoke_php_examples import EXTERNAL, ROOT, gateway, port, prepare, request


def exactly(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise EOFError("truncated fixture input")
        data.extend(chunk)
    return bytes(data)


def parameters(data):
    offset, result = 0, {}
    while offset < len(data):
        lengths = []
        for _ in range(2):
            if offset >= len(data):
                raise ValueError("missing length")
            width = 4 if data[offset] & 128 else 1
            if offset + width > len(data):
                raise ValueError("truncated length")
            lengths.append(int.from_bytes(data[offset:offset + width], "big") & 0x7fffffff)
            offset += width
        name, value = lengths
        if offset + name + value > len(data):
            raise ValueError("truncated parameter")
        key = data[offset:offset + name].decode("utf-8")
        result[key] = data[offset + name:offset + name + value].decode("utf-8")
        offset += name + value
    return result


@contextmanager
def backend(status=200, delay=0, stderr=b""):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.server.connections.append(True)
            self.request.settimeout(5)
            try:
                while True:
                    params, body = bytearray(), bytearray()
                    keepalive, begun = False, False
                    for _ in range(128):
                        version, kind, identity, size, padding, _ = struct.unpack(
                            "!BBHHBB", exactly(self.request, 8))
                        if version != 1 or identity == 0:
                            raise ValueError("unexpected FastCGI framing")
                        data = exactly(self.request, size)
                        exactly(self.request, padding)
                        if kind == 1:
                            begun = True
                            keepalive = len(data) >= 3 and bool(data[2] & 1)
                        elif kind == 4:
                            params.extend(data)
                        elif kind == 5:
                            body.extend(data)
                            if not size and begun:
                                break
                        if len(params) > 16384 or len(body) > 16384:
                            raise ValueError("fixture input bound")
                    else:
                        raise ValueError("fixture record bound")
                    self.server.seen.append((parameters(params), bytes(body)))
                    if self.server.stop.wait(delay):
                        return
                    payload = json.dumps({"received": len(body)}).encode()
                    output = (f"Status: {status}\r\nContent-Type: application/json\r\n\r\n".encode()
                              + payload)
                    for kind, data in ((7, stderr), (6, output), (6, b""), (3, bytes(8))):
                        self.request.sendall(struct.pack("!BBHHBB", 1, kind, identity, len(data), 0, 0) + data)
                    if not keepalive:
                        self.request.shutdown(socket.SHUT_WR)
                        drained = 0
                        while data := self.request.recv(4096):
                            drained += len(data)
                            if drained > 65536:
                                raise ValueError("trailing input bound")
                        return
            except (EOFError, ConnectionError, TimeoutError):
                return
            except Exception as error:
                self.server.errors.append(error)

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = False

    server = Server(("127.0.0.1", 0), Handler)
    server.seen, server.errors, server.connections, server.stop = [], [], [], threading.Event()
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield server
    finally:
        server.stop.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=6)
        assert not thread.is_alive() and not server.errors, server.errors


def php_fields(source, text):
    return replace_once(source, "[vhosts.php]\n", "[vhosts.php]\n" + text + "\n")


def main():
    if not __debug__:
        raise SystemExit("smoke requires assertions")
    os.umask(0o077)
    parent = subprocess.check_output(["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")],
                                     text=True, timeout=10).strip()
    with tempfile.TemporaryDirectory(prefix="php-transport-", dir=parent) as directory:
        root = Path(directory)
        (root / "public").mkdir()
        (root / "public/index.php").write_text("<?php // protocol fixture only\n")
        listen = port()
        with backend() as fpm:
            source = prepare(EXTERNAL.read_text(), listen, fpm.server_address[1])
            for spool in (False, True):
                extra = ""
                if spool:
                    extra = ('request_body_spool_threshold_bytes = "32B"\n'
                             'request_body_spool_dir = "spool"')
                with gateway(root, php_fields(source, extra), listen):
                    assert request(listen, method="POST", body=b"x" * 128)[0] == 200
                    params, body = fpm.seen[-1]
                    assert params["CONTENT_LENGTH"] == "128" and body == b"x" * 128
                with gateway(root, php_fields(source, extra + "\npass_request_body = false"), listen):
                    assert request(listen, method="POST", body=b"x" * 128)[0] == 200
                    params, body = fpm.seen[-1]
                    # documented contract: disabled forwarding still advertises the original length.
                    assert params["CONTENT_LENGTH"] == "128" and body == b""
            keepalive = replace_once(source, 'mode = "external"', 'mode = "external"\nkeepalive = true')
            connections_before = len(fpm.connections)
            with gateway(root, keepalive, listen):
                for _ in range(3):
                    assert request(listen)[0] == 200
                assert len(fpm.connections) == connections_before + 1
        print("PHP wire: memory/spooled replay, body-disable length gap and keepalive: ok")

        with backend(503) as first, backend(200, delay=1.25) as second:
            source = prepare(EXTERNAL.read_text(), listen, first.server_address[1])
            source = replace_once(source, f'tcp = "127.0.0.1:{first.server_address[1]}"',
                                  f'tcp_upstreams = ["127.0.0.1:{first.server_address[1]}", '
                                  f'"127.0.0.1:{second.server_address[1]}"]\n'
                                  'max_retries = 0\nretry_timeout_secs = 1\nretry_statuses = [503]')
            with gateway(root, source, listen):
                started = time.monotonic()
                assert request(listen)[0] == 200
                # documented contract: deadline gates retry admission, not the in-progress attempt.
                assert time.monotonic() - started >= 1.2
                assert len(first.seen) == len(second.seen) == 1
            with gateway(root, source, listen):
                assert request(listen, method="POST", body=b"no-replay")[0] == 503
                assert len(first.seen) == 2 and len(second.seen) == 1
        print("PHP wire: automatic multi-endpoint retry, deadline overrun, POST no-retry: ok")

        with backend(stderr=b"fixture-fatal") as fpm:
            source = prepare(EXTERNAL.read_text(), listen, fpm.server_address[1])
            with gateway(root, php_fields(source, 'stderr_failure_patterns = ["fixture-fatal"]'), listen):
                assert request(listen)[0] == 502
        print("PHP wire: configured STDERR failure pattern rejects response: ok")


if __name__ == "__main__":
    main()
