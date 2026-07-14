#!/usr/bin/env python3
"""Exercise a Podman blue/green handoff behind one stable TCP owner."""

from __future__ import annotations

import os
import shutil
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def secure_smoke_root() -> Path:
    parent = ROOT / "target/fluxheim-smoke-tmp"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent.chmod(0o700)
    return Path(tempfile.mkdtemp(prefix="fluxheim-podman-upgrade-smoke-", dir=parent))


def free_ports(count: int) -> list[int]:
    listeners = []
    try:
        for _ in range(count):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listeners.append(listener)
        return [listener.getsockname()[1] for listener in listeners]
    finally:
        for listener in listeners:
            listener.close()


def podman(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["podman", *args], check=check, capture_output=True, text=True
    )


def write_generation(root: Path, name: str, body: str) -> tuple[Path, Path]:
    generation = root / name
    public = generation / "public"
    public.mkdir(parents=True)
    (public / "index.html").write_text(body + "\n", encoding="ascii")
    config = generation / "fluxheim.toml"
    config.write_text(
        f'''[server]
listen = ["0.0.0.0:8080"]
default_vhost = "upgrade.test"

[server.process]
graceful_shutdown_timeout_seconds = 5

[logging]
level = "info"
format = "text"
target = "stderr"

[logging.access]
enabled = false
request_id = false

[proxy]
upstreams = ["127.0.0.1:9"]
upstream_tls = false

[tls]
enabled = false
backend = "rustls"

[cache]
enabled = false

[[vhosts]]
name = "upgrade.test"
hosts = ["upgrade.test"]

[vhosts.web]
root = "/srv/fluxheim"
index_files = ["index.html"]
''',
        encoding="ascii",
    )
    return config, public


def run_container(
    image: str,
    name: str,
    port: int,
    config: Path,
    public: Path,
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return podman(
        "run",
        "--detach",
        "--name",
        name,
        "--publish",
        f"127.0.0.1:{port}:8080",
        "--volume",
        f"{config}:/etc/fluxheim/fluxheim.toml:ro,Z",
        "--volume",
        f"{public}:/srv/fluxheim:ro,Z",
        image,
        "--config",
        "/etc/fluxheim/fluxheim.toml",
        check=check,
    )


def read_response(client: socket.socket) -> bytes:
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = client.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before response headers")
        response.extend(chunk)
    head, body = bytes(response).split(b"\r\n\r\n", 1)
    length = None
    for line in head.split(b"\r\n")[1:]:
        key, separator, value = line.partition(b":")
        if separator and key.lower() == b"content-length":
            length = int(value.strip())
            break
    if length is None:
        raise RuntimeError("response missing content-length")
    while len(body) < length:
        chunk = client.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before response body")
        body += chunk
    return head + b"\r\n\r\n" + body[:length]


def request(port: int) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=1.0) as client:
        client.settimeout(2.0)
        client.sendall(
            b"GET / HTTP/1.1\r\nHost: upgrade.test\r\nConnection: close\r\n\r\n"
        )
        return read_response(client)


def wait_for_body(port: int, body: bytes, timeout: float = 12.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if body in request(port):
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for {body!r} on port {port}")


class StableFront:
    def __init__(self, target_port: int) -> None:
        self._target_port = target_port
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(128)
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def switch(self, target_port: int) -> None:
        with self._lock:
            self._target_port = target_port

    def close(self) -> None:
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=2.0)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with self._lock:
                target_port = self._target_port
            threading.Thread(
                target=self._relay,
                args=(client, target_port),
                daemon=True,
            ).start()

    @staticmethod
    def _relay(client: socket.socket, target_port: int) -> None:
        try:
            upstream = socket.create_connection(("127.0.0.1", target_port), timeout=2.0)
        except OSError:
            client.close()
            return
        with client, upstream:
            client.setblocking(False)
            upstream.setblocking(False)
            selector = selectors.DefaultSelector()
            selector.register(client, selectors.EVENT_READ, upstream)
            selector.register(upstream, selectors.EVENT_READ, client)
            while True:
                events = selector.select(timeout=5.0)
                if not events:
                    break
                for key, _ in events:
                    try:
                        data = key.fileobj.recv(65_536)
                    except BlockingIOError:
                        continue
                    if not data:
                        return
                    key.data.sendall(data)


def main(image: str) -> None:
    root = secure_smoke_root()
    prefix = f"fluxheim-upgrade-{os.getpid()}"
    blue_name = prefix + "-blue"
    green_name = prefix + "-green"
    failed_name = prefix + "-failed"
    direct_name = prefix + "-direct-conflict"
    containers = [blue_name, green_name, failed_name, direct_name]
    front: StableFront | None = None
    persistent: socket.socket | None = None
    try:
        blue_config, blue_public = write_generation(root, "blue", "container-blue")
        green_config, green_public = write_generation(root, "green", "container-green")
        failed_config, failed_public = write_generation(root, "failed", "container-failed")
        failed_config.write_text("this is not valid toml = [", encoding="ascii")
        blue_port, green_port, failed_port = free_ports(3)

        run_container(image, blue_name, blue_port, blue_config, blue_public)
        wait_for_body(blue_port, b"container-blue")
        direct = run_container(
            image,
            direct_name,
            blue_port,
            green_config,
            green_public,
            check=False,
        )
        if direct.returncode == 0:
            raise RuntimeError("second direct-published container unexpectedly owned blue port")
        front = StableFront(blue_port)
        wait_for_body(front.port, b"container-blue")

        persistent = socket.create_connection(("127.0.0.1", front.port), timeout=2.0)
        persistent.settimeout(2.0)
        persistent.sendall(b"GET / HTTP/1.1\r\nHost: upgrade.test\r\n\r\n")
        if b"container-blue" not in read_response(persistent):
            raise RuntimeError("persistent request did not reach blue")

        run_container(image, failed_name, failed_port, failed_config, failed_public)
        status = int(podman("wait", failed_name).stdout.strip())
        if status == 0:
            raise RuntimeError("invalid replacement container unexpectedly started")
        wait_for_body(front.port, b"container-blue")

        run_container(image, green_name, green_port, green_config, green_public)
        wait_for_body(green_port, b"container-green")
        front.switch(green_port)
        for _ in range(20):
            if b"container-green" not in request(front.port):
                raise RuntimeError("new connection did not reach green after switch")

        podman("kill", "--signal", "TERM", blue_name)
        persistent.sendall(
            b"GET / HTTP/1.1\r\nHost: upgrade.test\r\nConnection: close\r\n\r\n"
        )
        if b"container-blue" not in read_response(persistent):
            raise RuntimeError("blue keep-alive did not drain after switch")
        persistent.close()
        persistent = None
        if int(podman("wait", blue_name).stdout.strip()) != 0:
            raise RuntimeError("blue container did not drain cleanly")
        wait_for_body(front.port, b"container-green")
        print("Podman blue/green upgrade smoke passed")
    finally:
        if persistent is not None:
            persistent.close()
        if front is not None:
            front.close()
        for container in containers:
            podman("rm", "--force", container, check=False)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} IMAGE")
    main(sys.argv[1])
