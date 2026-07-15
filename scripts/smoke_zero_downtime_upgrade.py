#!/usr/bin/env python3
"""Prove readiness-gated listener handoff and old-generation drain."""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FLUXHEIM_BINARY = ROOT / "target/debug/fluxheim"


@dataclass
class ChildProcess:
    pid: int
    returncode: int | None = None

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        waited_pid, status = os.waitpid(self.pid, os.WNOHANG)
        if waited_pid == 0:
            return None
        self.returncode = os.waitstatus_to_exitcode(status)
        return self.returncode

    def wait(self, timeout: float) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.poll()
            if status is not None:
                return status
            time.sleep(0.01)
        raise subprocess.TimeoutExpired(str(FLUXHEIM_BINARY), timeout)

    def send_signal(self, requested_signal: int) -> None:
        os.kill(self.pid, requested_signal)

    def kill(self) -> None:
        self.send_signal(signal.SIGKILL)


@dataclass
class Generation:
    name: str
    process: ChildProcess
    notify: socket.socket
    log_handle: object
    log_path: Path

    def wait_for(self, marker: bytes, timeout: float = 8.0) -> bytes:
        deadline = time.monotonic() + timeout
        self.notify.settimeout(0.2)
        messages = bytearray()
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"{self.name} exited before {marker!r}:\n{self.log_path.read_text()}"
                )
            try:
                message = self.notify.recv(4096)
            except TimeoutError:
                continue
            messages.extend(message)
            if marker in message:
                return bytes(messages)
        raise RuntimeError(f"timed out waiting for {marker!r} from {self.name}")

    def terminate(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)

    def wait(self, timeout: float = 8.0) -> int:
        status = self.process.wait(timeout=timeout)
        self.log_handle.close()
        return status

    def cleanup(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=2.0)
        self.log_handle.close()
        self.notify.close()


def child_main(
    config: Path,
    listener_fd: int,
    notify_name: str,
    log_handle: object,
) -> None:
    source_fd = listener_fd
    if source_fd != 3:
        os.dup2(source_fd, 3, inheritable=True)
    else:
        os.set_inheritable(3, True)
    os.dup2(log_handle.fileno(), 1)
    os.dup2(log_handle.fileno(), 2)
    environment = os.environ.copy()
    environment.update(
        {
            "LISTEN_PID": str(os.getpid()),
            "LISTEN_FDS": "1",
            "LISTEN_FDNAMES": "http",
            "NOTIFY_SOCKET": "@" + notify_name,
        }
    )
    binary = str(FLUXHEIM_BINARY)
    os.execve(binary, [binary, "--config", str(config)], environment)


def secure_smoke_root() -> Path:
    parent = ROOT / "target/fluxheim-smoke-tmp"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent.chmod(0o700)
    return Path(tempfile.mkdtemp(prefix="fluxheim-upgrade-smoke-", dir=parent))


def write_config(
    root: Path,
    name: str,
    listen: str,
    content: str,
    blocked_admin_address: str | None = None,
) -> Path:
    generation = root / name
    public = generation / "public"
    run = generation / "run"
    public.mkdir(parents=True)
    run.mkdir()
    (public / "index.html").write_text(content + "\n", encoding="ascii")
    config = generation / "fluxheim.toml"
    config_text = f'''[server]
listen = ["{listen}"]
default_vhost = "upgrade.test"

[server.process]
pid_file = "{run}/fluxheim.pid"
upgrade_sock = "{run}/fluxheim-upgrade.sock"
certificate_reload_sock = "{run}/fluxheim-cert-reload.sock"
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
root = "{public}"
index_files = ["index.html"]
'''
    if blocked_admin_address is not None:
        snapshots = generation / "snapshots"
        snapshots.mkdir(mode=0o700)
        token = generation / "admin-token"
        token.write_text("fluxheim-upgrade-smoke-token\n", encoding="ascii")
        integrity_key = generation / "snapshot-integrity.key"
        integrity_key.write_text(
            "0123456789abcdef0123456789abcdef", encoding="ascii"
        )
        integrity_key.chmod(0o600)
        config_text += f'''
[admin]
enabled = true
listen = "{blocked_admin_address}"
require_loopback = true
token_file = "{token}"
snapshot_store = "{snapshots}"
snapshot_integrity_key_file = "{integrity_key}"
'''
    config.write_text(config_text, encoding="ascii")
    return config


def launch(
    config: Path,
    listener: socket.socket,
    root: Path,
    name: str,
) -> Generation:
    notify_name = f"fluxheim-upgrade-{os.getpid()}-{name}"
    notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    notify.bind("\0" + notify_name)
    log_path = root / f"{name}.log"
    log_handle = log_path.open("wb")
    pid = os.fork()
    if pid == 0:
        notify.close()
        try:
            child_main(config, listener.fileno(), notify_name, log_handle)
        except BaseException as error:
            message = f"zero-downtime smoke child failed before exec: {error}\n".encode(
                "utf-8", errors="replace"
            )
            os.write(2, message)
        finally:
            os._exit(127)
    process = ChildProcess(pid)
    return Generation(name, process, notify, log_handle, log_path)


def read_response(client: socket.socket) -> bytes:
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = client.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before response headers")
        response.extend(chunk)
    head, body = bytes(response).split(b"\r\n\r\n", 1)
    content_length = None
    for line in head.split(b"\r\n")[1:]:
        key, separator, value = line.partition(b":")
        if separator and key.lower() == b"content-length":
            content_length = int(value.strip())
            break
    if content_length is None:
        raise RuntimeError("response omitted content-length")
    while len(body) < content_length:
        chunk = client.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before response body")
        body += chunk
    return head + b"\r\n\r\n" + body[:content_length]


def request(port: int) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=1.0) as client:
        client.settimeout(2.0)
        client.sendall(
            b"GET / HTTP/1.1\r\nHost: upgrade.test\r\nConnection: close\r\n\r\n"
        )
        return read_response(client)


def assert_body(response: bytes, expected: bytes) -> None:
    if b"HTTP/1.1 200 OK" not in response or expected not in response:
        raise RuntimeError(f"unexpected HTTP response: {response!r}")


def parent_main() -> None:
    if not FLUXHEIM_BINARY.is_file():
        raise RuntimeError(f"Fluxheim smoke binary is missing: {FLUXHEIM_BINARY}")
    root = secure_smoke_root()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    address = f"127.0.0.1:{port}"
    generations: list[Generation] = []
    persistent: socket.socket | None = None
    blocked_admin = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocked_admin.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    blocked_admin.bind(("127.0.0.1", 0))
    blocked_admin.listen(1)
    try:
        old_config = write_config(root, "old", address, "generation-old")
        new_config = write_config(root, "new", address, "generation-new")
        with socket.socket() as wrong_socket:
            wrong_socket.bind(("127.0.0.1", 0))
            wrong_address = f"127.0.0.1:{wrong_socket.getsockname()[1]}"
        failed_config = write_config(root, "failed", wrong_address, "generation-failed")
        late_failed_config = write_config(
            root,
            "late-failed",
            address,
            "generation-not-ready",
            f"127.0.0.1:{blocked_admin.getsockname()[1]}",
        )

        old = launch(old_config, listener, root, "old")
        generations.append(old)
        assert b"STATUS=Fluxheim native runtime ready" in old.wait_for(b"READY=1")
        assert_body(request(port), b"generation-old")

        persistent = socket.create_connection(("127.0.0.1", port), timeout=2.0)
        persistent.settimeout(2.0)
        persistent.sendall(b"GET / HTTP/1.1\r\nHost: upgrade.test\r\n\r\n")
        assert_body(read_response(persistent), b"generation-old")

        failed = launch(failed_config, listener, root, "failed")
        generations.append(failed)
        if failed.wait(timeout=5.0) == 0:
            raise RuntimeError("invalid replacement unexpectedly started")
        assert_body(request(port), b"generation-old")

        late_failed = launch(late_failed_config, listener, root, "late-failed")
        generations.append(late_failed)
        deadline = time.monotonic() + 5.0
        while late_failed.process.poll() is None and time.monotonic() < deadline:
            assert_body(request(port), b"generation-old")
        if late_failed.wait(timeout=5.0) == 0:
            raise RuntimeError("late-failing replacement unexpectedly started")
        for _ in range(20):
            assert_body(request(port), b"generation-old")

        new = launch(new_config, listener, root, "new")
        generations.append(new)
        assert b"STATUS=Fluxheim native runtime ready" in new.wait_for(b"READY=1")

        old.terminate()
        assert b"STATUS=Fluxheim native runtime draining" in old.wait_for(b"STOPPING=1")
        persistent.sendall(
            b"GET / HTTP/1.1\r\nHost: upgrade.test\r\nConnection: close\r\n\r\n"
        )
        assert_body(read_response(persistent), b"generation-old")
        persistent.close()
        persistent = None

        for _ in range(40):
            response = request(port)
            if b"generation-new" in response:
                break
            time.sleep(0.025)
        else:
            raise RuntimeError("new requests did not move to ready replacement")
        for _ in range(20):
            assert_body(request(port), b"generation-new")

        if old.wait(timeout=7.0) != 0:
            raise RuntimeError("old generation did not drain cleanly")
        assert_body(request(port), b"generation-new")

        new.terminate()
        new.wait_for(b"STOPPING=1")
        if new.wait(timeout=7.0) != 0:
            raise RuntimeError("new generation did not stop cleanly")
        print("zero-downtime upgrade smoke passed")
    finally:
        if persistent is not None:
            persistent.close()
        for generation in generations:
            generation.cleanup()
        blocked_admin.close()
        listener.close()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    parent_main()
