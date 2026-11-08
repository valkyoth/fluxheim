#!/usr/bin/env python3
"""Test TCP readiness-port isolation with a trusted local binary or smoke image.

All listeners are numeric loopback only. --container reuses the bounded,
non-root Podman fixture controls; this is not an untrusted-image sandbox.
"""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import uuid

import smoke_load_balancer_examples as smoke
import smoke_load_balancer_retry_container as container


class Readiness:
    def __init__(self):
        self.port = 0
        self.socket = None
        self.worker = None
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.connections = 0
        self.payload = False
        self.error = None

    def start(self):
        self.stop.clear()
        listener = socket.socket()
        if os.name != "nt":
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self.port))
        listener.listen(32)
        listener.settimeout(0.2)
        self.socket = listener
        self.port = listener.getsockname()[1]
        self.worker = threading.Thread(target=self.serve, args=(listener,), daemon=True)
        self.worker.start()

    def serve(self, listener):
        try:
            while not self.stop.is_set():
                try:
                    stream, _ = listener.accept()
                except TimeoutError:
                    continue
                with stream:
                    stream.settimeout(2)
                    data = stream.recv(1)
                    with self.lock:
                        self.connections += 1
                        self.payload |= bool(data)
        except OSError as error:
            with self.lock:
                self.error = error

    def close(self):
        self.stop.set()
        if self.worker:
            self.worker.join(timeout=4)
            if self.worker.is_alive():
                raise AssertionError("readiness fixture did not stop")
        if self.socket:
            self.socket.close()
            self.socket = None

    def assert_clean(self):
        with self.lock:
            assert self.connections > 0, "no probes reached readiness"
            assert not self.payload, "application traffic was sent to readiness"
            assert self.error is None, f"readiness fixture failed: {self.error}"


def configuration(public, first, second, ready, guest=False):
    source = smoke.prepare((smoke.EXAMPLES / "local.toml").read_text(), public, first, second)
    marker = "[proxy.load_balance.health_check]\n"
    if source.count(marker) != 1:
        raise ValueError("ambiguous health-check table")
    policy = (smoke.EXAMPLES / "tcp-health.toml").read_text()
    source = source.split(marker, 1)[0] + smoke.replace_once(policy, "port_override = 9100", f"port_override = {ready}")
    if guest:
        for name in ("fluxheim.pid", "upgrade.sock", "reload.sock"):
            source = smoke.replace_once(source, f'"{name}"', f'"/run/fluxheim/{name}"')
    return source


class ContainerProcess:
    def __init__(self, name):
        self.name = name
        self.returncode = None

    def poll(self):
        state = json.loads(container.engine("inspect", self.name))[0]["State"]
        self.returncode = None if state["Running"] else state["ExitCode"]
        return self.returncode


@contextmanager
def server(config, log, digest):
    if digest is not None:
        name = "fluxheim-retry-" + uuid.uuid4().hex
        config.chmod(0o644)  # Public fixture read by the non-root container.
        try:
            container.engine(*container.run_arguments(name, digest, config))
            yield ContainerProcess(name)
            container.engine("stop", "--time", "15", name)
            assert ContainerProcess(name).poll() == 0, "unclean container shutdown"
        finally:
            container.engine("rm", "--force", "--ignore", name)
    else:
        command = [str(smoke.BINARY), "--config", str(config)]
        smoke.validate_command(command, log)
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
        try:
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def run_case(parent, digest=None):
    first_calls, second_calls = smoke.OriginCalls(), smoke.OriginCalls()
    ready = Readiness()
    try:
        ready.start()
        with smoke.origin("origin-a", first_calls) as (first, a), smoke.origin("origin-b", second_calls) as (second, b):
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                public = reservation.getsockname()[1]
            with smoke.private_fixture(None if os.name == "nt" else parent) as directory, tempfile.TemporaryFile() as log:
                config = Path(directory) / "fluxheim.toml"
                config.write_text(configuration(public, first, second, ready.port, digest is not None), encoding="utf-8")
                with server(config, log, digest) as process:
                    both = lambda: {smoke.request(public) for _ in range(6)} == {(200, b"origin-a"), (200, b"origin-b")}
                    smoke.wait_for(process, both, "TCP readiness: both application members")
                    ready.close()
                    smoke.wait_for(process, lambda: smoke.request(public)[0] == 503, "TCP readiness: all down")
                    before = first_calls.count(), second_calls.count()
                    assert all(smoke.request(public)[0] == 503 for _ in range(4))
                    assert before == (first_calls.count(), second_calls.count()), "unhealthy member contacted"
                    ready.start()
                    smoke.wait_for(process, both, "TCP readiness: recovery")
                    # TCP readiness does not inspect HTTP application status.
                    a.clear()
                    b.clear()
                    assert {smoke.request(public) for _ in range(6)} == {(503, b"origin-a"), (503, b"origin-b")}
                    ready.assert_clean()
        print(f"TCP health port {'container' if digest else 'native'}: routing, all-down, recovery, isolation: ok")
    finally:
        ready.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work_root", type=Path)
    parser.add_argument("--container", action="store_true")
    args = parser.parse_args()
    digest = None
    if args.container:
        assert container.engine("info", "--format", "{{.Host.Security.Rootless}}") == "true"
        image = os.environ.get("FLUXHEIM_LB_CONTAINER_SMOKE_IMAGE", container.IMAGE)
        inspected = json.loads(container.engine("image", "inspect", "--", image))[0]
        assert inspected["Config"]["User"] == "65532:65532"
        digest = inspected["Id"]
    run_case(args.work_root.resolve(strict=True), digest)


if __name__ == "__main__":
    main()
