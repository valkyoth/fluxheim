#!/usr/bin/env python3
"""Run the checked-in guide recipes against local readiness-aware origins.

Called by smoke_load_balancer.sh after building the trusted local executable.
All listeners are loopback-only. Windows uses protected user-local temporary
directories; other platforms use the parent smoke's private root.
"""

import argparse
from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from smoke_log_file_rotation import private_fixture


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples/load-balancer"
BINARY = ROOT / "target/debug" / ("fluxheim.exe" if os.name == "nt" else "fluxheim")


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"example no longer contains exactly one {old!r}")
    return text.replace(old, new, 1)


def prepare(source, public, first, second, advanced=False):
    for old, new in ((8088, public), (9001, first), (9002, second)):
        source = replace_once(source, f'"127.0.0.1:{old}"', f'"127.0.0.1:{new}"')
    if advanced:
        marker = "[proxy.load_balance.health_check]\n"
        if source.count(marker) != 1:
            raise ValueError("ambiguous health-check table")
        source = source.split(marker, 1)[0] + (EXAMPLES / "http-health.toml").read_text()
    return source


class OriginCalls:
    def __init__(self):
        self.lock = threading.Lock()
        self.value = 0
        self.header_delay = 0
        self.body_delay = 0

    def increment(self):
        with self.lock:
            self.value += 1

    def count(self):
        with self.lock:
            return self.value

    def set_timing(self, header, body=0):
        if not (0 <= header <= 1 and 0 <= body <= 1):
            raise ValueError("fixture delays must be between zero and one second")
        with self.lock:
            self.header_delay, self.body_delay = header, body

    def timing(self):
        with self.lock:
            return self.header_delay, self.body_delay


@contextmanager
def origin(label, calls=None):
    ready = threading.Event()
    ready.set()
    body = (EXAMPLES / label / "index.html").read_bytes()
    health = (EXAMPLES / label / "healthz").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            header_delay, body_delay = 0, 0
            if calls is not None:
                calls.increment()
                header_delay, body_delay = calls.timing()
            is_health = self.path == "/healthz"
            payload = health if is_health else body
            time.sleep(header_delay)
            self.send_response(200 if ready.is_set() else 503)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Content-Type", "application/json" if is_health else "text/plain")
            self.send_header("x-health-state", "ready" if ready.is_set() else "down")
            self.end_headers()
            self.wfile.flush()
            time.sleep(body_delay)
            self.wfile.write(payload)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_address[1], ready
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def request(port):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", "/")
        response = connection.getresponse()
        body = response.read(4097)
        if len(body) > 4096:
            raise AssertionError("unexpectedly large guide response")
        return response.status, body.strip()
    finally:
        connection.close()


def wait_for(process, predicate, label):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"{label}: server exited {process.returncode}")
        try:
            if predicate():
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.2)
    raise AssertionError(f"{label}: readiness condition timed out")


def validate_command(command, log):
    try:
        subprocess.run(command + ["--validate-config"], check=True, timeout=20,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
    except subprocess.CalledProcessError:
        log.seek(0)
        print(log.read(8192).decode("utf-8", errors="replace"))
        raise


def run_case(parent, advanced):
    with origin("origin-a") as (first, a), origin("origin-b") as (second, b):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            public = reservation.getsockname()[1]
        with private_fixture(None if os.name == "nt" else parent) as directory, tempfile.TemporaryFile() as log:
            config = Path(directory) / "fluxheim.toml"
            config.write_text(prepare((EXAMPLES / "local.toml").read_text(), public,
                                      first, second, advanced), encoding="utf-8")
            command = [str(BINARY), "--config", str(config)]
            validate_command(command, log)
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=log)
            try:
                both = lambda: {request(public) for _ in range(6)} == {
                    (200, b"origin-a"), (200, b"origin-b")}
                wait_for(process, both, "two ready origins")
                a.clear()
                wait_for(process, lambda: all(request(public) == (200, b"origin-b")
                                             for _ in range(6)), "application-readiness failover")
                a.set()
                wait_for(process, both, "recovery")
                a.clear()
                b.clear()
                wait_for(process, lambda: request(public)[0] == 503, "all down")
                # An origin also returns 503, so status alone cannot prove ejection.
                def unavailable():
                    responses = [request(public) for _ in range(6)]
                    return all(status == 503 and body not in (b"origin-a", b"origin-b")
                               for status, body in responses)

                wait_for(process, unavailable, "no unhealthy origin selected")
                print(f"load-balancer guide {'advanced HTTP' if advanced else 'local'}: ok")
            except Exception:
                log.seek(0)
                print(log.read(8192).decode("utf-8", errors="replace"))
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


def retry_config(source, public, first, second, enabled):
    source = prepare(source, public, first, second)
    source = replace_once(source, "[proxy]\n", "[proxy]\nupstream_priority_groups = [20, 10]\n")
    marker = "[proxy.load_balance.health_check]\n"
    if source.count(marker) != 1:
        raise ValueError("ambiguous health-check table")
    source = source.split(marker, 1)[0]
    return source + (
        "[proxy.load_balance.health_check]\nenabled = false\n"
        "[proxy.load_balance.retry]\n"
        f"enabled = {'true' if enabled else 'false'}\n"
        'max_retries = 1\nmethods = ["GET"]\nstatuses = [503]\n'
        "budget_per_window = 1\nbudget_window_secs = 3600\n"
    )


def listener_ready(port):
    with socket.create_connection(("127.0.0.1", port), timeout=0.5):
        return True


def assert_retry_sequence(public, enabled, ready, first_calls, second_calls):
    assert request(public) == ((200, b"origin-b") if enabled else (503, b"origin-a"))
    assert first_calls.count() == 1
    assert second_calls.count() == int(enabled)
    assert request(public) == (503, b"origin-a"), "exhausted/disabled budget"
    assert first_calls.count() == 2
    assert second_calls.count() == int(enabled)
    ready.set()
    assert request(public) == (200, b"origin-a"), "initial sends remain available"
    assert first_calls.count() == 3
    assert second_calls.count() == int(enabled)


def run_retry_case(parent, enabled):
    first_calls, second_calls = OriginCalls(), OriginCalls()
    with origin("origin-a", first_calls) as (first, a), origin("origin-b", second_calls) as (second, _b):
        a.clear()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            public = reservation.getsockname()[1]
        with private_fixture(None if os.name == "nt" else parent) as directory, tempfile.TemporaryFile() as log:
            config = Path(directory) / "fluxheim.toml"
            source = retry_config((EXAMPLES / "local.toml").read_text(), public, first, second, enabled)
            command = [str(BINARY), "--config", str(config)]
            if enabled:
                for budget in ("", "budget_per_window = 0\n"):
                    config.write_text(replace_once(source, "budget_per_window = 1\n", budget), encoding="utf-8")
                    rejected = subprocess.run(command + ["--validate-config"], timeout=20,
                                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
                    log.seek(0)
                    error = log.read(8192)
                    assert rejected.returncode != 0 and b"retry.budget_per_window" in error, "unsafe retry budget accepted"
                    assert first_calls.count() + second_calls.count() == 0, "invalid config contacted an origin"
                    log.seek(0)
                    log.truncate()
                print("load-balancer missing/zero retry budgets rejected: ok")
            config.write_text(source, encoding="utf-8")
            validate_command(command, log)
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
            try:
                # Socket readiness must not consume an application retry/budget.
                wait_for(process, lambda: listener_ready(public), "retry listener")
                assert_retry_sequence(public, enabled, a, first_calls, second_calls)
                print(f"load-balancer guide retries {'enabled' if enabled else 'disabled'}: ok")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


def latency_config(source, public, first, second, mode):
    if mode not in ("selection", "passive", "disabled", "body"):
        raise ValueError("unknown latency fixture")
    source = prepare(source, public, first, second)
    source = replace_once(source, 'selection = "round-robin"', 'selection = "least-time"')
    marker = "[proxy.load_balance.health_check]\n"
    if source.count(marker) != 1:
        raise ValueError("ambiguous health-check table")
    threshold = {"selection": 0, "passive": 10, "disabled": 0, "body": 200}[mode]
    return source.split(marker, 1)[0] + (
        "[proxy.load_balance.health_check]\nenabled = false\n"
        "[proxy.load_balance.passive_health]\nenabled = true\n"
        f"max_latency_ms = {threshold}\nconsecutive_failure = 1\n"
        "min_healthy_backends = 0\nejection_secs = 120\n"
    )


def expect_latency_preference(public, expected):
    deadline = time.monotonic() + 10
    consecutive = 0
    observations = []
    # EWMA convergence depends on previous samples, including runner scheduling.
    # Bound convergence below the 30-second stale-sample reset, rather than
    # requiring a single new sample to outweigh every earlier measurement.
    for _ in range(12):
        status, body = request(public)
        assert status == 200 and body in (b"origin-a", b"origin-b"), "unexpected latency response"
        observations.append(body)
        if time.monotonic() >= deadline:
            break
        consecutive = consecutive + 1 if body == expected else 0
        if consecutive == 3:
            return
    raise AssertionError(f"latency preference did not converge to {expected!r}: {observations!r}")


def assert_latency_sequence(public, mode, first_calls, second_calls):
    if mode == "selection":
        first_calls.set_timing(0.12)
        second_calls.set_timing(0.001)
        assert {request(public) for _ in range(2)} == {(200, b"origin-a"), (200, b"origin-b")}
        expect_latency_preference(public, b"origin-b")
        first_calls.set_timing(0.001)
        second_calls.set_timing(0.8)
        assert request(public) == (200, b"origin-b")
        expect_latency_preference(public, b"origin-a")
        second_calls.set_timing(0.001)
        before = first_calls.count(), second_calls.count()
        time.sleep(30.1)  # Stale members must be sampled again without a configuration reload.
        for _ in range(4):
            assert request(public)[0] == 200
        assert first_calls.count() > before[0] and second_calls.count() > before[1], "stale member never resampled"
    else:
        for calls in (first_calls, second_calls):
            calls.set_timing(0 if mode == "body" else 0.03, 0.4 if mode == "body" else 0)
        for _ in range(2):
            assert request(public)[0] == 200
        if mode == "passive":
            assert request(public)[0] == 503
            assert first_calls.count() + second_calls.count() == 2, "ejected member was contacted"
        else:
            assert all(request(public)[0] == 200 for _ in range(3)), "body time or disabled threshold caused ejection"


def run_latency_case(parent, mode):
    first_calls, second_calls = OriginCalls(), OriginCalls()
    with origin("origin-a", first_calls) as (first, _a), origin("origin-b", second_calls) as (second, _b):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            public = reservation.getsockname()[1]
        with private_fixture(None if os.name == "nt" else parent) as directory, tempfile.TemporaryFile() as log:
            config = Path(directory) / "fluxheim.toml"
            config.write_text(latency_config((EXAMPLES / "local.toml").read_text(), public, first, second, mode), encoding="utf-8")
            command = [str(BINARY), "--config", str(config)]
            validate_command(command, log)
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log)
            try:
                wait_for(process, lambda: listener_ready(public), "latency listener")
                assert_latency_sequence(public, mode, first_calls, second_calls)
                print(f"load-balancer latency {mode}: ok")
            except Exception:
                log.seek(0)
                print(log.read(8192).decode("utf-8", errors="replace"))
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work_root", type=Path)
    parent = parser.parse_args().work_root.resolve(strict=True)
    for advanced in (False, True):
        run_case(parent, advanced)
    for enabled in (False, True):
        run_retry_case(parent, enabled)
    for mode in ("selection", "passive", "disabled", "body"):
        run_latency_case(parent, mode)


if __name__ == "__main__":
    main()
