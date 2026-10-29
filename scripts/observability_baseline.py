#!/usr/bin/env python3
"""Measure a local native proxy; record observations without claiming APM delivery."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import platform
import socket
import subprocess
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parent.parent
CANARY = "observability-private-canary"


def percentile(values, fraction):
    if not values or not 0 < fraction <= 1:
        raise ValueError("nonempty samples and fraction in (0, 1] required")
    return sorted(values)[math.ceil(len(values) * fraction) - 1]


def is_access_record(record):
    if not isinstance(record, dict):
        return False
    data = record.get("data")
    return (record.get("target") == "fluxheim::access"
            or (record.get("schema_version") == 1 and isinstance(data, dict)
                and data.get("kind") == "access"))


def get(port, path="/"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path, headers={
            "Host": "baseline.test", "Authorization": f"Bearer {CANARY}",
            "Cookie": f"session={CANARY}", "Connection": "close",
        })
        response = connection.getresponse()
        body = response.read(4 * 1024 * 1024 + 1)
        if response.status != 200 or len(body) > 4 * 1024 * 1024:
            raise RuntimeError(f"unexpected response: {response.status}")
        return body
    finally:
        connection.close()


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def process_usage(pid):
    if platform.system() != "Linux":
        return {"cpu_seconds": None, "rss_peak_bytes": None}
    stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    status = Path(f"/proc/{pid}/status").read_text().splitlines()
    peak = next(line.split()[1] for line in status if line.startswith("VmHWM:"))
    return {
        "cpu_seconds": (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK"),
        "rss_peak_bytes": int(peak) * 1024,
    }


class Fixture(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_args):
        pass

    def do_GET(self):
        body = b"baseline origin\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 4 * 1024 * 1024:
            self.send_error(413)
            return
        payload = self.rfile.read(size)
        decoded = json.loads(payload)
        with self.server.observation_lock:
            if CANARY.encode() in payload:
                self.server.leaked = True
            if "resourceMetrics" in decoded:
                signal = "metrics"
            elif "resourceSpans" in decoded:
                signal = "traces"
            else:
                self.send_error(400)
                return
            self.server.observations[signal] += 1
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")


def run_sample(binary, fixture, directory, enabled, count, workers):
    port, metrics_port = free_port(), free_port()
    config = directory / "fluxheim.toml"
    flag = "true" if enabled else "false"
    config.write_text(f'''[server]
listen = ["127.0.0.1:{port}"]
[server.process]
pid_file = "fluxheim.pid"
upgrade_sock = "upgrade.sock"
certificate_reload_sock = "reload.sock"
threads = 2
grace_period_seconds = 1
graceful_shutdown_timeout_seconds = 5
[logging]
level = "{"info" if enabled else "off"}"
format = "json"
[logging.access]
enabled = {flag}
[metrics]
enabled = {flag}
listen = "127.0.0.1:{metrics_port}"
[metrics.otlp]
enabled = {flag}
endpoint = "http://127.0.0.1:{fixture.server_port}/v1/metrics"
interval_secs = 1
timeout_secs = 1
[tracing]
enabled = {flag}
[tracing.otlp]
enabled = {flag}
endpoint = "http://127.0.0.1:{fixture.server_port}/v1/traces"
queue_size = 64
timeout_secs = 1
[proxy]
upstreams = ["127.0.0.1:{fixture.server_port}"]
upstream_tls = false
''')
    environment = dict(os.environ)
    environment.pop("RUST_LOG", None)
    with fixture.observation_lock:
        fixture.observations = {"metrics": 0, "traces": 0}
        fixture.leaked = False
    with (directory / "runtime.jsonl").open("wb") as log:
        process = subprocess.Popen(
            [str(binary), "--config", str(config)], cwd=ROOT,
            stdout=log, stderr=log, env=environment,
        )
        try:
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"server exited: {process.returncode}; inspect {directory}")
                try:
                    get(port)
                    break
                except (OSError, http.client.HTTPException):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("server readiness deadline exceeded")
                    time.sleep(0.05)

            def request(_index):
                start = time.perf_counter()
                if get(port, f"/asset?private={CANARY}") != b"baseline origin\n":
                    raise RuntimeError("wrong origin body")
                return (time.perf_counter() - start) * 1000

            for index in range(20):
                request(index)
            before = process_usage(process.pid)
            start = time.perf_counter()
            with ThreadPoolExecutor(max_workers=workers) as pool:
                timings = list(pool.map(request, range(count)))
            elapsed = time.perf_counter() - start
            after = process_usage(process.pid)
            if enabled:
                metrics = get(metrics_port, "/metrics")
                if b"fluxheim_proxy_requests_total" not in metrics:
                    raise RuntimeError("native proxy counter absent")
                if CANARY.encode() in metrics:
                    raise RuntimeError("secret canary leaked in metrics")
                (directory / "metrics.prom").write_bytes(metrics)
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline:
                    with fixture.observation_lock:
                        if all(fixture.observations.values()):
                            break
                    time.sleep(0.05)
            with fixture.observation_lock:
                observations = dict(fixture.observations)
                if fixture.leaked:
                    raise RuntimeError("secret canary leaked in exported telemetry")
            if enabled and observations["metrics"] == 0:
                raise RuntimeError("enabled OTLP metrics did not reach fixture")
            if not enabled and any(observations.values()):
                raise RuntimeError("disabled exporters sent telemetry")
        finally:
            shutdown = time.monotonic()
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise RuntimeError("server exceeded baseline shutdown deadline")
            shutdown_seconds = time.monotonic() - shutdown
    records = [json.loads(line) for line in (directory / "runtime.jsonl").read_text().splitlines()]
    if CANARY in json.dumps(records):
        raise RuntimeError("secret canary leaked in runtime logs")
    return {
        "enabled": enabled, "requests": count, "concurrency": workers,
        "elapsed_seconds": elapsed, "requests_per_second": count / elapsed,
        "latency_ms": {f"p{n}": percentile(timings, n / 100) for n in (50, 95, 99)},
        "cpu_seconds": None if before["cpu_seconds"] is None else after["cpu_seconds"] - before["cpu_seconds"],
        "rss_peak_bytes": after["rss_peak_bytes"], "shutdown_seconds": shutdown_seconds,
        "received_exports": observations, "runtime_records": len(records),
        "access_records": sum(is_access_record(record) for record in records),
        "latency_samples_ms": timings,
    }


class FixtureServer(ThreadingHTTPServer):
    request_queue_size = 128


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--requests", type=int, default=500)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.samples <= 10 or not 1 <= args.requests <= 10000 or not 1 <= args.workers <= 64:
        parser.error("samples 1..10, requests 1..10000, workers 1..64 required")
    binary = args.binary.resolve(strict=True)
    temporary_root = subprocess.check_output(
        ["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh")], text=True, cwd=ROOT,
    ).strip()
    directory = Path(tempfile.mkdtemp(prefix="observability-baseline.", dir=temporary_root))
    print(f"Evidence directory: {directory}", flush=True)
    fixture = FixtureServer(("127.0.0.1", 0), Fixture)
    fixture.observation_lock = threading.Lock()
    fixture.observations = {"metrics": 0, "traces": 0}
    fixture.leaked = False
    worker = threading.Thread(target=fixture.serve_forever, daemon=True)
    worker.start()
    results = []
    try:
        for sample in range(args.samples):
            for enabled in ((False, True) if sample % 2 == 0 else (True, False)):
                run = directory / f"sample-{sample}-{'on' if enabled else 'off'}"
                run.mkdir()
                results.append(run_sample(binary, fixture, run, enabled, args.requests, args.workers))
        evidence = {
            "schema_version": 1,
            "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "worktree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "binary_version": subprocess.check_output([str(binary), "--version"], text=True).strip(),
            "platform": platform.platform(), "machine": platform.machine(),
            "cpu_count": os.cpu_count(), "python": platform.python_version(),
            "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
            "results": results,
        }
        (directory / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print("Baseline recorded; traces are unsampled for untrusted fixture traffic. This is not backend-delivery proof.")
    finally:
        fixture.shutdown()
        fixture.server_close()
        worker.join(timeout=5)


if __name__ == "__main__":
    main()
