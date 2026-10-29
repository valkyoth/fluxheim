#!/usr/bin/env python3
"""Prove extracted full/wasm telemetry in real Prometheus/Jaeger, with outage.

The controller stops the owned collector after OUTAGE_READY and writes stopped
to stdin; after RECOVERY_READY it starts the collector and writes started.
All endpoints are numeric loopback, optionally carried by SSH reverse forwards.
"""
import argparse
import http.client as http_client
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import secrets
import ssl
import subprocess
import sys
import threading
from urllib.parse import urlencode

from collector_stack import api, http, poll
from native_archive import extract_pair, executable
from portable_release_plan import TARGET_LABELS, release_plan
from smoke_native_archives import Origin, configuration
from smoke_log_file_rotation import fixture_parent, private_fixture, request
from smoke_operational_events import ROOT, port


def acknowledged(expected):
    result = queue.Queue(maxsize=1)
    threading.Thread(target=lambda: result.put(sys.stdin.readline(32).strip()), daemon=True).start()
    if result.get(timeout=180) != expected:
        raise RuntimeError("collector controller did not acknowledge " + expected)


def run(args):
    kind = TARGET_LABELS[args.target].split("-")[-1]
    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    worker = threading.Thread(target=origin.serve_forever, daemon=True)
    worker.start()
    try:
        with private_fixture(fixture_parent(False)) as root:
            bundle = release_plan(args.version, kind, args.target, args.profile)[0][0]
            extracted = extract_pair(args.dist / (bundle + ".tar.gz"), args.dist / (bundle + ".zip"), bundle, root / "archive")
            binary = executable(extracted, "fluxheim.exe" if kind == "windows" else "fluxheim", TARGET_LABELS[args.target])
            public, tls, admin, metrics = port(), port(), port(), port()
            service = "native-proof-" + secrets.token_hex(8)
            text = configuration(root, public, tls, admin, origin.server_port)
            text += f'''\n[metrics]
enabled = true
listen = "127.0.0.1:{metrics}"
[metrics.otlp]
enabled = true
endpoint = "http://127.0.0.1:{args.otlp}/v1/metrics"
service_name = "{service}"
interval_secs = 1
timeout_secs = 1
[tracing]
enabled = true
[tracing.otlp]
enabled = true
endpoint = "http://127.0.0.1:{args.otlp}/v1/traces"
service_name = "{service}"
timeout_secs = 1
'''
            config = root / "fluxheim.toml"
            config.write_text(text)
            context = ssl.create_default_context(cafile=str(root / "cert.pem"))
            context.minimum_version = ssl.TLSVersion.TLSv1_2

            def traffic(secure=False):
                trace = secrets.token_hex(16)
                client = (http_client.HTTPSConnection("localhost", tls, context=context, timeout=5) if secure
                          else http_client.HTTPConnection("127.0.0.1", public, timeout=5))
                try:
                    client.request("GET", "/", headers={"Host": "localhost", "traceparent": f"00-{trace}-0123456789abcdef-01"})
                    response = client.getresponse()
                    assert (response.status, response.read(1024)) == (200, b"native-archive-proof")
                    return trace
                finally:
                    client.close()

            def stored(trace):
                code, body = http(args.jaeger, "/api/traces/" + trace)
                return code == 200 and bool(json.loads(body).get("data"))

            def metric(name):
                expression = f'{name}{{exported_job="{service}"}}'
                return api(args.prometheus, "/api/v1/query?" + urlencode({"query": expression}))["data"]["result"]

            def local_counter(name):
                code, body = http(metrics, "/metrics")
                assert code == 200
                return sum(float(line.rsplit(" ", 1)[1]) for line in body.decode().splitlines()
                           if line.startswith(name + "{"))

            with (root / "process.log").open("wb") as output:
                process = subprocess.Popen([str(binary), "--config", str(config)], cwd=root, stdout=output, stderr=output)
                try:
                    def ready():
                        assert process.poll() is None, (root / "process.log").read_text()
                        return request(admin, "/_fluxheim/operational-status", "native-archive-control-token")[0] == 200
                    poll(ready, "native collector server startup")
                    for secure in (False, True):
                        trace = traffic(secure)
                        poll(lambda: stored(trace), "stored native trace")
                    poll(lambda: metric("fluxheim_http_requests_total"), "stored native counter")
                    poll(lambda: metric("fluxheim_http_request_duration_seconds_bucket"), "stored native histogram")
                    before = local_counter("fluxheim_otlp_failed_total")
                    print("OUTAGE_READY", flush=True)
                    acknowledged("stopped")
                    def degraded():
                        traffic()
                        return local_counter("fluxheim_otlp_failed_total") > before
                    poll(degraded, "native collector outage without service failure")
                    requests_before_recovery = local_counter("fluxheim_http_requests_total")
                    print("RECOVERY_READY", flush=True)
                    acknowledged("started")
                    trace = traffic(True)
                    poll(lambda: stored(trace), "fresh native trace after collector restart")
                    poll(lambda: sum(float(row["value"][1]) for row in metric("fluxheim_http_requests_total"))
                         >= requests_before_recovery + 1, "new native counter value after collector restart")
                    print(json.dumps({"profile": args.profile, "target": args.target, "service": service,
                                      "stored_traces": True, "stored_counter_histogram": True,
                                      "collector_stop_recovery": True}), flush=True)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                        raise
    finally:
        origin.shutdown()
        origin.server_close()
        worker.join(timeout=5)


def main():
    if not __debug__:
        raise SystemExit("native qualification requires Python assertions")
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", choices=TARGET_LABELS, required=True)
    parser.add_argument("--profile", choices=("full", "wasm"), required=True)
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    for name in ("otlp", "prometheus", "jaeger"):
        parser.add_argument("--" + name, type=int, required=True)
    args = parser.parse_args()
    if not all(1 <= value <= 65535 for value in (args.otlp, args.prometheus, args.jaeger)):
        parser.error("ports must be between 1 and 65535")
    run(args)


if __name__ == "__main__":
    main()
