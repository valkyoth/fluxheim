#!/usr/bin/env python3
"""Characterize the dashboard's direct-scrape versus OTLP health boundary."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading

from smoke_log_file_rotation import fixture_parent, private_fixture, wait_for
from smoke_logging_examples import replace_once
from smoke_metrics_examples import EXAMPLE, Origin, request, samples, server

CANARY = "collector-guide-request-private-canary"
HEALTH = "fluxheim_otlp_failed_total"


def exported_names(payload):
    return {metric["name"] for resource in payload["resourceMetrics"]
            for scope in resource["scopeMetrics"] for metric in scope["metrics"]}


class Receiver(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 4 * 1024 * 1024 or self.path != "/v1/metrics":
            self.send_error(400)
            return
        body = self.rfile.read(size)
        names = exported_names(json.loads(body))
        with self.server.lock:
            status = self.server.status
            if status == 200:
                self.server.names = names
                self.server.received += 1
            self.server.leaked |= CANARY.encode() in body
        self.send_response(status)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_):
        pass


def run(binary):
    from smoke_operational_events import port
    with private_fixture(fixture_parent(False)) as root:
        with ThreadingHTTPServer(("127.0.0.1", 0), Origin) as origin, \
                ThreadingHTTPServer(("127.0.0.1", 0), Receiver) as collector:
            collector.lock = threading.Lock()
            collector.status, collector.received, collector.names, collector.leaked = 200, 0, set(), False
            workers = []
            for http in (origin, collector):
                http.daemon_threads = True
                worker = threading.Thread(target=http.serve_forever, daemon=True)
                worker.start()
                workers.append(worker)
            try:
                public, metrics = port(), port()
                while public == metrics:
                    metrics = port()
                source = replace_once(EXAMPLE.read_text(), "127.0.0.1:8080", f"127.0.0.1:{public}")
                source = replace_once(source, "127.0.0.1:9091", f"127.0.0.1:{metrics}")
                source = replace_once(source, 'upstreams = ["127.0.0.1:9001"]',
                                      f'upstreams = ["127.0.0.1:{origin.server_port}"]')
                source = replace_once(source, 'token_file = "metrics-token"', '# Private local fixture; no token.')
                source += f'\n[metrics.otlp]\nenabled = true\nendpoint = "http://127.0.0.1:{collector.server_port}/v1/metrics"\ninterval_secs = 1\ntimeout_secs = 1\n'
                with server(binary, root, source, metrics):
                    status, _, body = request(public, f"/{CANARY}")
                    assert status == 200 and body == b"ok"

                    def ingested():
                        with collector.lock:
                            return collector.received > 0 and "fluxheim_http_requests_total" in collector.names

                    wait_for(ingested)
                    local = request(metrics)[2].decode()
                    before = sum(samples(local, HEALTH))
                    assert samples(local, HEALTH), "local-only health series absent from direct scrape"
                    with collector.lock:
                        assert HEALTH not in collector.names
                        collector.status = 503
                    wait_for(lambda: sum(samples(request(metrics)[2].decode(), HEALTH)) > before)
                    assert request(public, "/during-outage")[0] == 200
                    with collector.lock:
                        collector.status = 200
                        previous = collector.received

                    def recovered():
                        with collector.lock:
                            return collector.received > previous

                    wait_for(recovered)
                    assert sum(samples(request(metrics)[2].decode(), HEALTH)) > before
                    with collector.lock:
                        assert HEALTH not in collector.names and not collector.leaked
                    assert request(public, "/after-recovery")[0] == 200
                assert CANARY not in (root / "stdout.log").read_text() + (root / "stderr.log").read_text()
            finally:
                for http in (origin, collector):
                    http.shutdown()
                for worker in workers:
                    worker.join(timeout=5)
                    assert not worker.is_alive()
    print("collector guide: real OTLP metrics and serving survive failure/recovery")
    print("documented contract: exporter failures exist locally but remain absent from OTLP payloads")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    run(args.binary.resolve(strict=True))
