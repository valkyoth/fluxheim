#!/usr/bin/env python3
"""Run the exact tracing guide against a trusted local binary and bounded fixtures."""
import argparse
from contextlib import closing, contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading

from smoke_log_file_rotation import fixture_parent, private_fixture, wait_for
from smoke_logging_examples import access_records, replace_once
from smoke_metrics_examples import request, samples, server
from smoke_operational_events import ROOT, port

EXAMPLE = ROOT / "examples/tracing/proxy.toml"
PARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
CANARY = "trace-guide-private-canary"
MISSING_ATTRIBUTES = {"fluxheim.route", "fluxheim.cache.phase", "fluxheim.cache.lookup.duration_ms",
                      "fluxheim.cache.lock_wait.duration_ms", "fluxheim.load_balancer.upstream",
                      "fluxheim.load_balancer.retries", "fluxheim.compression.encoding",
                      "fluxheim.php.runtime", "fluxheim.php.outcome"}


class Fixture(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def do_GET(self):
        with self.server.lock:
            self.server.items.append({key.lower(): value for key, value in self.headers.items()})
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 65536 or self.path != "/v1/traces":
            self.send_error(400)
            return
        payload = json.loads(self.rfile.read(size))
        with self.server.lock:
            if len(self.server.items) >= 16:
                self.send_error(429)
                return
            self.server.items.append(payload)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_):
        pass


@contextmanager
def fixture():
    with ThreadingHTTPServer(("127.0.0.1", 0), Fixture) as http:
        http.daemon_threads = True
        http.items, http.lock = [], threading.Lock()
        worker = threading.Thread(target=http.serve_forever, daemon=True)
        worker.start()
        try:
            yield http
        finally:
            http.shutdown()
            worker.join(timeout=5)
            assert not worker.is_alive()


def observed(http):
    with http.lock:
        return list(http.items)


def spans(payloads):
    return [span for payload in payloads for resource in payload["resourceSpans"]
            for scope in resource["scopeSpans"] for span in scope["spans"]]


def check_native_attributes(span):
    attrs = {item["key"]: item["value"] for item in span["attributes"]}
    assert attrs["fluxheim.vhost"] == {"stringValue": ""}
    assert not MISSING_ATTRIBUTES & attrs.keys()  # documented contract, not implementation acceptance.
    assert span["name"] in {"HTTP request", "Upstream attempt"}
    return attrs


def run_case(binary, *, trusted=True, parent=PARENT, tracing=True, exporting=True, log_ids=True):
    with private_fixture(fixture_parent(False)) as root, fixture() as origin, fixture() as collector:
        public, metrics = port(), port()
        while metrics == public:
            metrics = port()
        source = replace_once(EXAMPLE.read_text(), "127.0.0.1:8080", f"127.0.0.1:{public}")
        source = replace_once(source, "127.0.0.1:9091", f"127.0.0.1:{metrics}")
        source = replace_once(source, "127.0.0.1:9001", f"127.0.0.1:{origin.server_port}")
        source = replace_once(source, "127.0.0.1:4318", f"127.0.0.1:{collector.server_port}")
        for old, new in [('[tracing]\nenabled = true', f'[tracing]\nenabled = {str(tracing).lower()}'),
                         ('[tracing.otlp]\nenabled = true', f'[tracing.otlp]\nenabled = {str(exporting).lower()}'),
                         ('log_trace_id = true', f'log_trace_id = {str(log_ids).lower()}')]:
            source = replace_once(source, old, new)
        if not trusted:
            source = replace_once(source, 'trusted_proxies = ["127.0.0.1"]', 'trusted_proxies = []')
        expected = tracing and exporting and trusted and parent == PARENT
        with server(binary, root, source, metrics):
            with closing(http.client.HTTPConnection("127.0.0.1", public, timeout=2)) as client:
                headers = {"Host": "traces.example.test", "x-request-id": "guide-request",
                           "baggage": CANARY, "tracestate": CANARY, "Authorization": f"Bearer {CANARY}",
                           "Connection": "close"}
                if parent:
                    headers["traceparent"] = parent
                client.request("GET", f"/{CANARY}?secret={CANARY}", headers=headers)
                response = client.getresponse()
                assert response.status == 200 and response.read(1024) == b"ok"
            wait_for(lambda: sum(samples(request(metrics)[2].decode(), "fluxheim_http_requests_total")) == 1)
            wait_for(lambda: (root / "stdout.log").read_text().endswith("\n")
                     and len(access_records((root / "stdout.log").read_text())) == 1)
            if expected:
                wait_for(lambda: len(spans(observed(collector))) == 2)
        events = access_records((root / "stdout.log").read_text())
        correlation = events[0].get("correlation", {})
        assert ("trace_id" in correlation) == (tracing and log_ids)
        sent = observed(origin)[0]
        assert "baggage" not in sent and "tracestate" not in sent
        assert ("traceparent" in sent) == tracing
        assert (sent["x-request-id"] == "guide-request") == trusted
        if tracing:
            accepted = trusted and parent in (PARENT, PARENT[:-2] + "00")
            assert (sent["traceparent"][3:35] == PARENT[3:35]) == accepted
            assert sent["traceparent"].endswith("-01" if trusted and parent == PARENT else "-00")
        payloads = observed(collector)
        emitted = spans(payloads)
        assert len(emitted) == (2 if expected else 0)
        if expected:
            server_span = next(span for span in emitted if span["kind"] == "SPAN_KIND_SERVER")
            client_span = next(span for span in emitted if span["kind"] == "SPAN_KIND_CLIENT")
            assert server_span["traceId"] == client_span["traceId"] == PARENT[3:35]
            assert server_span["parentSpanId"] == PARENT[36:52]
            assert client_span["parentSpanId"] == server_span["spanId"]
            assert client_span["spanId"] == sent["traceparent"][36:52] != server_span["spanId"]
            for span in emitted:
                check_native_attributes(span)
            for payload in payloads:
                attributes = payload["resourceSpans"][0]["resource"]["attributes"]
                assert {"key": "service.name", "value": {"stringValue": "fluxheim-tracing-guide"}} in attributes
        assert CANARY not in json.dumps(payloads) + (root / "stdout.log").read_text() + (root / "stderr.log").read_text()


def run(binary):
    for options in [{}, {"trusted": False}, {"parent": None}, {"parent": PARENT[:-2] + "00"},
                    {"exporting": False}, {"tracing": False, "exporting": False}, {"log_ids": False}]:
        run_case(binary, **options)
    print("tracing guide: seven live trust/sampling/propagation/export/log cases passed")
    print("documented contract: empty vhost and absent native enrichment characterized; correction pending")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    run(args.binary.resolve(strict=True))
