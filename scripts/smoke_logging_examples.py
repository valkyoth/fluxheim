#!/usr/bin/env python3
"""Bounded live logging-guide cases; run only a trusted local Fluxheim binary."""
import argparse
from contextlib import closing
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading
import time

from smoke_log_file_rotation import fixture_parent, private_fixture, wait_for
from smoke_operational_events import ROOT, port

EXAMPLE = ROOT / "examples/logging/proxy.toml"
CANARY = "logging-guide-private-canary"
ACCESS_KEYS = {"kind", "outcome", "method", "status", "duration_micros", "bytes_sent", "attempts"}
INCLUDES = ("host", "client_ip", "cache_phase", "path", "route", "upstream")


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError(f"example marker must occur once: {old}")
    return source.replace(old, new, 1)


def access_records(contents):
    result = []
    for line in contents.splitlines():
        if line.startswith("INFO access "):
            line = line.removeprefix("INFO access ")
        if line.startswith("{"):
            record = json.loads(line)
            if record.get("data", {}).get("kind") == "access":
                result.append(record)
    return result


def has_complete_access(path):
    if not path.is_file():
        return False
    contents = path.read_text()
    return contents.endswith("\n") and bool(access_records(contents))


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.seen.append(dict(self.headers))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_):
        pass


def run_case(binary, *, include=True, format_="json", target="stderr",
             file_sink=False, enabled=True, request_id=True, filter_=None,
             expect=True, header="x-request-id"):
    with private_fixture(fixture_parent(False)) as root:
        with ThreadingHTTPServer(("127.0.0.1", 0), Origin) as origin:
            origin.daemon_threads = True
            origin.seen = []
            worker = threading.Thread(target=origin.serve_forever, daemon=True)
            worker.start()
            process = None
            try:
                public = port()
                source = EXAMPLE.read_text()
                source = replace_once(source, "127.0.0.1:8080", f"127.0.0.1:{public}")
                # The example mentions the origin once in a comment and once in configuration.
                source = replace_once(source, 'upstreams = ["127.0.0.1:9001"]',
                                      f'upstreams = ["127.0.0.1:{origin.server_port}"]')
                source = replace_once(source, 'format = "json"', f'format = "{format_}"')
                source = replace_once(source, 'target = "stderr"', f'target = "{target}"')
                source = replace_once(source, '[logging.access]\nenabled = true',
                                      f'[logging.access]\nenabled = {str(enabled).lower()}')
                source = replace_once(source, 'request_id = true', f'request_id = {str(request_id).lower()}')
                source = replace_once(source, 'request_id_header = "x-request-id"', f'request_id_header = "{header}"')
                for name in INCLUDES:
                    source = replace_once(source, f'include_{name} = true', f'include_{name} = {str(include).lower()}')
                if file_sink:
                    source = replace_once(source, '[logging.file]\nenabled = false', '[logging.file]\nenabled = true')
                    source = replace_once(source, '# path = "logs/events.log"', 'path = "events.log"')
                    source = replace_once(source, 'append = true', 'append = false')
                    source = replace_once(source, '# crash_file = "logs/fatal.log"', 'crash_file = "fatal.log"')
                    (root / "events.log").write_text("old-startup-sentinel\n")
                    (root / "events.log").chmod(0o600)
                config = root / "fluxheim.toml"
                config.write_text(source)
                environment = {key: value for key, value in os.environ.items()
                               if key.casefold() not in {"rust_log", "fluxheim_config"}}
                if filter_ is not None:
                    environment["RUST_LOG"] = filter_
                stdout, stderr = root / "stdout.log", root / "stderr.log"
                with stdout.open("wb") as out, stderr.open("wb") as err:
                    process = subprocess.Popen([str(binary), "--config", str(config)],
                                               cwd=root, env=environment, stdout=out, stderr=err)
                    deadline = time.monotonic() + 15
                    while True:
                        if process.poll() is not None:
                            raise AssertionError("logging fixture exited before readiness: " + stderr.read_text()[-2048:])
                        try:
                            with closing(http.client.HTTPConnection("127.0.0.1", public, timeout=2)) as client:
                                client.request("GET", f"/{CANARY}?token={CANARY}", headers={
                                    "Host": "logs.example.test", "Connection": "close",
                                    header: CANARY, "Authorization": f"Bearer {CANARY}",
                                })
                                response = client.getresponse()
                                assert response.status == 200 and response.read() == b"ok"
                            break
                        except ConnectionRefusedError:
                            if time.monotonic() >= deadline:
                                raise AssertionError("logging fixture did not listen")
                            time.sleep(0.05)
                    if expect:
                        # Windows terminate() does not drain workers. Observe the
                        # complete record before stopping this owned fixture.
                        destination = root / "events.log" if file_sink else (stdout if target == "stdout" else stderr)
                        wait_for(lambda: has_complete_access(destination))
                    process.terminate()
                    process.wait(timeout=10)
                assert len(origin.seen) == 1
                seen = {key.lower(): value for key, value in origin.seen[0].items()}
                if request_id:
                    assert seen[header].startswith("fh-") and len(seen[header]) == 35
                else:
                    assert seen[header] == CANARY
                streams = {"stdout": stdout.read_text(), "stderr": stderr.read_text()}
                contents = (root / "events.log").read_text() if file_sink else streams[target]
                events = access_records(contents)
                assert len(events) == int(expect), events
                for event in events:
                    assert set(event["data"]) == ACCESS_KEYS, "documented contract changed: review field contract"
                    assert event["data"]["status"] == 200
                    assert event["data"]["outcome"] == "completed"
                    assert event["data"]["attempts"] == 1
                    assert "resource" not in event
                    assert CANARY not in json.dumps(event)
                    assert ("request_id" in event["correlation"]) == request_id
                    if request_id:
                        assert event["correlation"]["request_id"] == seen[header]
                other = streams["stdout" if target == "stderr" else "stderr"]
                assert not access_records(other)
                if file_sink:
                    assert not access_records(streams[target])
                    assert "old-startup-sentinel" not in contents
                    assert (root / "fatal.log").read_bytes() == b""
                    if os.name == "posix":
                        assert (root / "events.log").stat().st_mode & 0o777 == 0o600
                return events
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                origin.shutdown()
                worker.join(timeout=5)
                assert not worker.is_alive()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    binary = parser.parse_args().binary.resolve(strict=True)
    run_case(binary)
    run_case(binary, include=False, target="stdout")
    run_case(binary, format_="text", file_sink=True)
    run_case(binary, enabled=False, expect=False)
    run_case(binary, filter_="off", expect=False)
    run_case(binary, filter_="warn", expect=False)
    run_case(binary, filter_="info/Request outcome", header="x-correlation-id")
    run_case(binary, request_id=False)
    print("logging guide smoke: 8 live scenarios passed")


if __name__ == "__main__":
    main()
