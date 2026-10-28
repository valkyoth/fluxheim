"""Observable sink failure and bounded graceful exit under real HTTP traffic."""
import json
import os
import threading
import time

from collector_stack import http, poll
from collector_files import assert_current_runtime_file, open_runtime_file


def verify(stack, request, metric):
    path = stack.data / "logs/events.log"
    before = metric(stack, "fluxheim_log_dispatch_events_total",
                    'job="fluxheim-scrape",lane="ordinary",outcome="sink_errors"') or 0
    with open_runtime_file(path) as log:
        assert_current_runtime_file(path, log)
        os.fchmod(log.fileno(), 0o644)
        try:
            def failed():
                assert request(stack)[2]["status"] == 200
                assert_current_runtime_file(path, log)
                return (metric(stack, "fluxheim_log_dispatch_events_total",
                               'job="fluxheim-scrape",lane="ordinary",outcome="sink_errors"') or 0) > before
            poll(failed, "observed confidential log sink failure")
        finally:
            os.fchmod(log.fileno(), 0o600)
        assert_current_runtime_file(path, log)
        size = os.fstat(log.fileno()).st_size
        assert request(stack)[2]["status"] == 200
        assert_current_runtime_file(path, log)
        assert os.fstat(log.fileno()).st_size == size, "failed sink silently resumed"
        assert_current_runtime_file(path, log)

    stop, served = threading.Event(), threading.Event()
    def traffic():
        while not stop.is_set():
            try:
                if http(stack.ports[8088], "/asset.png", headers={"Host": "cache.test"})[0] == 200:
                    served.set()
            except OSError:
                pass  # Connections close as the listener drains.
            stop.wait(0.02)
    worker = threading.Thread(target=traffic, daemon=True)
    worker.start()
    try:
        assert served.wait(10), "shutdown workload did not reach the server"
        started = time.monotonic()
        stack.stop("fluxheim")
        state = json.loads(stack.command("inspect", stack.names["fluxheim"]))[0]["State"]
        assert not state["Running"] and state["ExitCode"] == 0 and not state["OOMKilled"], "server did not exit gracefully"
        assert time.monotonic() - started < 8, "shutdown exceeded container kill deadline"
    finally:
        stop.set()
        worker.join(timeout=6)
        assert not worker.is_alive(), "shutdown traffic worker leaked"
