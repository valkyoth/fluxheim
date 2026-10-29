#!/usr/bin/env python3
"""Check measurement math and the local fixture without starting Fluxheim."""

import http.client
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

from observability_baseline import CANARY, Fixture, ThreadingHTTPServer, get, is_access_record, percentile


class BaselineTests(unittest.TestCase):
    def test_access_records_include_structured_schema_without_counting_other_events(self):
        for record in ({"target": "fluxheim::access"},
                       {"schema_version": 1, "data": {"kind": "access"}}):
            self.assertTrue(is_access_record(record))
        for record in ({"schema_version": 1, "data": {"kind": "audit"}},
                       {"schema_version": 2, "data": {"kind": "access"}},
                       {"data": {"kind": "access"}}, {"schema_version": 1, "data": "access"},
                       {"target": "fluxheim::runtime"}, [], None):
            self.assertFalse(is_access_record(record))

    def test_prometheus_fixture_retains_lf_on_windows_style_checkout(self):
        repository = Path(__file__).resolve().parents[1]
        fixture = Path("tests/fixtures/observability/metrics.prom")
        expected = (repository / fixture).read_bytes()
        self.assertNotIn(b"\r", expected)
        self.assertTrue(expected.endswith(b"\n"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = os.environ.copy()
            for name in tuple(environment):
                if name.startswith("GIT_"):
                    del environment[name]
            environment.update(
                GIT_CONFIG_GLOBAL=os.devnull,
                GIT_CONFIG_NOSYSTEM="1",
                GIT_ATTR_NOSYSTEM="1",
            )

            def git(*arguments):
                subprocess.run(
                    ["git", *arguments], cwd=root, env=environment,
                    check=True, capture_output=True,
                )

            git("init", "--quiet")
            git("config", "core.autocrlf", "true")
            git("config", "core.attributesFile", os.devnull)
            (root / ".gitattributes").write_bytes(
                (repository / ".gitattributes").read_bytes()
            )
            (root / fixture).parent.mkdir(parents=True)
            (root / fixture).write_bytes(expected)
            control = root / "control.txt"
            control.write_bytes(b"unprotected text\n")
            git("add", ".gitattributes", fixture.as_posix(), control.name)
            (root / fixture).unlink()
            control.unlink()
            git("checkout-index", "--force", "--all")
            self.assertEqual(control.read_bytes(), b"unprotected text\r\n")
            self.assertEqual((root / fixture).read_bytes(), expected)

    def test_nearest_rank_percentile(self):
        self.assertEqual(percentile([3, 1, 2], 0.5), 2)
        self.assertEqual(percentile(list(range(1, 101)), 0.99), 99)
        self.assertEqual(percentile([5], 1), 5)

    def test_invalid_samples_are_rejected(self):
        for values, fraction in [([], 0.5), ([1], 0), ([1], 1.1)]:
            with self.assertRaises(ValueError):
                percentile(values, fraction)

    def test_fixture_records_signal_and_canary_without_echoing_request(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        server.observation_lock = threading.Lock()
        server.observations = {"metrics": 0, "traces": 0}
        server.leaked = False
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            self.assertEqual(get(server.server_port), b"baseline origin\n")
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            try:
                connection.request("POST", "/v1/metrics", json.dumps({"resourceMetrics": [], "secret": CANARY}))
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), b"{}")
            finally:
                connection.close()
            with server.observation_lock:
                self.assertEqual(server.observations, {"metrics": 1, "traces": 0})
                self.assertTrue(server.leaked)
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


if __name__ == "__main__":
    unittest.main()
