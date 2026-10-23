#!/usr/bin/env python3
"""Check measurement math and the local fixture without starting Fluxheim."""

import http.client
import json
import threading
import unittest

from observability_baseline import CANARY, Fixture, ThreadingHTTPServer, get, percentile


class BaselineTests(unittest.TestCase):
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
