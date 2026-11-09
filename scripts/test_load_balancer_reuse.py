#!/usr/bin/env python3
"""Regression checks for the loopback connection-count qualification fixture."""
import http.client
import tomllib
import unittest

import smoke_load_balancer_reuse as reuse


class ReuseFixtureTests(unittest.TestCase):
    def test_counts_cannot_confuse_fresh_with_reused_connections(self):
        self.assertTrue(reuse.counts_prove_policy((2, 8, 2), True))
        self.assertTrue(reuse.counts_prove_policy((8, 8, 0), False))
        self.assertFalse(reuse.counts_prove_policy((2, 8, 2), False))
        self.assertFalse(reuse.counts_prove_policy((8, 8, 0), True))
        self.assertFalse(reuse.counts_prove_policy((2, 2, 2), True))
        # An accept in progress is not yet evidence of another completed probe.
        self.assertFalse(reuse.counts_prove_policy((9, 8, 1), False))

    def test_configuration_preserves_routing_and_is_loopback_only(self):
        for enabled in (False, True):
            config = tomllib.loads(reuse.configuration(11001, 11002, 11003, 11004, enabled))
            self.assertEqual(config["server"]["listen"], ["127.0.0.1:11001"])
            self.assertEqual(config["proxy"]["upstreams"], ["127.0.0.1:11002", "127.0.0.1:11003"])
            health = config["proxy"]["load_balance"]["health_check"]
            self.assertEqual(health["port_override"], 11004)
            self.assertEqual(health["protocol"], "http")
            self.assertEqual(health["reuse_connection"], enabled)

    def test_readiness_fixture_really_keeps_connection_and_sends_trailers(self):
        with reuse.readiness() as (port, counts):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            try:
                for ready in (True, False, True):
                    counts.readiness(ready)
                    connection.request("GET", "/healthz")
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200 if ready else 503)
                    self.assertEqual(response.read(), b"ready")
                self.assertEqual(counts.sample()[:2], (1, 3))
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
