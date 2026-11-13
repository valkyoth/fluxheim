#!/usr/bin/env python3
"""Validate balanced slice fixtures and their bounded response contracts."""

import http.client
import json
import tomllib
import unittest

import smoke_slice_upstreams as smoke


class SliceUpstreamTests(unittest.TestCase):
    def test_discovery_has_no_static_fallback(self):
        config = tomllib.loads(smoke.configuration(18080, [19001, 19002, 19003], 19004, "discovery", False))
        self.assertNotIn("upstreams", config["proxy"])
        self.assertEqual(config["proxy"]["upstreams_http_refresh_secs"], 1)
        self.assertTrue(config["cache"]["range"]["slice"]["enabled"])

    def test_static_drain_and_active_health(self):
        config = tomllib.loads(smoke.configuration(18080, [19001, 19002, 19003], 19004, "health", True))
        self.assertEqual(config["proxy"]["drain_upstreams"], ["127.0.0.1:19001"])
        self.assertTrue(config["proxy"]["load_balance"]["health_check"]["enabled"])
        self.assertEqual(config["server"]["listen"], ["127.0.0.1:18080"])

    def test_origin_and_membership_are_bounded_fixtures(self):
        state = smoke.State()
        state.membership([19001, 19002])
        with smoke.endpoint(state) as port:
            for path, headers, expected in [
                ("/asset.css", {"Range": "bytes=4-7"}, 206),
                ("/asset.css", {"Range": "bytes=0-99999999"}, 400),
                ("/members", {}, 200),
                ("/healthz", {}, 200),
            ]:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                try:
                    connection.request("GET", path, headers=headers)
                    response = connection.getresponse()
                    self.assertEqual(response.status, expected)
                    body = response.read(4097)
                    if path == "/members":
                        self.assertEqual(json.loads(body), {"upstreams": ["127.0.0.1:19001", "127.0.0.1:19002"]})
                    if response.status == 206:
                        self.assertEqual(body, b"4567")
                        self.assertEqual(response.getheader("ETag"), '"revision-a"')
                finally:
                    connection.close()
        self.assertEqual(state.count(), 3)


if __name__ == "__main__":
    unittest.main()
