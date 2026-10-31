#!/usr/bin/env python3
import tomllib
import unittest

from smoke_stream_examples import EXAMPLE, prepare


class StreamExamplesTests(unittest.TestCase):
    def test_render_preserves_route_policies(self):
        source = EXAMPLE.read_text()
        original = tomllib.loads(source)
        rendered = tomllib.loads(prepare(source, 12001, 12002))
        route = original["stream"]["routes"][0]
        route["listen"] = ["127.0.0.1:12001"]
        route["upstream"] = "127.0.0.1:12002"
        self.assertEqual(original, rendered)

    def test_recipe_is_private_and_has_finite_limits(self):
        config = tomllib.loads(EXAMPLE.read_text())
        self.assertEqual(config["server"]["listen"], [])
        route = config["stream"]["routes"][0]
        self.assertEqual(route["allow_sources"], ["127.0.0.1/32"])
        self.assertEqual(route["trusted_proxies"], [])
        for field in ("max_connections", "max_connection_secs", "max_connection_bytes"):
            self.assertGreater(route[field], 0)

    def test_changed_placeholder_fails_before_execution(self):
        with self.assertRaises(ValueError):
            prepare(EXAMPLE.read_text().replace("19001", "19002"), 12001, 12002)


if __name__ == "__main__":
    unittest.main()
