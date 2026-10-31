#!/usr/bin/env python3
"""Keep the static guide recipe transformations exact and loopback-only."""

import tomllib
import unittest

from smoke_static_examples import ROOT, prepare, routed_listing


class StaticExamplesTests(unittest.TestCase):
    def test_complete_templates_and_route_projection(self):
        for name in ("static", "listing"):
            source = (ROOT / f"examples/web/{name}.toml").read_text()
            config = tomllib.loads(prepare(source, 19001))
            self.assertEqual(config["server"]["listen"], ["127.0.0.1:19001"])
            self.assertFalse(config["cache"]["enabled"])
        config = tomllib.loads(routed_listing(source))
        self.assertNotIn("web", config["vhosts"][0])
        route = config["vhosts"][0]["routes"][0]
        self.assertEqual(route["strip_prefix"], "/assets")
        self.assertTrue(route["web"]["directory_listing"]["enabled"])

    def test_ambiguous_template_rejected(self):
        source = (ROOT / "examples/web/static.toml").read_text()
        with self.assertRaises(ValueError):
            prepare(source + source, 19001)
        with self.assertRaises(ValueError):
            prepare(source.replace("8080", "8081"), 19001)


if __name__ == "__main__":
    unittest.main()
