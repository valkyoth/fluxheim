#!/usr/bin/env python3
"""Keep the live CORS recipe renderer constrained and policy-preserving."""

import tomllib
import unittest

from smoke_cors_examples import EXAMPLE, prepare


class CorsExamplesTests(unittest.TestCase):
    def test_rendering_preserves_all_scoped_policies(self):
        source = EXAMPLE.read_text()
        original = tomllib.loads(source)
        rendered = tomllib.loads(prepare(source, 12001, 12002))
        self.assertEqual(rendered["server"]["listen"], ["127.0.0.1:12001"])
        self.assertEqual(rendered["headers"], original["headers"])
        self.assertEqual(rendered["vhosts"][0]["routes"][0]["headers"],
                         original["vhosts"][0]["routes"][0]["headers"])
        self.assertEqual(rendered["vhosts"][0]["proxy"]["upstreams"], ["127.0.0.1:12002"])
        self.assertEqual(rendered["vhosts"][0]["routes"][0]["proxy"]["upstreams"],
                         ["127.0.0.1:12002"])

    def test_missing_or_ambiguous_addresses_are_rejected(self):
        source = EXAMPLE.read_text()
        for changed in (source.replace("9001", "9002"), source + '\n# upstreams = ["127.0.0.1:9001"]',
                        source.replace("8080", "8081"), source + '\n# listen = ["127.0.0.1:8080"]'):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                prepare(changed, 12001, 12002)


if __name__ == "__main__":
    unittest.main()
