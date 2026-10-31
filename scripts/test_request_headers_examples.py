#!/usr/bin/env python3
import tomllib
import unittest

from smoke_cors_examples import prepare
from smoke_request_headers import EXAMPLE


class RequestHeadersExamplesTests(unittest.TestCase):
    def test_template_renderer_preserves_trust_and_policy(self):
        source = EXAMPLE.read_text()
        original = tomllib.loads(source)
        rendered = tomllib.loads(prepare(source, 12001, 12002))
        self.assertEqual(rendered["headers"], original["headers"])
        self.assertEqual(rendered["server"]["trusted_proxies"], [])
        self.assertEqual(rendered["server"]["listen"], ["127.0.0.1:12001"])
        self.assertEqual(rendered["vhosts"][0]["routes"][0]["headers"],
                         original["vhosts"][0]["routes"][0]["headers"])

    def test_ambiguous_template_fails_closed(self):
        with self.assertRaises(ValueError):
            prepare(EXAMPLE.read_text() + '\n# upstreams = ["127.0.0.1:9001"]', 12001, 12002)


if __name__ == "__main__":
    unittest.main()
