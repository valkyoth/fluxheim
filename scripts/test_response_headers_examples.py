#!/usr/bin/env python3
import tomllib
import unittest

from smoke_cors_examples import prepare
from smoke_response_headers import EXAMPLE, digest


class ResponseHeadersExamplesTests(unittest.TestCase):
    def test_rendering_preserves_response_policy(self):
        original = tomllib.loads(EXAMPLE.read_text())
        rendered = tomllib.loads(prepare(EXAMPLE.read_text(), 12001, 12002))
        self.assertEqual(rendered["headers"], original["headers"])
        self.assertEqual(rendered["vhosts"][0]["routes"][0]["headers"],
                         original["vhosts"][0]["routes"][0]["headers"])
        self.assertEqual(rendered["server"]["listen"], ["127.0.0.1:12001"])
        for proxy in (rendered["vhosts"][0], rendered["vhosts"][0]["routes"][0]):
            self.assertEqual(proxy["proxy"]["upstreams"], ["127.0.0.1:12002"])

    def test_digest_oracle_known_value(self):
        self.assertEqual(digest(b"hello"), "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:")


if __name__ == "__main__":
    unittest.main()
