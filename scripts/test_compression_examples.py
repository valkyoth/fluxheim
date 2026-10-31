#!/usr/bin/env python3
"""Check the trusted compression template and bounded decode fixture."""

import gzip
import tomllib
import unittest

from smoke_compression_examples import BODY, EXAMPLE, gzip_response, prepare


class CompressionExamplesTests(unittest.TestCase):
    def test_template_has_inherited_and_disabled_policies(self):
        config = tomllib.loads(prepare(EXAMPLE.read_text(), 18080, 19001))
        self.assertEqual(config["server"]["listen"], ["127.0.0.1:18080"])
        self.assertTrue(config["compression"]["enabled"])
        self.assertFalse(config["cache"]["enabled"])
        routes = config["vhosts"][0]["routes"]
        self.assertEqual(routes[0]["proxy"]["upstreams"], ["127.0.0.1:19001"])
        self.assertFalse(routes[1]["compression"]["enabled"])
        with self.assertRaises(ValueError):
            prepare(EXAMPLE.read_text() * 2, 18080, 19001)

    def test_decode_checks_contents_and_framing(self):
        encoded = gzip.compress(BODY)
        headers = {"content-encoding": "gzip", "vary": "accept-encoding", "content-length": str(len(encoded))}
        gzip_response((200, headers, encoded))
        with self.assertRaises(AssertionError):
            gzip_response((200, {**headers, "content-length": "0"}, encoded))
        wrong = gzip.compress(BODY + b"extra")
        with self.assertRaises(AssertionError):
            gzip_response((200, {**headers, "content-length": str(len(wrong))}, wrong))


if __name__ == "__main__":
    unittest.main()
