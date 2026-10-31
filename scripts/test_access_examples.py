#!/usr/bin/env python3
import tomllib
import unittest

from smoke_access_examples import IP_EXAMPLE, TLS_EXAMPLE
from smoke_cors_examples import prepare


class AccessExamplesTests(unittest.TestCase):
    def test_port_preparation_preserves_access_and_trust(self):
        source = IP_EXAMPLE.read_text()
        before = tomllib.loads(source)
        after = tomllib.loads(prepare(source, 12001, 12002))
        self.assertEqual(after["server"]["trusted_proxies"], [])
        self.assertEqual(after["vhosts"][0]["access"], before["vhosts"][0]["access"])
        self.assertEqual(after["vhosts"][0]["routes"][0]["access"],
                         before["vhosts"][0]["routes"][0]["access"])

    def test_certificate_recipe_cannot_serve_plaintext(self):
        recipe = tomllib.loads(TLS_EXAMPLE.read_text())
        self.assertEqual(recipe["server"]["listen"], [])
        self.assertEqual(recipe["tls"]["client_auth"]["mode"], "optional")
        policy = recipe["vhosts"][0]["access"]
        self.assertTrue(policy["require_client_cert"])
        self.assertEqual(policy["allow_client_cert_sha256"], ["0" * 64])


if __name__ == "__main__":
    unittest.main()
