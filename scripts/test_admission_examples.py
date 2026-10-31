#!/usr/bin/env python3
import tomllib
import unittest

from smoke_admission_examples import EXAMPLE
from smoke_cors_examples import prepare


class AdmissionExamplesTests(unittest.TestCase):
    def test_prepare_preserves_both_policy_scopes(self):
        source = EXAMPLE.read_text()
        original = tomllib.loads(source)["vhosts"][0]
        rendered = tomllib.loads(prepare(source, 12001, 12002))["vhosts"][0]
        for policy in ("rate_limit", "concurrency"):
            self.assertEqual(original[policy], rendered[policy])
            self.assertEqual(original["routes"][0][policy], rendered["routes"][0][policy])

    def test_example_does_not_trust_forwarded_identity(self):
        recipe = tomllib.loads(EXAMPLE.read_text())
        self.assertEqual(recipe["server"]["trusted_proxies"], [])
        self.assertFalse(recipe["vhosts"][0]["rate_limit"]["enabled"])
        self.assertTrue(recipe["vhosts"][0]["routes"][0]["rate_limit"]["enabled"])


if __name__ == "__main__":
    unittest.main()
