#!/usr/bin/env python3
import tomllib
import unittest

from smoke_proxy_transport import EXAMPLE, prepare


class ProxyTransportRecipeTests(unittest.TestCase):
    def test_complete_recipe_remains_parseable(self):
        rendered = tomllib.loads(prepare(EXAMPLE.read_text(), 12001, 12002))
        self.assertEqual(rendered["server"]["listen"], ["127.0.0.1:12001"])
        proxy = rendered["vhosts"][0]["proxy"]
        self.assertEqual(proxy["upstreams"], ["127.0.0.1:12002"])
        self.assertEqual([page["status"] for page in proxy["error_pages"]], [502, 504])
        self.assertEqual(proxy["read_timeout_secs"], 2)

    def test_ambiguous_replacement_is_rejected(self):
        with self.assertRaises(ValueError):
            prepare(EXAMPLE.read_text() + '\n# listen = ["127.0.0.1:8080"]', 12001, 12002)


if __name__ == "__main__":
    unittest.main()
