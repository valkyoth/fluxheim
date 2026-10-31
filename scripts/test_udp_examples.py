#!/usr/bin/env python3
import tomllib
import unittest

from smoke_udp_examples import EXAMPLE, SYSLOG_EXAMPLE, prepare, syslog_recipe


class UdpExamplesTests(unittest.TestCase):
    def test_private_recipe_and_renderer_preserve_limits(self):
        source = EXAMPLE.read_text()
        original = tomllib.loads(source)
        rendered = tomllib.loads(prepare(source, 12001, 12002, 12003))
        self.assertEqual(original["server"]["listen"], [])
        self.assertTrue(original["udp"]["enabled"])
        route = original["udp"]["routes"][0]
        self.assertEqual(route["listen"], ["127.0.0.1:15353"])
        route["listen"] = ["127.0.0.1:12001"]
        route["upstream"] = "127.0.0.1:12002"
        self.assertEqual(original["udp"], rendered["udp"])
        self.assertEqual(rendered["metrics"]["listen"], "127.0.0.1:12003")
        self.assertTrue(rendered["metrics"]["require_loopback"])

    def test_ipv6_renderer_only_changes_loopback_addresses(self):
        rendered = tomllib.loads(prepare(EXAMPLE.read_text(), 12001, 12002, 12003, True))
        route = rendered["udp"]["routes"][0]
        self.assertEqual(route["listen"], ["[::1]:12001"])
        self.assertEqual(route["upstream"], "[::1]:12002")

    def test_changed_placeholder_fails_before_execution(self):
        with self.assertRaises(ValueError):
            prepare(EXAMPLE.read_text().replace("15353", "15354"), 12001, 12002, 12003)

    def test_syslog_recipe_changes_only_fixture_addresses(self):
        original = tomllib.loads(SYSLOG_EXAMPLE.read_text())
        rendered = tomllib.loads(prepare(syslog_recipe(), 12001, 12002, 12003))
        route = original["udp"]["routes"][0]
        self.assertEqual(route["mode"], "syslog-forward")
        route["listen"] = ["127.0.0.1:12001"]
        route["upstream"] = "127.0.0.1:12002"
        self.assertEqual(original["udp"], rendered["udp"])


if __name__ == "__main__":
    unittest.main()
