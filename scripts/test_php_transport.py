#!/usr/bin/env python3
import tomllib
import unittest
import re

from smoke_php_transport import EXTERNAL, ROOT, parameters, php_fields


class PhpTransportTests(unittest.TestCase):
    def test_bounded_parameter_decoding(self):
        self.assertEqual(parameters(b"\x03\x03FOObar"), {"FOO": "bar"})
        self.assertEqual(parameters(b"\x80\x00\x00\x03\x03FOObar"), {"FOO": "bar"})
        for data in (b"\x80", b"\x01", b"\x03\x03FOO"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                parameters(data)

    def test_transport_fixture_only_changes_php_scope(self):
        original = tomllib.loads(EXTERNAL.read_text())
        changed = tomllib.loads(php_fields(EXTERNAL.read_text(), 'pass_request_body = false'))
        original["vhosts"][0]["php"]["pass_request_body"] = False
        self.assertEqual(original, changed)

    def test_runtime_guide_fragments_are_valid_toml(self):
        guide = (ROOT / "docs/guides/php-runtime-support.md").read_text()
        fragments = re.findall(r"```toml\n(.*?)```", guide, re.DOTALL)
        self.assertGreaterEqual(len(fragments), 7)
        for fragment in fragments:
            with self.subTest(fragment=fragment):
                tomllib.loads(fragment)


if __name__ == "__main__":
    unittest.main()
