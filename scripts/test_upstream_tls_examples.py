import tomllib
import unittest

from smoke_upstream_tls_examples import EXAMPLES, prepare


class UpstreamTlsExamples(unittest.TestCase):
    def test_rendering_preserves_trust_and_client_policy(self):
        for name in ("upstream.toml", "upstream-mtls.toml"):
            source = (EXAMPLES / name).read_text()
            before = tomllib.loads(source)
            after = tomllib.loads(prepare(source, 12345, 12346))
            self.assertEqual(after["server"]["listen"], ["127.0.0.1:12345"])
            expected = before["vhosts"][0]["proxy"]
            expected["upstreams"] = ["127.0.0.1:12346"]
            self.assertEqual(after["vhosts"][0]["proxy"], expected)
            self.assertTrue(expected["upstream_verify_cert"])
            self.assertTrue(expected["upstream_verify_hostname"])

    def test_missing_and_ambiguous_ports_are_rejected(self):
        source = (EXAMPLES / "upstream.toml").read_text()
        for needle in ('listen = ["127.0.0.1:8080"]', 'upstreams = ["127.0.0.1:9443"]'):
            for invalid in (source.replace(needle, ""), source + "\n" + needle):
                with self.subTest(needle=needle), self.assertRaises(ValueError):
                    prepare(invalid, 12345, 12346)


if __name__ == "__main__":
    unittest.main()
