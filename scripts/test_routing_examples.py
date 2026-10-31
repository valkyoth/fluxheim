import tomllib
import unittest

from smoke_routing_examples import EXAMPLE, prepare


class RoutingExamples(unittest.TestCase):
    def test_renderer_changes_only_listener_and_origin_ports(self):
        source = EXAMPLE.read_text()
        expected = tomllib.loads(source)
        expected["server"]["listen"] = ["127.0.0.1:12345"]
        for vhost in expected["vhosts"]:
            if "proxy" in vhost:
                vhost["proxy"]["upstreams"] = ["127.0.0.1:12346"]
            for route in vhost.get("routes", []):
                if "proxy" in route:
                    route["proxy"]["upstreams"] = ["127.0.0.1:12346"]
        self.assertEqual(tomllib.loads(prepare(source, 12345, 12346)), expected)

    def test_ambiguous_or_changed_origin_is_rejected(self):
        source = EXAMPLE.read_text()
        for invalid in (source + '\n# "127.0.0.1:9001"',
                        source.replace("127.0.0.1:9001", "127.0.0.1:9002", 1)):
            with self.assertRaises(ValueError):
                prepare(invalid, 12345, 12346)


if __name__ == "__main__":
    unittest.main()
