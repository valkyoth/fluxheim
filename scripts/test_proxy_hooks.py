import tomllib
import unittest

from smoke_proxy_hooks import EXAMPLES, prepare


class ProxyHookExamples(unittest.TestCase):
    def test_renderer_preserves_policies(self):
        for name in ("auth.toml", "mirror.toml"):
            source = (EXAMPLES / name).read_text()
            expected = tomllib.loads(source)
            expected["server"]["listen"] = ["127.0.0.1:12340"]
            vhost = expected["vhosts"][0]
            proxy = vhost["routes"][0]["proxy"] if "routes" in vhost else vhost["proxy"]
            proxy["upstreams"] = ["127.0.0.1:12341"]
            if "auth_request" in proxy:
                proxy["auth_request"]["url"] = "http://127.0.0.1:12342/check"
            else:
                proxy["mirror"]["base_url"] = "http://127.0.0.1:12343/shadow"
            self.assertEqual(tomllib.loads(prepare(source, 12340, 12341, 12342, 12343)), expected)

    def test_renderer_rejects_duplicate_origin_literal(self):
        source = (EXAMPLES / "auth.toml").read_text()
        with self.assertRaises(ValueError):
            prepare(source + '\n# upstreams = ["127.0.0.1:9001"]', 12340, 12341, 12342, 12343)


if __name__ == "__main__":
    unittest.main()
