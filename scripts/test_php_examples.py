#!/usr/bin/env python3
import tomllib
import unittest

from smoke_php_examples import EXTERNAL, MANAGED, ROOT, prepare


class PhpExamplesTests(unittest.TestCase):
    def test_external_renderer_only_changes_loopback_ports(self):
        original = tomllib.loads(EXTERNAL.read_text())
        rendered = tomllib.loads(prepare(EXTERNAL.read_text(), 18080, 19000))
        original["server"]["listen"] = ["127.0.0.1:18080"]
        original["vhosts"][0]["php"]["fpm"]["tcp"] = "127.0.0.1:19000"
        self.assertEqual(original, rendered)

    def test_recipes_keep_shared_roots_and_safe_static_defaults(self):
        for example in (EXTERNAL, MANAGED):
            with self.subTest(example=example.name):
                config = tomllib.loads(example.read_text())
                vhost = config["vhosts"][0]
                self.assertEqual(vhost["php"]["root"], vhost["web"]["root"])
                self.assertEqual(vhost["php"]["preset"], "wordpress")
                self.assertTrue(vhost["web"]["deny_dotfiles"])
                self.assertFalse(vhost["web"]["directory_listing"]["enabled"])
                self.assertNotIn("index.php", vhost["web"]["index_files"])
                self.assertNotIn("cache", vhost)

    def test_managed_recipe_has_no_external_endpoint(self):
        fpm = tomllib.loads(MANAGED.read_text())["vhosts"][0]["php"]["fpm"]
        self.assertEqual(fpm["mode"], "managed")
        self.assertFalse({"socket", "tcp", "tcp_upstreams"}.intersection(fpm))
        self.assertLessEqual(fpm["min_spare_servers"], fpm["start_servers"])
        self.assertLessEqual(fpm["start_servers"], fpm["max_spare_servers"])
        self.assertLessEqual(fpm["max_spare_servers"], fpm["workers"])

    def test_placeholder_drift_fails(self):
        with self.assertRaises(ValueError):
            prepare(EXTERNAL.read_text().replace("9000", "9001"), 18080, 19000)

    def test_flat_root_recipe_has_no_catch_all_static_action(self):
        config = tomllib.loads((ROOT / "examples/php/flat-root.toml").read_text())
        vhost = config["vhosts"][0]
        self.assertNotIn("web", vhost)
        self.assertNotIn("root", vhost)
        self.assertEqual(vhost["php"]["root"], "app")
        self.assertEqual(len(vhost["routes"]), 1)
        route = vhost["routes"][0]
        self.assertEqual(route["path_exact"], "/assets/style.css")
        self.assertEqual(route["web"]["root"], "public-static")
        self.assertNotIn("path_prefix", route)
        self.assertNotIn("methods", route)
        self.assertNotIn("strip_prefix", route)

    def test_application_fragments_parse_without_invented_route_action_key(self):
        import re

        guide = (ROOT / "docs/guides/php-fpm-app-recipes.md").read_text()
        for fragment in re.findall(r"```toml\n(.*?)```", guide, re.DOTALL):
            config = tomllib.loads(fragment)
            vhosts = config.get("vhosts", [])
            if isinstance(vhosts, dict):
                vhosts = [vhosts]
            for vhost in vhosts:
                for route in vhost.get("routes", []):
                    self.assertNotIn("action", route)


if __name__ == "__main__":
    unittest.main()
