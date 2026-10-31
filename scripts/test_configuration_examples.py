import tomllib
import unittest

from smoke_configuration_examples import EXAMPLES, prepare


class ConfigurationExamples(unittest.TestCase):
    def test_renderer_only_changes_the_loopback_listener(self):
        for name in ("single.toml", "split/fluxheim.toml"):
            source = (EXAMPLES / name).read_text()
            expected = tomllib.loads(source)
            expected["server"]["listen"] = ["127.0.0.1:12345"]
            self.assertEqual(tomllib.loads(prepare(source, 12345)), expected)

    def test_changed_or_ambiguous_template_is_rejected(self):
        source = (EXAMPLES / "single.toml").read_text()
        for invalid in (source.replace("127.0.0.1:8080", "0.0.0.0:8080"),
                        source + '\n# listen = ["127.0.0.1:8080"]'):
            with self.assertRaises(ValueError):
                prepare(invalid, 12345)

    def test_examples_keep_process_paths_local_and_disable_cache(self):
        for name in ("single.toml", "split/fluxheim.toml"):
            config = tomllib.loads((EXAMPLES / name).read_text())
            self.assertFalse(config["cache"]["enabled"])
            process = config["server"]["process"]
            self.assertEqual(process["pid_file"], "fluxheim.pid")
            self.assertEqual(process["certificate_reload_sock"], "reload.sock")
        site = tomllib.loads((EXAMPLES / "split/conf.d/10-site.toml").read_text())
        self.assertEqual(site["vhosts"][0]["web"]["root"], "site")


if __name__ == "__main__":
    unittest.main()
