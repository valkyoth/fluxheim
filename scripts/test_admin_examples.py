#!/usr/bin/env python3
"""Keep the admin guide's inventory aligned with actual source definitions."""
import re
import tomllib
import unittest

from smoke_admin_examples import EXAMPLE, ROOT


class AdminGuideTests(unittest.TestCase):
    def test_recipe_is_local_and_uses_distinct_secret_files(self):
        value = tomllib.loads(EXAMPLE.read_text())
        admin = value["admin"]
        self.assertEqual(admin["listen"], "127.0.0.1:9090")
        self.assertTrue(admin["require_loopback"])
        self.assertNotIn("token_env", admin)
        self.assertEqual(len({admin["token_file"], admin["operational_token_file"],
                              admin["snapshot_integrity_key_file"]}), 3)
        self.assertFalse(admin["health"]["unauthenticated"])

    def test_every_router_path_is_documented(self):
        source = (ROOT / "src/admin/request_router.rs").read_text()
        guide = (ROOT / "docs/guides/admin.md").read_text()
        paths = set(re.findall(r'"(/_fluxheim/[^"\s]+)"', source))
        self.assertEqual(len(paths), 26)
        for path in paths:
            self.assertIn(path, guide)

    def test_every_scalar_configuration_field_is_documented(self):
        guide = (ROOT / "docs/guides/admin.md").read_text()
        count = 0
        structs = (("config_admin", "AdminConfig", ""),
                   ("config_admin_transport", "AdminClientCertificateConfig", ""),
                   ("config_admin_socket", "AdminOpsSocketConfig", ""),
                   ("config_admin_health", "AdminHealthConfig", "admin.health."),
                   ("config_admin_health", "AdminAuthThrottleConfig", "admin.auth_throttle."),
                   ("config_admin_health", "AdminSelfHealingConfig", "admin.self_healing."))
        for file, name, prefix in structs:
            source = (ROOT / f"crates/fluxheim-config/src/{file}.rs").read_text()
            body = source.split(f"pub struct {name} {{", 1)[1].split("\n}", 1)[0]
            for field, kind in re.findall(r"pub (\w+): ([^,]+),", body):
                if kind.startswith("Admin") and kind.endswith("Config"):
                    continue
                self.assertIn(f"| `{prefix}{field}` |", guide)
                count += 1
        self.assertEqual(count, 30)
        self.assertIn('`"trusted_tls_terminator"`', guide)



if __name__ == "__main__":
    unittest.main()
