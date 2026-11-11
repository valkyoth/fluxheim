#!/usr/bin/env python3
import tomllib
import unittest

import smoke_peer_variants as smoke


class PeerVariantFixtureTests(unittest.TestCase):
    def test_each_tier_and_vary_source(self):
        for tier in ("memory", "filesystem", "storage-bin"):
            for configured in (False, True):
                config = tomllib.loads(smoke.configuration(18080, 18081, tier, configured, (18082, 18083), False))
                cache = config["cache"]
                self.assertEqual(cache.get("vary_request_headers", []), ["x-edition"] if configured else [])
                self.assertEqual(cache["memory"]["enabled"], tier == "memory")
                self.assertTrue(cache["peer_fill"]["fail_open"])
                self.assertEqual(len(cache["peer_fill"]["peers"]), 2)
                if tier != "memory":
                    self.assertEqual(cache["disk"]["backend"], tier)

    def test_container_paths_are_guest_private(self):
        config = tomllib.loads(smoke.configuration(18080, 18081, "storage-bin", True, (), True))
        self.assertEqual(config["cache"]["disk"]["path"], "/var/cache/fluxheim/peer")
        self.assertEqual(config["server"]["process"]["pid_file"], "/run/fluxheim/fluxheim.pid")

    def test_native_receiving_peer_loads_secret_without_outbound_fills(self):
        config = tomllib.loads(smoke.configuration(18080, 18081, "memory", True, (), False, True))
        peer = config["cache"]["peer_fill"]
        self.assertFalse(peer["enabled"])
        self.assertEqual(peer["shared_secret_file"], "peer.secret")

    def test_rejects_unknown_tier_and_invalid_peer_ports(self):
        with self.assertRaises(ValueError):
            smoke.configuration(18080, 18081, "invalid", True, (), False)
        for peer in (0, -1, 65536, '18082"\n'):
            with self.assertRaises(ValueError):
                smoke.configuration(18080, 18081, "memory", True, (peer,), False)


if __name__ == "__main__":
    unittest.main()
