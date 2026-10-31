#!/usr/bin/env python3
"""Keep the executable retry guide fixture bounded and independent of health probes."""

import concurrent.futures
from pathlib import PurePosixPath
import tomllib
import unittest
from unittest import mock

import smoke_load_balancer_examples as smoke
import smoke_load_balancer_retry_container as container


class RetryExamplesTests(unittest.TestCase):
    def test_latency_preference_allows_bounded_ewma_convergence(self):
        replies = [(200, b"origin-b")] * 3 + [(200, b"origin-a")] * 3
        with mock.patch.object(smoke, "request", side_effect=replies) as request:
            smoke.expect_latency_preference(12345, b"origin-a")
        self.assertEqual(request.call_count, 6)

    def test_latency_preference_rejects_stuck_and_alternating_selection(self):
        for replies in ([(200, b"origin-b")] * 12,
                        [(200, b"origin-a"), (200, b"origin-b")] * 6):
            with self.subTest(replies=replies), \
                    mock.patch.object(smoke, "request", side_effect=replies) as request, \
                    mock.patch.object(smoke.time, "monotonic", return_value=0):
                with self.assertRaisesRegex(AssertionError, "did not converge"):
                    smoke.expect_latency_preference(12345, b"origin-a")
                self.assertEqual(request.call_count, 12)

    def test_latency_preference_has_time_limit_and_rejects_bad_responses(self):
        with mock.patch.object(smoke, "request", return_value=(200, b"origin-b")) as request, \
                mock.patch.object(smoke.time, "monotonic", side_effect=[0, 10]):
            with self.assertRaisesRegex(AssertionError, "did not converge"):
                smoke.expect_latency_preference(12345, b"origin-a")
            self.assertEqual(request.call_count, 1)
        with mock.patch.object(smoke, "request", return_value=(200, b"origin-a")), \
                mock.patch.object(smoke.time, "monotonic", side_effect=[0, 1, 2, 10]):
            with self.assertRaisesRegex(AssertionError, "did not converge"):
                smoke.expect_latency_preference(12345, b"origin-a")
        for response in ((503, b"origin-a"), (200, b"unexpected")):
            with mock.patch.object(smoke, "request", return_value=response):
                with self.assertRaisesRegex(AssertionError, "unexpected latency response"):
                    smoke.expect_latency_preference(12345, b"origin-a")

    def test_latency_modes_are_bounded_and_disable_active_probes(self):
        source = (smoke.EXAMPLES / "local.toml").read_text()
        for mode, threshold in (("selection", 0), ("passive", 10), ("disabled", 0), ("body", 200)):
            config = tomllib.loads(smoke.latency_config(source, 10001, 10002, 10003, mode))
            policy = config["proxy"]["load_balance"]
            self.assertEqual(policy["selection"], "least-time")
            self.assertEqual(policy["health_check"], {"enabled": False})
            self.assertEqual(policy["passive_health"]["max_latency_ms"], threshold)
            self.assertEqual(policy["passive_health"]["ejection_secs"], 120)
            self.assertEqual(policy["passive_health"]["min_healthy_backends"], 0)
            guest = tomllib.loads(container.container_config(10001, 10002, 10003, False, mode))
            self.assertEqual(guest["proxy"], config["proxy"])
        with self.assertRaises(ValueError):
            smoke.latency_config(source, 10001, 10002, 10003, "unknown")
        calls = smoke.OriginCalls()
        for delay in (-1, 2, float("inf"), float("nan")):
            with self.assertRaises(ValueError):
                calls.set_timing(delay)
        calls.set_timing(0.1, 0.4)
        self.assertEqual(calls.timing(), (0.1, 0.4))

    def test_disabled_and_enabled_share_the_same_single_retry_budget(self):
        source = (smoke.EXAMPLES / "local.toml").read_text()
        for enabled in (False, True):
            config = tomllib.loads(smoke.retry_config(source, 10001, 10002, 10003, enabled))
            self.assertEqual(config["server"]["listen"], ["127.0.0.1:10001"])
            self.assertEqual(config["proxy"]["upstreams"], ["127.0.0.1:10002", "127.0.0.1:10003"])
            self.assertEqual(config["proxy"]["upstream_priority_groups"], [20, 10])
            self.assertEqual(config["proxy"]["load_balance"]["health_check"], {"enabled": False})
            self.assertEqual(config["proxy"]["load_balance"]["retry"], {
                "enabled": enabled, "max_retries": 1, "methods": ["GET"],
                "statuses": [503], "budget_per_window": 1, "budget_window_secs": 3600,
            })

    def test_ambiguous_template_is_rejected(self):
        source = (smoke.EXAMPLES / "local.toml").read_text()
        for duplicate in ("[proxy]\n", "[proxy.load_balance.health_check]\n"):
            with self.assertRaises(ValueError):
                smoke.retry_config(source + duplicate, 10001, 10002, 10003, True)

    def test_origin_counter_is_shared_under_concurrency(self):
        calls = smoke.OriginCalls()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(lambda _: calls.increment(), range(1000)))
        self.assertEqual(calls.count(), 1000)

    def test_container_config_only_changes_private_runtime_paths(self):
        for enabled in (False, True):
            config = tomllib.loads(container.container_config(10001, 10002, 10003, enabled))
            process = config["server"]["process"]
            self.assertEqual(process["pid_file"], "/run/fluxheim/fluxheim.pid")
            self.assertEqual(process["upgrade_sock"], "/run/fluxheim/upgrade.sock")
            self.assertEqual(process["certificate_reload_sock"], "/run/fluxheim/reload.sock")
            self.assertEqual(config["server"]["listen"], ["127.0.0.1:10001"])
            self.assertEqual(config["proxy"]["load_balance"]["retry"]["enabled"], enabled)

    def test_container_uses_immutable_image_and_read_only_single_file_mount(self):
        digest = "sha256:" + "a" * 64
        name = "fluxheim-retry-" + "b" * 32
        args = container.run_arguments(name, digest, PurePosixPath("/tmp/fixture/config.toml"))
        self.assertIn("--pull=never", args)
        self.assertIn("--cap-drop=ALL", args)
        self.assertIn("no-new-privileges", args)
        self.assertIn("--network=host", args)
        self.assertEqual(args[-3:], [digest, "--config", "/etc/fluxheim/fluxheim.toml"])
        self.assertEqual(args[args.index("-v") + 1], "/tmp/fixture/config.toml:/etc/fluxheim/fluxheim.toml:ro,Z")
        for invalid in ("latest", "--privileged", digest + "x"):
            with self.assertRaises(ValueError):
                container.run_arguments(name, invalid, PurePosixPath("/tmp/config.toml"))
        for invalid in ("other-project", "--all"):
            with self.assertRaises(ValueError):
                container.run_arguments(invalid, digest, PurePosixPath("/tmp/config.toml"))
        for invalid in ("relative", "/tmp/a:b", "/tmp/a,b", "/tmp/a\nb"):
            with self.assertRaises(ValueError):
                container.run_arguments(name, digest, PurePosixPath(invalid))


if __name__ == "__main__":
    unittest.main()
