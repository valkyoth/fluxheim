#!/usr/bin/env python3
"""Fail-closed fixture/contract tests; live backends are a separate required gate."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import collector_configs
import collector_logs
import collector_signoz
import collector_stack as stack
import generate_observability_dashboards as dashboards


class CollectorTests(unittest.TestCase):
    def test_images_are_digest_pinned(self):
        fixture = stack.Stack("podman", Path("/tmp/fixture"))
        self.assertEqual(len(fixture.images), 9)
        self.assertTrue(all("@sha256:" in value["image"] for value in fixture.images.values()))

    def test_mutable_backend_tag_is_rejected_before_execution(self):
        with patch.object(Path, "read_text", return_value='{"backend":{"image":"example:latest"}}'):
            with self.assertRaises(ValueError):
                stack.Stack("podman", Path("/tmp/fixture"))

    def test_runtime_is_closed_enum(self):
        with self.assertRaises(ValueError):
            stack.Stack("sh", Path("/tmp/fixture"))

    def test_candidate_cannot_be_an_option_and_is_resolved_once(self):
        fixture = stack.Stack("podman", Path("/tmp/fixture"))
        with patch.object(fixture, "command", return_value=json.dumps([{"Id": "sha256:" + "a" * 64}])) as command:
            self.assertEqual(fixture.candidate("localhost/fluxheim:test"), "sha256:" + "a" * 64)
            for reference in ("--help", "bad value", "image;command", "a\nimage"):
                with self.assertRaises(ValueError):
                    fixture.candidate(reference)
            command.assert_called_once_with("image", "inspect", "localhost/fluxheim:test")

    def test_mutable_candidate_identity_is_rejected(self):
        fixture = stack.Stack("podman", Path("/tmp/fixture"))
        with patch.object(fixture, "command", return_value='[{"Id":"image:tag"}]'):
            with self.assertRaises(ValueError):
                fixture.candidate("image:tag")

    def test_duplicate_role_cannot_overwrite_cleanup_ownership(self):
        fixture = stack.Stack("podman", Path("/tmp/fixture"))
        fixture.names["php"] = "owned-php"
        with self.assertRaises(ValueError):
            fixture.start("php", "test")
        self.assertEqual(fixture.names["php"], "owned-php")

    def test_container_calls_do_not_use_shell(self):
        fixture = stack.Stack("docker", Path("/tmp/fixture"))
        with patch.object(stack.subprocess, "run", return_value=Mock(stdout="ok", stderr="")) as run:
            self.assertEqual(fixture.command("inspect", "opaque;value"), "ok")
            self.assertEqual(run.call_args.args[0], ["docker", "inspect", "opaque;value"])
            self.assertNotIn("shell", run.call_args.kwargs)
            self.assertTrue(run.call_args.kwargs["check"])
            self.assertEqual(run.call_args.kwargs["timeout"], 120)

    def test_published_ports_are_loopback_only_and_ephemeral(self):
        fixture = stack.Stack("podman", Path("/tmp/fixture"))
        inspect = json.dumps([{"NetworkSettings": {"Ports": {"8088/tcp": [{"HostPort": "12345"}]}}}])
        with patch.object(fixture, "command", side_effect=["id", inspect]) as command:
            fixture.start("php", "test", ports=[8088], owner=True)
        args = command.call_args_list[0].args
        self.assertIn("127.0.0.1::8088", args)
        self.assertNotIn("--privileged", args)
        self.assertIn("--userns=keep-id", args)
        self.assertEqual(fixture.ports, {8088: 12345})

    def test_shared_network_and_user_namespace_for_podman(self):
        fixture = stack.Stack("podman", Path("/tmp/fixture"))
        fixture.names["php"] = "owned-php"
        with patch.object(fixture, "command") as command:
            fixture.start("origin", "test", owner=True)
        args = command.call_args.args
        self.assertIn("--userns", args)
        self.assertEqual(args.count("container:owned-php"), 2)

    def test_docker_does_not_use_podman_user_namespace_flags(self):
        fixture = stack.Stack("docker", Path("/tmp/fixture"))
        fixture.names["php"] = "owned-php"
        with patch.object(fixture, "command") as command:
            fixture.start("origin", "test", owner=True)
        self.assertNotIn("--userns", command.call_args.args)

    def test_partial_start_is_owned_for_cleanup(self):
        fixture = stack.Stack("podman", Path("/tmp/fixture"))
        with patch.object(fixture, "command", side_effect=OSError("failed")):
            with self.assertRaises(OSError):
                fixture.start("php", "test")
        self.assertEqual(list(fixture.names), ["php"])

    def test_cleanup_only_owned_names_in_reverse_order(self):
        fixture = stack.Stack("podman", Path("/tmp/fixture"))
        fixture.names = {"php": "own-php", "origin": "own-origin"}
        with patch.object(fixture, "command") as command:
            fixture.close()
        self.assertEqual([c.args for c in command.call_args_list],
                         [("rm", "-f", "-v", "own-origin"), ("rm", "-f", "-v", "own-php")])

    def test_cleanup_failure_is_not_silently_ignored(self):
        fixture = stack.Stack("podman", Path("/tmp/fixture"))
        fixture.names = {"php": "own-php"}
        with patch.object(fixture, "command", side_effect=OSError("failed")):
            with self.assertRaisesRegex(RuntimeError, "own-php"):
                fixture.close()

    def test_missing_collector_never_skips(self):
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            stack.poll(lambda: False, "required backend", seconds=0)

    def test_bad_assertion_is_not_retried(self):
        def broken():
            raise AssertionError("bad signal")
        with self.assertRaisesRegex(AssertionError, "bad signal"):
            stack.poll(broken, "signal")

    def test_api_rejects_redirect_and_does_not_disclose_body(self):
        for status in (302, 401, 500):
            with self.subTest(status=status), patch.object(stack, "http", return_value=(status, b"secret")):
                with self.assertRaises(RuntimeError) as error:
                    stack.api(1, "/private?token=secret")
                self.assertNotIn("secret", str(error.exception))

    def test_response_is_bounded_and_connection_closed(self):
        connection = Mock()
        connection.getresponse.return_value.read.return_value = b"x" * (stack.LIMIT + 1)
        with patch.object(stack.http_client, "HTTPConnection", return_value=connection):
            with self.assertRaisesRegex(RuntimeError, "exceeded"):
                stack.http(12345)
        connection.close.assert_called_once()
        connection.getresponse.return_value.read.assert_called_once_with(stack.LIMIT + 1)

    def test_collected_log_canary_and_size_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "logs"
            for data in (collector_logs.CANARY, "x" * (stack.LIMIT + 1)):
                path.write_text(data)
                with self.assertRaises(AssertionError):
                    collector_logs.read_private(path)

    def test_partial_export_record_waits_but_malformed_complete_record_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "logs"
            path.write_text('{"partial":')
            self.assertEqual(collector_logs.records(path), [])
            path.write_text('invalid\n')
            with self.assertRaises(json.JSONDecodeError):
                collector_logs.records(path)

    def test_configs_preserve_security_and_distinct_ingest_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collector_configs.fixtures(root)
            collector_configs.collector(root, signoz=True)
            config = json.loads((root / "collector.json").read_text())
            self.assertEqual(config["receivers"]["otlp"]["protocols"]["http"]["endpoint"], "127.0.0.1:4318")
            self.assertEqual(config["exporters"]["otlphttp/signoz"]["endpoint"], "http://127.0.0.1:4321")
            self.assertIn("memory_limiter", config["processors"])
            text = (root / "fluxheim.toml").read_text()
            self.assertNotIn("verify_cert = false", text)
            self.assertIn('mode = "external"', text)
            self.assertEqual((root / "key.pem").stat().st_mode & 0o777, 0o600)

    def test_dashboard_drift_and_missing_data_semantics(self):
        for name, content in (("grafana", dashboards.grafana()), ("signoz", dashboards.signoz())):
            self.assertEqual(json.loads((stack.ASSETS / f"{name}-dashboard.json").read_text()), content)
            encoded = json.dumps(content)
            self.assertNotIn("vector(0)", encoded)
            self.assertNotIn("password", encoded.lower())
            self.assertIn("vhost", encoded)

    def test_signoz_uses_otlp_histogram_component_names(self):
        query = 'histogram_quantile(0.95,sum by(le)(rate(fluxheim_http_request_duration_seconds_bucket{%s}[1m])))'
        converted = dashboards.signoz_query(query)
        self.assertIn('{"fluxheim_http_request_duration_seconds.bucket",%s}', converted)
        self.assertNotIn("seconds_bucket", converted)
        self.assertEqual(dashboards.signoz_query('fluxheim_http_requests_total{%s}'), 'fluxheim_http_requests_total{%s}')

    def test_empty_or_nonfinite_chart_is_not_proof(self):
        for result in (None, [], [{"aggregations": None}], [{"aggregations": [{"series": None}]}],
                       [{"aggregations": [{"series": [{"values": [{"value": "NaN"}]}]}]}]):
            self.assertFalse(collector_signoz.has_chart_points({"data": {"data": {"results": result}}}))
        with self.assertRaises(KeyError):
            collector_signoz.has_chart_points({"data": {"error": "bad response"}})
        self.assertTrue(collector_signoz.has_chart_points({"data": {"data": {"results": [
            {"aggregations": [{"series": [{"values": [{"value": 0}]}]}]}]}}}))

    def test_visible_chart_requires_two_finite_samples_in_one_series(self):
        response = {"data": {"data": {"results": [{"aggregations": [{"series": [
            {"values": [{"value": 0}, {"value": "NaN"}]}, {"values": [{"value": 1}]}]}]}]}}}
        self.assertFalse(collector_signoz.has_chart_points(response, minimum=2))
        response["data"]["data"]["results"][0]["aggregations"][0]["series"][0]["values"].append({"value": 0})
        self.assertTrue(collector_signoz.has_chart_points(response, minimum=2))

    def test_build_contexts_exclude_private_vm_state_and_node_modules(self):
        docker = (stack.ROOT / ".dockerignore").read_text()
        self.assertEqual(docker, (stack.ROOT / ".containerignore").read_text())
        for path in ("release-reports", "**/node_modules", ".git", "target"):
            self.assertIn(path, docker.splitlines())

    def test_required_mode_dispatches_before_optional_smoke_setup(self):
        script = (stack.ROOT / "scripts/smoke_observability_local.sh").read_text()
        self.assertLess(script.index("--required-collectors"), script.index("mktemp"))
        wrapper = (stack.ROOT / "scripts/check_collectors.sh").read_text()
        self.assertIn("--required-collectors", wrapper)
        self.assertNotIn("--stack grafana", wrapper)

    def test_doc_links_skip_installed_packages_but_check_project_docs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor = root / "tools/browser/node_modules/package"
            vendor.mkdir(parents=True)
            (vendor / "README.md").write_text("[upstream-only](not-shipped.md)\n")
            command = ["perl", str(stack.ROOT / "scripts/check-doc-links.pl")]
            result = subprocess.run(command, cwd=root, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0)
            (root / "README.md").write_text("[broken project link](missing.md)\n")
            result = subprocess.run(command, cwd=root, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"broken local link: missing.md", result.stderr)

    def test_optimized_python_cannot_disable_live_assertions(self):
        result = subprocess.run([os.sys.executable, "-O", str(stack.ROOT / "scripts/smoke_collectors.py"), "--help"],
                                text=True, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)

    def test_browser_timeout_reaps_its_process_group(self):
        process = Mock(pid=12345)
        process.wait.side_effect = [subprocess.TimeoutExpired("node", 1), 0]
        context = Mock()
        context.__enter__ = Mock(return_value=process)
        context.__exit__ = Mock(return_value=False)
        with patch.object(stack.subprocess, "Popen", return_value=context) as popen, patch.object(stack.os, "killpg") as kill:
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                stack.run_browser(["node", "fixture"], timeout=1)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        kill.assert_called_once_with(12345, stack.signal.SIGTERM)
        self.assertEqual(process.wait.call_count, 2)


if __name__ == "__main__":
    unittest.main()
