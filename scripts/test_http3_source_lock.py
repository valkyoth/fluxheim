#!/usr/bin/env python3
"""Negative regression tests for the Commit 1 admission gate."""

import copy
import json
import os
import subprocess
import tomllib
import unittest

import validate_http3_source_lock as gate


class SourceLockTests(unittest.TestCase):
    def setUp(self):
        self.scope = json.loads((gate.ROOT / "docs/http3-source-lock.json").read_text())
        self.manifest = tomllib.loads((gate.PROBE / "Cargo.toml").read_text())
        self.lock = (gate.PROBE / "Cargo.lock").read_bytes()

    def test_current_contract(self):
        gate.validate_scope(self.scope)
        gate.validate_sources(self.scope, self.manifest, self.lock, {"fluxheim"})

    def test_missing_duplicate_and_unknown_requirements_fail(self):
        for replacement in ([], [self.scope["requirements"][0]], [{"id": "unclassified"}]):
            with self.subTest(replacement=replacement):
                scope = copy.deepcopy(self.scope)
                scope["requirements"][1:2] = replacement
                with self.assertRaises(ValueError):
                    gate.validate_scope(scope)

    def test_requirement_cannot_move_to_later_commit(self):
        self.scope["requirements"][0]["owner"] = 23
        with self.assertRaisesRegex(ValueError, "ownership"):
            gate.validate_scope(self.scope)

    def test_empty_requirement_is_not_classified(self):
        self.scope["requirements"][0]["contract"] = " "
        with self.assertRaisesRegex(ValueError, "empty"):
            gate.validate_scope(self.scope)

    def test_exclusion_cannot_be_removed(self):
        self.scope["excluded"].remove("zero-rtt")
        with self.assertRaisesRegex(ValueError, "excluded"):
            gate.validate_scope(self.scope)

    def test_stock_artifact_cannot_drop_php_or_add_wasm(self):
        for features in (list(gate.FEATURES - {"php-fpm"}), list(gate.FEATURES | {"wasm"})):
            self.scope["artifact_features"] = features
            with self.assertRaisesRegex(ValueError, "artifact_features"):
                gate.validate_scope(self.scope)

    def test_unsupported_platform_cannot_be_advertised(self):
        self.scope["platforms"].append("aarch64-pc-windows-msvc")
        with self.assertRaisesRegex(ValueError, "platforms"):
            gate.validate_scope(self.scope)

    def test_pending_qualification_is_not_acceptance(self):
        self.scope["address_policy_evidence"] = "pending-qualification"
        with self.assertRaisesRegex(ValueError, "qualification"):
            gate.validate_scope(self.scope, acceptance=True)
        self.scope["address_policy_evidence"] = "source-qualified"
        gate.validate_scope(self.scope, acceptance=True)

    def test_seamless_policy_cannot_be_downgraded(self):
        for policy in ("reconnect-required", "pending-approval", "unknown"):
            self.scope["address_policy"] = policy
            with self.subTest(policy=policy), self.assertRaisesRegex(ValueError, "seamless"):
                gate.validate_scope(self.scope)

    def test_address_change_coverage_cannot_drift(self):
        for case in gate.ADDRESS_REQUIREMENTS:
            for replacement in ([], ["unknown"], [case, case]):
                scope = copy.deepcopy(self.scope)
                index = scope["address_change_requirements"].index(case)
                scope["address_change_requirements"][index:index + 1] = replacement
                with self.subTest(case=case, replacement=replacement), self.assertRaisesRegex(ValueError, "coverage"):
                    gate.validate_scope(scope)

    def test_active_migration_cannot_be_excluded(self):
        self.scope["excluded"].append("active-migration")
        with self.assertRaisesRegex(ValueError, "excluded"):
            gate.validate_scope(self.scope)

    def test_unknown_qualification_is_rejected(self):
        self.scope["address_policy_evidence"] = "approved"
        with self.assertRaisesRegex(ValueError, "evidence"):
            gate.validate_scope(self.scope)

    def test_provider_rejections_with_forced_color(self):
        result = subprocess.run(
            ["sh", str(gate.ROOT / "scripts/validate_http3_probe_features.sh")],
            env={**os.environ, "CARGO_TERM_COLOR": "always"},
            capture_output=True, text=True, check=False, timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("provider rejection checks: ok", result.stdout)

    def test_transitive_lock_cannot_drift(self):
        with self.assertRaisesRegex(ValueError, "transitive lock"):
            gate.validate_sources(self.scope, self.manifest, self.lock + b"\n", set())

    def test_direct_versions_are_exact(self):
        self.manifest["dependencies"]["quinn"]["version"] = "0.11"
        with self.assertRaisesRegex(ValueError, "unpinned"):
            gate.validate_sources(self.scope, self.manifest, self.lock, set())

    def test_provider_features_and_defaults_are_frozen(self):
        self.manifest["features"]["default"].append("aws-lc")
        with self.assertRaisesRegex(ValueError, "provider feature"):
            gate.validate_sources(self.scope, self.manifest, self.lock, set())
        self.manifest["features"]["default"] = ["ring"]
        self.manifest["dependencies"]["quinn"]["default-features"] = True
        with self.assertRaisesRegex(ValueError, "implicit defaults"):
            gate.validate_sources(self.scope, self.manifest, self.lock, set())

    def test_datagram_cannot_be_added(self):
        self.manifest["dependencies"]["h3-quinn"]["features"] = ["datagram"]
        with self.assertRaisesRegex(ValueError, "forbidden H3"):
            gate.validate_sources(self.scope, self.manifest, self.lock, set())

    def test_runtime_and_brynja_dependency_injection_fails(self):
        for name in ("quinn", "h3", "brynja-quic-tls"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "production graph"):
                gate.validate_sources(self.scope, self.manifest, self.lock, {name})

    def test_renamed_dependency_is_still_identified(self):
        names = gate.dependency_names({"target": {"cfg(unix)": {
            "dependencies": {"transport": {"package": "quinn", "version": "0.11"}}
        }}})
        self.assertEqual(names, {"quinn"})


if __name__ == "__main__":
    unittest.main()
