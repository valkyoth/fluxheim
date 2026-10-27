#!/usr/bin/env python3
"""Validate the OpenAPI document and positive/negative response fixtures."""
import copy
import json
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile

from jsonschema import Draft202012Validator, ValidationError
from openapi_spec_validator import validate
from operational_status_client import read_status

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "docs/reference/operational-status.schema.json").read_text())
API = json.loads((ROOT / "docs/reference/operational-status.openapi.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


class ContractTests(unittest.TestCase):
    def test_wheel_lock_and_all_ci_installs_enforce_hashes(self):
        lock = (ROOT / "scripts/operational_status_requirements.txt").read_text()
        self.assertIn("--require-hashes", lock)
        self.assertIn("--only-binary=:all:", lock)
        entries = lock.replace("\\\n", " ").splitlines()
        count = 0
        for entry in entries:
            if not entry or entry.startswith(("#", "--")):
                continue
            self.assertRegex(entry, r"^[\w-]+==[\d.]+")
            hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})(?:\s|$)", entry)
            self.assertTrue(hashes)
            count += 1
        self.assertEqual(count, 19)
        commands = [line for line in (ROOT / ".github/workflows/ci.yml").read_text().splitlines()
                    if "pip install" in line and "operational_status_requirements.txt" in line]
        self.assertEqual(len(commands), 3)
        for command in commands:
            self.assertIn("--require-hashes --only-binary=:all:", command)
            self.assertIn("--force-reinstall", command)

    def test_pip_rejects_substituted_wheel_and_unhashed_dependency(self):
        # An offline synthetic wheel exercises pip itself, without installing code.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "fluxheim_hash_fixture-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("fluxheim_hash_fixture-1.0.dist-info/METADATA",
                                 "Metadata-Version: 2.1\nName: fluxheim-hash-fixture\nVersion: 1.0\n")
                archive.writestr("fluxheim_hash_fixture-1.0.dist-info/WHEEL",
                                 "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            requirement = root / "requirements.txt"
            command = [sys.executable, "-m", "pip", "--isolated", "--disable-pip-version-check",
                       "download", "--no-index", "--no-deps", "--no-cache-dir",
                       "--require-hashes", "--only-binary=:all:", "--find-links", str(root),
                       "--dest", str(root / "output"), "-r", str(requirement)]
            for hash_value, success in [(digest, True), ("0" * 64, False), (None, False)]:
                requirement.write_text("fluxheim-hash-fixture==1.0" +
                                       (f" --hash=sha256:{hash_value}" if hash_value else "") + "\n")
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                if not success:
                    self.assertIn("hash", result.stderr.lower())

    def test_openapi_and_schema(self):
        Draft202012Validator.check_schema(SCHEMA)
        validate(API, base_uri=(ROOT / "docs/reference/operational-status.openapi.json").as_uri())

    def test_response_and_error_fixtures(self):
        VALIDATOR.validate(json.loads((ROOT / "tests/fixtures/observability/operational-status.json").read_text()))
        validator = Draft202012Validator(API["components"]["schemas"]["Error"])
        for value in json.loads((ROOT / "tests/fixtures/observability/operational-errors.json").read_text()):
            validator.validate(value)

    def test_private_fields_invalid_states_and_unbounded_values_rejected(self):
        value = json.loads((ROOT / "tests/fixtures/observability/operational-status.json").read_text())
        for key, invalid in (("token", "secret"), ("schema_version", 2),
                             ("readiness", "maybe"), ("instance_id", "x" * 5000), ("uptime_secs", -1)):
            other = copy.deepcopy(value)
            other[key] = invalid
            with self.assertRaises(ValidationError):
                VALIDATOR.validate(other)

    def test_client_rejects_unsafe_origins_before_connecting(self):
        for origin in ("http://example.com", "http://10.0.0.1", "https://user:secret@example.com",
                       "https://example.com/path", "https://example.com/?token=secret", "ftp://127.0.0.1"):
            with self.assertRaises(ValueError):
                read_status(origin, "secret")


if __name__ == "__main__":
    unittest.main()
