#!/usr/bin/env python3
"""Validate the OpenAPI document and positive/negative response fixtures."""
import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, ValidationError
from openapi_spec_validator import validate
from operational_status_client import read_status

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "docs/reference/operational-status.schema.json").read_text())
API = json.loads((ROOT / "docs/reference/operational-status.openapi.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)


class ContractTests(unittest.TestCase):
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
