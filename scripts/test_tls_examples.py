#!/usr/bin/env python3
"""Guard the local guide harness against treating timeouts or success as denial."""

import socket
import ssl
import unittest

from smoke_tls_examples import rejected, replace_once


class TlsGuideHarnessTests(unittest.TestCase):
    def test_tls_alert_is_expected_denial(self):
        def deny():
            raise ssl.SSLError("fixture alert")
        rejected(deny)

    def test_success_is_not_denial(self):
        with self.assertRaises(AssertionError):
            rejected(lambda: None)

    def test_timeout_is_not_denial(self):
        def stall():
            raise socket.timeout("fixture stalled")
        with self.assertRaises(TimeoutError):
            rejected(stall)

    def test_template_edits_require_exactly_one_occurrence(self):
        for content in ("", "needle needle"):
            with self.assertRaises(ValueError):
                replace_once(content, "needle", "replacement")


if __name__ == "__main__":
    unittest.main()
