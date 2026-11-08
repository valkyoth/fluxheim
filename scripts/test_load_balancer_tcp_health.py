#!/usr/bin/env python3
"""Regression checks for the TCP readiness-port smoke fixture."""

import socket
import time
import tomllib
import unittest

import smoke_load_balancer_tcp_health as smoke


class TcpHealthTests(unittest.TestCase):
    def test_configuration_keeps_application_and_probe_ports_separate(self):
        for guest in (False, True):
            config = tomllib.loads(smoke.configuration(10001, 10002, 10003, 10004, guest))
            self.assertEqual(config["server"]["listen"], ["127.0.0.1:10001"])
            self.assertEqual(config["proxy"]["upstreams"], ["127.0.0.1:10002", "127.0.0.1:10003"])
            self.assertEqual(config["proxy"]["load_balance"]["health_check"], {
                "enabled": True, "protocol": "tcp", "port_override": 10004,
                "interval_secs": 1, "consecutive_success": 1, "consecutive_failure": 1,
                "connect_timeout_secs": 1,
            })

    def test_readiness_detects_misdirected_application_payload(self):
        ready = smoke.Readiness()
        try:
            ready.start()
            with socket.create_connection(("127.0.0.1", ready.port), timeout=2) as stream:
                stream.sendall(b"GET / HTTP/1.1\r\n\r\n")
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                with ready.lock:
                    if ready.connections:
                        break
                time.sleep(0.01)
            with self.assertRaisesRegex(AssertionError, "application traffic"):
                ready.assert_clean()
        finally:
            ready.close()

    def test_readiness_accepts_empty_probes_and_restarts_on_same_port(self):
        ready = smoke.Readiness()
        try:
            for _ in range(2):
                ready.start()
                port = ready.port
                with socket.create_connection(("127.0.0.1", port), timeout=2):
                    pass
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    with ready.lock:
                        if ready.connections:
                            break
                    time.sleep(0.01)
                ready.close()
                ready.assert_clean()
                self.assertEqual(ready.port, port)
        finally:
            ready.close()


if __name__ == "__main__":
    unittest.main()
