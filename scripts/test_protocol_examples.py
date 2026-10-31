#!/usr/bin/env python3
import socket
import tomllib
import unittest

from smoke_protocol_examples import EXAMPLES, FRAME, SIGNATURE, preamble, prepare


class ProtocolExamplesTests(unittest.TestCase):
    def test_templates_render_without_changing_protocol_policy(self):
        for name in ("websocket", "grpc", "proxy-protocol"):
            original = tomllib.loads((EXAMPLES / f"{name}.toml").read_text())
            actual = tomllib.loads(prepare((EXAMPLES / f"{name}.toml").read_text(), 12001, 12002))
            self.assertEqual(actual["server"]["listen"], ["127.0.0.1:12001"])
            original["server"]["listen"] = actual["server"]["listen"]
            old = original["vhosts"][0]
            new = actual["vhosts"][0]
            old_proxy = old["routes"][0]["proxy"] if "routes" in old else old["proxy"]
            new_proxy = new["routes"][0]["proxy"] if "routes" in new else new["proxy"]
            self.assertEqual(new_proxy["upstreams"], ["127.0.0.1:12002"])
            old_proxy["upstreams"] = new_proxy["upstreams"]
            self.assertEqual(actual, original)

    def test_sender_frames_have_exact_bounded_layout(self):
        self.assertEqual(preamble("v1", 8080), b"PROXY TCP4 198.51.100.20 127.0.0.1 4567 8080\r\n")
        binary = preamble("v2", 8080)
        self.assertEqual(len(binary), 28)
        self.assertEqual(binary[:16], SIGNATURE + b"\x21\x11\x00\x0c")
        self.assertEqual(binary[16:20], socket.inet_aton("198.51.100.20"))
        self.assertEqual(bytes(a ^ b for a, b in zip(FRAME[6:], FRAME[2:6])), b"ping")

    def test_ambiguous_listener_replacement_rejected(self):
        with self.assertRaises(ValueError):
            prepare((EXAMPLES / "websocket.toml").read_text() + '\n# listen = ["127.0.0.1:8080"]', 12001, 12002)


if __name__ == "__main__":
    unittest.main()
