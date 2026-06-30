#!/usr/bin/env python3
"""Allocate best-effort free localhost ports for smoke tests.

The script reserves all selected ports at once while choosing them, then prints
the numbers and exits. The caller still owns the final bind, so this cannot make
shell smoke tests perfectly race-free, but it avoids repeated ad-hoc allocation
snippets and reduces collision risk by probing random high ports with retries.
"""

from __future__ import annotations

import argparse
import random
import socket
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("count", type=int, help="number of ports to allocate")
    parser.add_argument("--host", default="127.0.0.1", help="bind host to probe")
    parser.add_argument("--min", dest="minimum", type=int, default=20000)
    parser.add_argument("--max", dest="maximum", type=int, default=60999)
    parser.add_argument("--attempts", type=int, default=4096)
    return parser.parse_args()


def reserve_port(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
    except OSError:
        sock.close()
        raise
    return sock


def main() -> int:
    args = parse_args()
    if args.count <= 0:
        print("smoke port allocation failed: count must be positive", file=sys.stderr)
        return 2
    if args.minimum < 1024 or args.maximum > 65535 or args.minimum > args.maximum:
        print("smoke port allocation failed: invalid port range", file=sys.stderr)
        return 2

    sockets: list[socket.socket] = []
    ports: list[int] = []
    rng = random.SystemRandom()

    try:
        for _ in range(args.attempts):
            if len(ports) == args.count:
                break
            port = rng.randint(args.minimum, args.maximum)
            if port in ports:
                continue
            try:
                sockets.append(reserve_port(args.host, port))
            except OSError:
                continue
            ports.append(port)
    finally:
        for sock in sockets:
            sock.close()

    if len(ports) != args.count:
        print(
            f"smoke port allocation failed: needed {args.count} free ports, "
            f"found {len(ports)}",
            file=sys.stderr,
        )
        return 1

    print(" ".join(str(port) for port in ports))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
