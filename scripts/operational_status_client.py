#!/usr/bin/env python3
"""Read Fluxheim status using only HTTP; no access to server files is needed."""
import argparse
import getpass
import http.client
import ipaddress
import json
import ssl
from urllib.parse import urlsplit

MAX_BYTES = 16384
PATH = "/_fluxheim/operational-status"


def read_status(endpoint, token):
    url = urlsplit(endpoint)
    if (url.scheme not in ("http", "https") or not url.hostname or url.username is not None
            or url.password is not None or url.path not in ("", "/") or url.query or url.fragment):
        raise ValueError("provide only the admin origin, without credentials, query or path")
    if url.scheme == "http" and not ipaddress.ip_address(url.hostname).is_loopback:
        raise ValueError("plaintext status access requires a numeric loopback address")
    connection = (http.client.HTTPSConnection(url.hostname, url.port, timeout=5, context=ssl.create_default_context())
                  if url.scheme == "https" else http.client.HTTPConnection(url.hostname, url.port, timeout=5))
    try:
        connection.request("GET", PATH, headers={"Authorization": "Bearer " + token, "Connection": "close"})
        response = connection.getresponse()
        body = response.read(MAX_BYTES + 1)
        if response.status != 200:
            raise RuntimeError(f"status request failed: HTTP {response.status}")
        if len(body) > MAX_BYTES or response.getheader("Content-Type") != "application/json":
            raise ValueError("invalid status response")
        value = json.loads(body)
        if value.get("schema_version") != 1:
            raise ValueError("unsupported status schema")
        return value
    finally:
        connection.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("origin", help="HTTPS admin origin or a loopback SSH tunnel")
    args = parser.parse_args()
    print(json.dumps(read_status(args.origin, getpass.getpass("Operational observer token: ")), indent=2))
