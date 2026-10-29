"""Test-only TLS adapter: give Pebble's data: terms URL an HTTPS equivalent.

No ACME/JWS, authorization, challenge or certificate result is synthesized.
Only the directory's terms metadata changes; both TLS hops verify/use the local CA.
"""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl

LIMIT = 2 * 1024 * 1024
TERMS = "https://localhost:14000/terms"
PEBBLE_TERMS = "data:text/plain,Do%20what%20thou%20wilt"


def directory_body(body):
    directory = json.loads(body)
    if directory["meta"]["termsOfService"] != PEBBLE_TERMS:
        raise ValueError("unexpected Pebble terms metadata")
    directory["meta"]["termsOfService"] = TERMS
    return json.dumps(directory).encode()


def main():
    context = ssl.create_default_context(cafile="/fixture/ca.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def handle_request(self):
            self.connection.settimeout(10)
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 <= size <= LIMIT or self.headers.get("Transfer-Encoding"):
                self.send_error(400)
                return
            connection = http.client.HTTPSConnection("localhost", 14001, context=context, timeout=10)
            try:
                headers = {"Host": "localhost:14000", "User-Agent": "Fluxheim-ACME-smoke"}
                if self.headers.get("Content-Type"):
                    headers["Content-Type"] = self.headers["Content-Type"]
                connection.request(self.command, self.path, self.rfile.read(size), headers)
                response = connection.getresponse()
                body = response.read(LIMIT + 1)
                if len(body) > LIMIT:
                    raise ValueError("oversized local CA response")
                if self.path == "/dir" and response.status == 200:
                    body = directory_body(body)
                self.send_response(response.status)
                for name in ("Replay-Nonce", "Location", "Content-Type", "Retry-After"):
                    if response.getheader(name):
                        self.send_header(name, response.getheader(name))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            finally:
                connection.close()

        do_GET = handle_request
        do_HEAD = handle_request
        do_POST = handle_request

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain("/fixture/server.pem", "/fixture/server.key")
    server = ThreadingHTTPServer(("0.0.0.0", 14000), Handler)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
