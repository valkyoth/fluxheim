"""Test-only TLS adapter: give Pebble's data: terms URL an HTTPS equivalent.

No ACME/JWS, authorization, challenge or certificate result is synthesized.
The retry fixture also refuses the first two requests to its separate directory.
"""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
import threading
import time

LIMIT = 2 * 1024 * 1024
TERMS = "https://localhost:14000/terms"
PEBBLE_TERMS = "data:text/plain,Do%20what%20thou%20wilt"
PAUSE_PHASES = ("account", "order", "authorization", "challenge", "ready", "finalize", "certificate")


def response_phase(path, mime, body):
    if mime == "application/pem-certificate-chain":
        return "certificate"
    if mime != "application/json":
        return None
    obj = json.loads(body)
    if "orders" in obj and "status" in obj:
        return "account"
    if path == "/order-plz":
        return "order"
    if "challenges" in obj and "identifier" in obj:
        return "authorization"
    if "token" in obj and "type" in obj:
        return "challenge"
    if "authorizations" in obj:
        if path == obj.get("finalize", "").removeprefix("https://localhost:14000"):
            return "finalize"
        if obj.get("status") == "ready":
            return "ready"
    return None


def directory_body(body):
    directory = json.loads(body)
    if directory["meta"]["termsOfService"] != PEBBLE_TERMS:
        raise ValueError("unexpected Pebble terms metadata")
    directory["meta"]["termsOfService"] = TERMS
    return json.dumps(directory).encode()


def main():
    context = ssl.create_default_context(cafile="/fixture/ca.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    failures_left = 2
    pause_phase = None
    fault_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def handle_request(self):
            nonlocal failures_left, pause_phase
            self.connection.settimeout(10)
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 <= size <= LIMIT or self.headers.get("Transfer-Encoding"):
                self.send_error(400)
                return
            path = self.path
            if self.command == "GET" and path.removeprefix("/pause-") in PAUSE_PHASES and path.startswith("/pause-"):
                with fault_lock:
                    pause_phase = path.removeprefix("/pause-")
                path = "/dir"
            if self.command == "GET" and path == "/retry-dir":
                with fault_lock:
                    print(f"retry directory {time.monotonic_ns()}", flush=True)
                    refuse = failures_left > 0
                    if refuse:
                        failures_left -= 1
                if refuse:
                    self.send_error(403, "Test issuer temporarily refusing renewal")
                    return
                path = "/dir"
            connection = http.client.HTTPSConnection("localhost", 14001, context=context, timeout=10)
            try:
                headers = {"Host": "localhost:14000", "User-Agent": "Fluxheim-ACME-smoke"}
                if self.command == "POST" and self.path == "/order-plz":
                    print("order request", flush=True)
                if self.headers.get("Content-Type"):
                    headers["Content-Type"] = self.headers["Content-Type"]
                request = self.rfile.read(size)
                connection.request(self.command, path, request, headers)
                response = connection.getresponse()
                body = response.read(LIMIT + 1)
                if len(body) > LIMIT:
                    raise ValueError("oversized local CA response")
                if self.command == "POST" and 200 <= response.status < 300:
                    phase = response_phase(path, response.headers.get_content_type(), body)
                    with fault_lock:
                        pause = phase is not None and phase == pause_phase
                        if pause:
                            pause_phase = None
                    if pause:
                        print("paused issuer response: " + phase, flush=True)
                        time.sleep(30)
                        return
                if path == "/dir" and response.status == 200:
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
