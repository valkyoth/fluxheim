"""Disposable origin: deliberately quiet even when requests contain canaries."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl
import threading


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"collector-proof-origin"
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Cache-Control", "public, max-age=120")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain("/fixture/cert.pem", "/fixture/key.pem")
https = ThreadingHTTPServer(("127.0.0.1", 8444), Origin)
https.socket = context.wrap_socket(https.socket, server_side=True)
threading.Thread(target=https.serve_forever, daemon=True).start()
ThreadingHTTPServer(("127.0.0.1", 8081), Origin).serve_forever()
