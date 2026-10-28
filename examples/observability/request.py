"""Send known traffic from the disposable namespace, not a trusted public proxy."""
import http.client
import json
import ssl
import sys

host, trace, request_id, transport = sys.argv[1:]
context = ssl.create_default_context(cafile="/fixture/cert.pem")
context.minimum_version = ssl.TLSVersion.TLSv1_2
connection = (http.client.HTTPSConnection("localhost", 8443, context=context, timeout=6)
              if transport == "https" else http.client.HTTPConnection("127.0.0.1", 8088, timeout=6))
try:
    headers = {"Host": host,
                       "traceparent": f"00-{trace}-00f067aa0ba902b7-01", "x-request-id": request_id,
                       "Authorization": "Bearer collector-proof-secret-canary",
                       "Cookie": "secret=collector-proof-secret-canary"}
    path = ("/index.php" if host.startswith("php") else "/asset.png") + "?secret=collector-proof-secret-canary"
    if host == "cache.test":
        # Authenticated/cookie-bearing requests must bypass cache by design.
        del headers["Authorization"], headers["Cookie"]
        path = "/asset.png"
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    print(json.dumps({"status": response.status, "body": response.read(8192).decode(),
                      "cache": response.getheader("x-cache-status")}))
finally:
    connection.close()
