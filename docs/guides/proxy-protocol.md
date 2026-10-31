# PROXY Protocol

PROXY protocol is connection metadata sent before application bytes. A trusted
load balancer can use it to tell Fluxheim the original client's address. It is
not an HTTP header, a forward-proxy API, encryption or authentication. Both ends
of the connection must agree on its version before connecting.

There are two independent settings:

| Direction | Setting | Current HTTP implementation |
| --- | --- | --- |
| Load balancer to Fluxheim | `server.proxy_protocol = "v1"` or `"v2"` | Required preamble on plaintext HTTP listeners, direct peer must be trusted |
| Fluxheim to origin | `proxy.upstream_proxy_protocol = "v1"` or `"v2"` | Native HTTP/1 origin only; emitted before HTTP or outbound TLS |

Both default to `off`. Enabling one does not automatically enable the other.
Stream routes have independent `downstream_proxy_protocol`,
route-local `trusted_proxies` and `upstream_proxy_protocol` policies; see the
[TCP stream guide](tcp-streams.md). Do not infer their
TLS combinations from HTTP proxy support.

## Important HTTPS Limitation

**Current limitation:** Server-level
PROXY configuration is carried into the HTTPS listener plan but not consumed
by the native TLS dispatch. A real rustls listener accepts direct TLS from a
peer outside the configured PROXY trust list without a preamble. Conversely, a
load balancer sending a PROXY preamble before TLS is not handled by that path.

Do not rely on `server.proxy_protocol` or its trusted-peer check to restrict an
HTTPS listener today. Independently firewall backend access. Until corrected,
use an already-qualified edge arrangement, such as trusted TLS termination
followed by private HTTP with PROXY enabled. This limitation is not permission
to expose a backend directly or to trust arbitrary forwarded headers. OpenSSL
has the same dispatch omission by source inspection; its dedicated live
qualification remains required.

## Local End-To-End Recipe

The [complete recipe](../../examples/proxy/proxy-protocol.toml) sets both
directions to v1 for a test sender and origin that understand the format:

```toml
[server]
listen = ["127.0.0.1:8080"]
proxy_protocol = "v1"
trusted_proxies = ["127.0.0.1"]

# Inside the application vhost:
[vhosts.proxy]
upstreams = ["127.0.0.1:9001"]
upstream_http_version = "http1"
upstream_proxy_protocol = "v1"
```

An ordinary `curl http://127.0.0.1:8080/` is no longer sufficient: the listener
requires a preamble on every connection. Ordinary health checks need to send it
too. The [protocol smoke](../../scripts/smoke_protocol_examples.py) supplies a
bounded local sender and matching origin, verifies v1 and v2 receive/send and
checks that a non-trusted peer never reaches the origin.

For a real private edge, use its exact reachable backend IP or narrowly scoped
CIDR in `trusted_proxies`, and bind to a private address reachable only from
that edge. Do not copy `127.0.0.1` unless the actual direct peer is local. Do not
trust an entire container/cloud network merely because it is private. Any
trusted peer can assert another client's identity.

## Formats, Identity And Bounds

v1 is a text preamble; v2 is binary. Fluxheim does not automatically negotiate
or detect versions. The listener checks the socket peer against the trust list
before reading identity. A missing/wrong/malformed preamble closes the connection;
it is not silently treated as ordinary HTTP.

- v1 input is bounded to 108 bytes; TCP4/TCP6 source information and UNKNOWN
  are handled by the parser.
- v2 uses a 16-byte header and at most 4096 payload bytes. TCP4/TCP6 and
  LOCAL/UNSPEC are supported; bounded TLVs are skipped, not promoted to trusted
  application claims such as client-certificate identity.
- Reading the preamble is bounded by the request-head timeout. Partial clients
  do not get an unbounded wait.
- The PROXY source becomes effective client context while the direct socket
  peer remains available. The listener's actual local socket remains its local
  context; do not assume all original-destination/TLV information is relayed.
- `trusted_proxies` also governs forwarded-header trust. Keep origin-generated
  client-IP policy explicit and do not treat request IDs as identity.

## Outbound Origin Requirements

Enable `upstream_proxy_protocol` only when the origin listener is configured to
parse it. Sending a PROXY line to an ordinary HTTP/TLS server causes protocol
failure. Native H2 origin mode is rejected with PROXY enabled.

The outbound header uses effective client context and the gateway's local
address. When client identity came from a forwarded HTTP header without a known
port, source port 0 represents that unknown value. A usable same-family pair
produces TCP4/TCP6; otherwise v1 uses UNKNOWN and v2 uses UNSPEC. No arbitrary
input TLVs are forwarded.

Origin HTTP/1 idle pooling is disabled when PROXY is enabled: one connection's
client identity must not leak into another client's request. For HTTP-origin
TLS, the preamble is written on TCP before the TLS handshake, with normal
verification afterward. That support does not imply inbound HTTPS PROXY support.

## Troubleshooting

Check the direct peer address, configured version, required trust entry and
whether the origin expects a preamble. Connection resets before HTTP headers
usually need transport logs rather than an HTTP error-page diagnosis. Never
solve a trust rejection by allowing every address: broad catch-all ranges are
rejected by validation, and network access should be restricted independently.
