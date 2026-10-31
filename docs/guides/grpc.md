# gRPC Routes And Current Limits

gRPC uses HTTP/2 to carry RPC messages and trailing metadata. An HTTP 200 alone
does **not** mean an RPC succeeded: the final `grpc-status` usually arrives in
response trailers. Fluxheim has HTTP/2 transport primitives and an explicit
gRPC route filter, but the current routed proxy is **not production-qualified
for general gRPC pass-through**.

Two implementation gaps remain:

- **Current limitation:** the H2 client reads response trailers, then the
  proxy's H2-to-common-response conversion drops them. A real H2 origin's
  `grpc-status: 7` and `grpc-message` disappear downstream while HTTP 200 and
  the DATA body survive. Even ordinary unary RPCs can fail at the client.
- **Current limitation:** request and response bodies are collected before
  the next application stage. This is not bidirectional streaming; long-lived
  RPCs are constrained by buffering and phase deadlines. Streaming qualification
  is pending, and increasing a buffer does not implement streaming.

Do not use the example as evidence that these gaps have been fixed. Keep
production RPC traffic on an already-qualified path until the corrections and
real client/server tests pass.

## Configure The Existing Route Filter

The complete [local configuration](../../examples/proxy/grpc.toml) demonstrates
the fields without exposing a public service:

```toml
[[vhosts.routes]]
name = "rpc"
path_prefix = "/example.Greeter/"

[vhosts.routes.grpc]
enabled = true
require_content_type = true

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:9001"]
upstream_http_version = "http2"
upstream_h2_max_streams = 32
read_timeout_secs = 30
send_timeout_secs = 30

[vhosts.routes.cache]
enabled = false
```

The route path follows the service/method shape, for example
`/example.Greeter/Hello`. Do not casually rewrite it. These are the only gRPC
route fields:

| Field | Meaning |
| --- | --- |
| `enabled` | Default false; applies the gRPC method/content-type guard to a proxy route |
| `require_content_type` | Default true; must remain true when enabled |

Validation requires a proxy action with `http2` or `http1-and-http2`, and rejects
explicitly enabled route caching. Prefer explicit `http2` for known RPC origins;
mixed-mode fallback does not guarantee an HTTP/2 connection and has the pooling
limits described in [reverse proxy](reverse-proxy.md). Disable response caching
at all applicable scopes, not just on the route.

No separate `grpc` Cargo feature is needed for this route filter. Use a proxy
binary; add a supported TLS backend for HTTPS. There is no protobuf schema
registry, reflection server, JSON transcoding or gRPC-Web translation in this
setting.

## What The Filter Actually Checks

- Methods other than POST produce HTTP 405 with `Allow: POST` and diagnostic
  gRPC status/message headers.
- A missing, duplicate or unaccepted Content-Type produces HTTP 415. Accepted
  media types are case-insensitive `application/grpc` and the
  `application/grpc+` prefix, with optional parameters. This is not protobuf
  payload validation.
- The filter does not require that the original downstream request was H2;
  HTTP/1 POST can reach it too. Such a request is not evidence of real gRPC
  client compatibility. Its HTTP rejection responses are not a guarantee of
  canonical gRPC error trailers.

## HTTP/2 On Both Sides

The recipe's plain `server.listen` is useful for inspecting the route's method
and media-type rejection. It is **not a downstream h2c listener recipe**. For a
real HTTP/2 client, configure `server.tls_listen` and TLS ALPN using the
[TLS guide](tls.md); keep SNI, vhost host names and certificate identity aligned.

On the origin side, `upstream_http_version = "http2"` without TLS means cleartext
H2 prior knowledge. Use that only for a deliberately local/private origin that
supports it. For an encrypted origin add verified [upstream TLS](upstream-tls.md).
Avoid treating the h2c OPTIONS upgrade probe as a gRPC compatibility mechanism.

HTTP/2 headers, concurrent streams, body retention and deadlines remain bounded.
`read_timeout_secs` is a transport policy, not an implementation of the
application's `grpc-timeout` semantics. An incoming deadline header can be
forwarded to the origin; do not assume Fluxheim schedules a complete RPC deadline
from it. Compression and HTTP status handling are not substitutes for gRPC
message compression and final RPC status.

## How We Qualify Corrections

The [routed H2 characterization](../../crates/fluxheim-server/src/native_grpc_contract_tests.rs)
uses actual TCP/H2 on both sides and proves current trailer loss. Existing
low-level H2 trailer tests remain valuable, but cannot certify the full route.
Before claiming gRPC support, qualification must also include a real generated
client/server, success and nonzero RPC statuses, binary metadata, trailers-only
replies, cancellation, deadline expiry, slow peers and the supported streaming
shapes. [Load-balancer gRPC health checks](load-balancer.md) are a separate
monitor implementation and do not prove routed RPC fidelity.
