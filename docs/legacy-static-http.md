# Legacy Static HTTP Support

Legacy HTTP support is a future experimental compatibility feature for isolated
devices that cannot speak modern HTTP. It must never be part of Fluxheim's
default binary and must never run on normal proxy, cache, admin, PHP, CGI, or
TLS listener paths.

The modern protocol focus for Fluxheim remains strict HTTP/1.1 and HTTP/2
today, with HTTP/3/QUIC planned as the future performance and security
direction. Legacy protocol support is a quarantined compatibility exception.

## Compile-Time Features

Planned feature flags:

```toml
legacy-http-static = []
legacy-http10-static = ["legacy-http-static"]
legacy-http09-static = ["legacy-http-static"]
```

The default feature set must never include these features. Release checks should
fail if `cargo tree -e features` shows any legacy HTTP feature enabled by
default.

## Runtime Isolation

Legacy support requires explicit runtime config and dedicated listeners:

```toml
[legacy_http]
enabled = true

[[legacy_http.listeners]]
protocol = "http1.0"
listen = "127.0.0.1:18080"
vhost = "legacy-static"

[[legacy_http.listeners]]
protocol = "http0.9"
listen = "127.0.0.1:18090"
vhost = "museum-device"
```

Legacy listeners must not share `server.listen`, `server.tls_listen`,
`admin.listen`, or `metrics.listen`. Listener changes are process-upgrade
changes.

## HTTP/1.0 Static Mode

HTTP/1.0 support is allowed only for static file serving.

Required behavior:

- Dedicated legacy listener only.
- Explicit legacy vhost only.
- Static `GET` and `HEAD` only by default.
- No reverse proxying.
- No cache admission or cache lookup.
- No admin endpoints.
- No PHP or CGI execution.
- No compression/body filters.
- No protocol upgrade.
- No persistent connections.
- Always force `Connection: close`.
- Reject `Transfer-Encoding`.
- Reject multiple or invalid `Content-Length`.
- Reject request bodies unless a later static-only use case is explicitly
  justified.
- If `Host` is absent, route only to the configured legacy vhost.
- If `Host` is present, still restrict the request to the configured legacy
  vhost and static root.

The motivation is compatibility with old internal health checks, PLCs, and
legacy enterprise equipment, not public internet service.

## HTTP/0.9 Static Mode

HTTP/0.9 is too old and ambiguous for Pingora's normal HTTP pipeline. It should
be implemented, if ever, as a separate raw TCP service.

Required behavior:

- Dedicated raw TCP listener only.
- One request per connection.
- Accept only `GET /path` followed by line ending.
- Static files only.
- No headers.
- No request body.
- No TLS.
- No vhost by `Host` header.
- No reverse proxying.
- No cache.
- No admin endpoints.
- No PHP or CGI.
- No directory listing.
- No redirects that rely on HTTP status codes.
- Close the connection after the response body.

Most unexpected input that resembles HTTP/0.9 should be treated as hostile and
rejected.

## Security Tests

Before implementation is considered usable:

- HTTP/1.0 `Transfer-Encoding: chunked` must be rejected.
- Multiple `Content-Length` values must be rejected.
- Invalid `Content-Length` must be rejected.
- `Upgrade` headers must be rejected.
- Keep-alive attempts must still close the connection.
- HTTP/1.0 requests must never reach proxy/cache/admin/PHP/CGI paths.
- HTTP/0.9 malformed request lines must be rejected.
- HTTP/0.9 traversal attempts must be rejected.
- HTTP/0.9 absolute URLs and scheme-prefixed paths must be rejected.
- Both modes must reuse the existing static resolver's canonical path checks.
- Metrics and access logs must label legacy protocol traffic clearly.

## Relationship To Pingora Smuggling Advisories

Pingora versions before `0.8.0` had HTTP request-smuggling vulnerabilities
around HTTP/1.0 transfer-encoding parsing and premature upgrade handling.
Fluxheim already tracks Pingora `0.8.0`, but legacy support must still add its
own stricter rejection layer because compatibility modes are especially exposed
to ambiguous parsing attacks.

Legacy support must not weaken the normal modern listener behavior.
