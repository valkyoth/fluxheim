# Fluxheim 1.6.13 Release Notes

Fluxheim 1.6.13 continues the Pingora-exit line with the first native HTTP/1.1
upstream connection-pooling slice. The active production proxy still keeps
Pingora as the compatibility fallback for unsupported policy combinations, but
the Fluxheim-owned HTTP/1.1 upstream client can now reuse safe idle origin
connections under bounded pool controls.

## Added

- Added a bounded native HTTP/1.1 upstream idle-connection pool in
  `fluxheim-server`.
- Added native pool capacity wiring from `server.process.upstream_keepalive_pool_size`
  into native HTTP/1 proxy candidates.
- Added native pool idle-age enforcement from `proxy.upstream_idle_timeout_secs`.
- Added real socket tests proving safe connection reuse and idle expiry.
- Added a proxy-listener regression proving two separate downstream clients can
  reuse one safe pooled origin connection.

## Hardened

- Native HTTP/1.1 pooling only returns sockets for response shapes that are safe
  to reuse today: no-body responses and content-length responses with no extra
  buffered bytes.
- Native HTTP/1.1 pooling now applies HTTP/1.0 close-by-default semantics before
  returning origin sockets to the idle pool.
- Native HTTP/1.1 pooling no longer reuses `1xx` origin responses, including
  `101 Switching Protocols`, because the connection state is ambiguous.
- Native HTTP/1.1 pooling retries once on a fresh origin connection when a
  checked-out idle socket fails with a dead-connection I/O error.
- Reduced `server.process.upstream_keepalive_pool_size` maximum to 16384 to
  bound per-native-upstream idle file-descriptor exposure.
- Native HTTP/1.1 pooling does not reuse close-delimited responses, chunked
  responses, or responses with `Connection: close`.
- Unsupported upstream TLS/mTLS, HTTP/2 upstreams, dynamic discovery,
  load-balancing, upstream PROXY protocol, websocket upgrade, and broader
  policy layers remain fail-closed for the native proxy eligibility gate.

## Verification

- `cargo test --locked -p fluxheim-server native_http1`
- `cargo clippy --locked -p fluxheim-server --all-targets -- -D warnings`
- `cargo check --locked --workspace --all-targets`
- `scripts/smoke_native_http1_proxy.sh`
