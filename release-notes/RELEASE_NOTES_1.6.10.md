# Fluxheim 1.6.10 Release Notes

Fluxheim 1.6.10 continues the 1.6 Pingora-exit line by adding the first
Fluxheim-owned native HTTP/1 upstream/proxy foundation. The active production
HTTP runtime still uses the Pingora compatibility adapter until route policy,
cache, PHP-FPM, ACME, observability, and failure-semantics parity are green on
the native path.

## Added

- Added a bounded native HTTP/1 upstream client for plain static upstreams.
- Added upstream request serialization, response-head parsing, fixed-length
  response bodies, chunked response bodies, and close-delimited response bodies
  to the native HTTP/1 migration path.
- Added native proxy candidate inventory in `fluxheim-server` so eligible
  vhost and route proxy configurations can be discovered before cutover.
- Added a staged native proxy handler for plain static upstreams.
- Added Fluxheim-owned native proxy `Via` and `X-Forwarded-For` header
  injection parity with the compatibility proxy path.
- Added a `fluxheim-server` `privacy-mode` feature and wired the root
  `privacy-mode` feature into it.

## Hardened

- Native upstream forwarding strips inbound hop-by-hop framing headers, prior
  `Via`, and prior `X-Forwarded-For` before writing Fluxheim-owned proxy
  headers.
- Privacy-mode builds suppress native `X-Forwarded-For` injection.
- Native close-delimited upstream responses now accept exact-limit bodies and
  reject oversized bodies immediately after the configured limit is exceeded.
- Native proxy eligibility fails closed for unsupported policy layers,
  dynamic discovery, load balancing, upstream TLS, upstream PROXY protocol,
  HTTP/2 upstreams, and websocket upgrade.
- Connection pooling remains deferred performance parity for the upstream
  connector/pooling work planned in `v1.6.13`; `1.6.10` focuses on correctness
  and bounded native HTTP/1 proxy foundations.

## Tests

- Added native upstream tests for content-length responses, chunked responses,
  close-delimited responses, exact-limit close-delimited bodies, oversized
  close-delimited bodies, timeout handling, invalid forwarded request headers,
  and Fluxheim-owned proxy headers.
- Added a privacy-mode regression test proving native upstream forwarding does
  not emit `X-Forwarded-For`.
- Extended `scripts/smoke_native_http1_proxy.sh` to explicitly run the real
  TCP downstream listener to native proxy to upstream socket test.

## Verification

- `cargo fmt --all --check`
- `scripts/smoke_native_http1_proxy.sh`
- `scripts/validate-modularity-policy.sh check`
- `RUSTFLAGS='-D warnings' cargo check --locked -p fluxheim-server -p fluxheim-protocol`
- `RUSTFLAGS='-D warnings' cargo check --locked --features profile-full --lib`
- `cargo test --locked -p fluxheim-server --features privacy-mode privacy_mode_native_upstream_does_not_add_forwarded_for`
- `cargo check --locked --workspace --all-targets`
