# Fluxheim 1.6.11 Release Notes

Fluxheim 1.6.11 continues the 1.6 Pingora-exit line by adding a native HTTP/2
runtime preview gate in `fluxheim-server`. This release does not cut production
traffic over to the native HTTP/2 path. Instead, it makes the remaining safety
hooks explicit and proves the first bounded HTTP/2 request handling path with
focused tests.

## Added

- Added a native HTTP/2 preview gate that records required safety hooks and
  keeps cutover blocked until every hook is implemented and covered by parity
  fixtures.
- Added a native HTTP/2 stack probe using the Rust `h2` stack with bounded
  header-list size, decoded header count, URI length, request body size,
  request body timeout, concurrent streams, frame size, send buffer size, and
  rapid-reset policy settings.
- Added downstream HTTP/1.0 socket tests for missing `Host`, default
  connection close, and explicit `Connection: keep-alive`.
- Added `scripts/smoke_native_http2_preview.sh` and registered it in
  `docs/runtime-parity-fixtures.tsv`.

## Hardened

- Native HTTP/2 cutover remains blocked on three explicit hooks:
  pre-routing HPACK/header-count allocation proof, absolute response-write
  lifetime, and trailer/gRPC pass-through parity.
- Native HTTP/2 request-body draining now releases flow-control capacity after
  consumed DATA frames and keeps the h2 connection driven while bodies drain.
- Native HTTP/2 now enforces `[server.limits].max_uri_bytes` against the request
  URI, matching the HTTP/1 request-target budget.
- Native HTTP/2 post-shutdown streams are logged at debug level instead of
  being silently discarded.

## Tests

- Added HTTP/2 preview tests for successful responses, decoded header-count
  rejection, oversized URI rejection, bounded request bodies, oversized request
  bodies, slow request-body timeout, and request-body flow-control release.
- Added real downstream HTTP/1.0 socket coverage for hostless requests,
  close-by-default behavior, and explicit keep-alive.

## Verification

- `cargo fmt --all --check`
- `cargo test --locked -p fluxheim-server native_http1`
- `cargo test --locked -p fluxheim-server native_http2`
- `cargo test --locked -p fluxheim-server downstream_http2`
- `scripts/smoke_native_http1_proxy.sh`
- `scripts/smoke_native_http2_preview.sh`
- `RUSTFLAGS='-D warnings' cargo check --locked -p fluxheim-server`
- `scripts/validate-runtime-fixtures.sh check`
- `cargo check --locked --workspace --all-targets`
