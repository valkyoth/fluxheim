# Fluxheim 1.6.12 Release Notes

Fluxheim 1.6.12 continues the Pingora-exit line by turning the native HTTP/2
preview into a reusable server primitive with stronger flow-control and trailer
coverage.

## Added

- Added native HTTP/2 request/response handler types in `fluxheim-server`.
- Added native HTTP/2 response trailer support, including gRPC-style trailer
  propagation tests.
- Added real h2 client/server tests for request trailers and response trailers.

## Hardened

- Refreshed non-Pingora dependency patches: `getrandom` 0.4.3, `openssl`
  0.10.81, `brotli` 8.0.4, and `h2` 0.4.15. Pingora remains pinned at 0.8.0
  while the 1.6 exit line removes it from normal builds.
- Added an absolute downstream HTTP/2 response-write lifetime budget.
- Sends response DATA through explicit h2 capacity reservation and polling,
  avoiding unbounded implicit response buffering.
- Keeps native HTTP/2 production cutover blocked until pre-routing
  HPACK/header-count allocation bounds are proven.

## Verification

- `cargo test --locked -p fluxheim-server native_http2`
- `cargo check --locked --workspace --all-targets`
- `scripts/check_latest_crates.sh`
