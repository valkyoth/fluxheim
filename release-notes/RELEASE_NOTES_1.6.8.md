# Fluxheim 1.6.8 Release Notes

Fluxheim 1.6.8 continues the 1.6 Pingora-exit line by adding native HTTP/1.1
request-head foundations. The active HTTP runtime still uses the Pingora
compatibility adapter in this slice.

## Added

- Added a Fluxheim-owned HTTP/1.0/HTTP/1.1 request-head parser in
  `fluxheim-protocol`.
- Added strict parser bounds for total request-head bytes, header count,
  start-line length, and individual header-line length.
- Rejected obsolete folded header lines, invalid header names, invalid header
  control bytes, malformed request lines, and unsupported HTTP versions at the
  protocol boundary.
- Added downstream HTTP/1 policy defaults to `fluxheim-server` so the native
  server plan carries HTTP/1 parser limits before production traffic is moved
  off the Pingora adapter.
- Added an incremental HTTP/1 request-head buffer for future native socket read
  loops, with fragmented-head support and bounded storage when an incomplete
  head exceeds the configured cap.
- Added strict HTTP/1 request body-framing classification for `Content-Length`
  and `Transfer-Encoding`, including rejection of ambiguous
  `Content-Length`/`Transfer-Encoding` combinations.
- Added HTTP/1.1 required `Host` boundary validation for the native parser,
  rejecting missing, duplicate, empty, or whitespace-containing host fields.
- Added HTTP/1 connection persistence classification for the native parser,
  covering HTTP/1.0 close-by-default, HTTP/1.1 persistent-by-default, explicit
  `Connection: close`, and HTTP/1.0 `Connection: keep-alive`.
- Added a bounded complete-buffer HTTP/1 chunked body decoder that writes into
  caller-owned output and enforces chunk-size, total-body, output-buffer, and
  CRLF framing limits.
- Split the HTTP/1 chunked decoder into a focused `fluxheim-protocol` module so
  the native HTTP parser stays below the reviewability target while more HTTP
  runtime pieces are added.
- Added native HTTP/1 request-target classification for origin-form,
  absolute-form, CONNECT authority-form, and OPTIONS asterisk-form requests,
  including percent-encoding and forbidden-fragment/backslash checks.
- Added a bounded native HTTP/1 response-head parser for future upstream
  response handling, reusing the same strict header-count, line-length, UTF-8,
  and obsolete-folding checks as request-head parsing.
- Hardened the native HTTP/1 parser by rejecting deprecated authority userinfo,
  non-ASCII obs-text in strict header values and response reason phrases, all
  duplicate `Content-Length` fields, and unbounded chunked body defaults.
- Extended the temporary `pingora-runtime` and `pingora-rustls` dependency
  policy exceptions to `1.6.9` because `1.6.8` adds parser foundations but does
  not yet replace the active server/listener adapter.

## Tests

- Added `fluxheim-protocol` unit tests for complete HTTP/1.1 heads, incomplete
  heads, oversized heads, header-count limits, folded headers, invalid controls,
  invalid methods, and unsupported versions.
- Added `fluxheim-protocol` unit tests for fragmented request heads and
  oversized incomplete chunks that must not be stored unboundedly.
- Added `fluxheim-protocol` unit tests for no-body, fixed-length, chunked, and
  invalid/ambiguous request body framing decisions.
- Added `fluxheim-protocol` unit tests for valid, missing, duplicate, empty,
  and malformed `Host` fields.
- Added `fluxheim-protocol` unit tests for HTTP/1.0/HTTP/1.1 connection
  persistence decisions and invalid `Connection` tokens.
- Added `fluxheim-protocol` unit tests for chunked body decoding, incomplete
  chunks, output/body limits, chunk-size limits, and invalid chunk framing.
- Added `fluxheim-protocol` unit tests for HTTP/1 request-target classification
  and malformed target rejection.
- Added `fluxheim-protocol` unit tests for HTTP/1 response-head parsing,
  incomplete response heads, malformed status lines, and shared header bounds.
- Added `fluxheim-protocol` regression tests for authority userinfo rejection,
  obs-text rejection, duplicate `Content-Length` rejection, and bounded chunked
  body defaults.
- Added `fluxheim-server` unit coverage for downstream HTTP/1 bounded defaults.

## Verification

- `cargo test --locked -p fluxheim-protocol`
- `cargo test --locked -p fluxheim-server`
- `cargo fmt --all --check`
- `RUSTFLAGS='-D warnings' cargo check --locked -p fluxheim-protocol`
- `RUSTFLAGS='-D warnings' cargo check --locked -p fluxheim-server`
- `scripts/validate-modularity-policy.sh check`
