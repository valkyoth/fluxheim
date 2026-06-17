# Fluxheim 1.6.9 Release Notes

Fluxheim 1.6.9 continues the 1.6 Pingora-exit line by adding the first
Fluxheim-owned native HTTP/1.1 server runtime boundary. The active production
HTTP runtime still uses the Pingora compatibility adapter until routing,
proxying, cache, PHP-FPM, ACME, observability, and failure-semantics parity are
green on the native path.

## Added

- Added `fluxheim-server` native HTTP/1 connection handling over Tokio IO using
  the bounded HTTP/1 parser from `fluxheim-protocol`.
- Added a native HTTP/1 listener accept loop with explicit shutdown future and
  per-connection tasks.
- Added a small async handler boundary returning `NativeHttp1Response`, giving
  the later proxy/static/PHP adapter work a Fluxheim-owned runtime target.
- Added a staged native static-file adapter that reuses Fluxheim's existing
  safe web-root resolver, conditional-response planner, and body reader while
  writing through the native HTTP/1 response type. This is tested but not yet
  selected by the production listener path.
- Added fixed-length and chunked request-body reads with the existing
  Fluxheim-owned body-size and chunk-decoding limits.
- Mapped existing `[server.limits]` request-head, URI, header-count, and
  request-body limits into the native downstream HTTP/1 policy.

## Hardened

- HTTP/1.1 requests without a valid `Host` header receive a bounded
  `400 Bad Request` response on the native path.
- Request bodies exceeding the configured server body limit receive
  `413 Payload Too Large` before being handed to the handler.
- Handler-supplied response headers cannot override `Content-Length` or
  `Connection`; those framing headers are owned by the native runtime writer.
- Native responses can advertise an explicit `Content-Length` independent of
  body bytes, preserving HEAD and static conditional-response semantics.
- Native HTTP/1 request-head and request-body reads now have explicit policy
  deadlines so slowloris and slow-body clients cannot hold staged native tasks
  indefinitely.
- Native HTTP/1 listener accepts are bounded by a policy connection cap and
  drop over-budget connections before spawning per-connection work.
- A zero native HTTP/1 connection cap is treated as the default cap instead of
  silently dropping all accepted connections.
- Native HTTP/1 responses now own the `Date` header and ignore handler-supplied
  `Date` overrides, matching the runtime-owned framing model.
- Handler-supplied response headers are validated before writing so invalid
  names or control/obs-text bytes cannot produce response splitting.
- Native static 500 responses no longer include internal filesystem or OS error
  details in the HTTP body; details are kept in server logs.
- Native request-body reads preserve IO errors distinctly from HTTP parse
  failures for later admin/logging semantics.
- The native HTTP/1 head-buffer secondary guard now fails at the configured
  limit instead of allowing one extra read chunk of overshoot.
- The native HTTP/1 chunked-body secondary raw-buffer guard now uses the same
  fail-at-limit behavior as the head-buffer guard.
- Tight `[server.limits]` configurations now preserve the invariant that the
  derived HTTP/1 start-line limit never exceeds the total head limit.

## Tests

- Added real TCP socket tests for native HTTP/1 keep-alive, explicit close,
  fixed-length request bodies, chunked request bodies, listener shutdown,
  configured body-limit rejection, missing-host rejection, and response framing
  header ownership.
- Added native HTTP/1 tests for peer-address propagation, slow request-head
  timeout, slow request-body timeout, over-budget listener drops, runtime-owned
  `Date` headers, and tight head/start-line limit derivation.
- Added tests for zero connection-cap fallback and positive-cap over-budget
  shedding.
- Added real TCP socket tests for native static file serving, HEAD
  `Content-Length` preservation, and directory listings.
- Added server-plan tests proving `[server.limits]` feeds the native HTTP/1
  policy instead of hard-coded parser defaults.

## Verification

- `cargo test --locked -p fluxheim-server`
- `cargo fmt --all --check`
- `RUSTFLAGS='-D warnings' cargo check --locked -p fluxheim-server -p fluxheim-protocol`
- `cargo test --locked native_static --features profile-full --lib`
- `RUSTFLAGS='-D warnings' cargo check --locked --features profile-full --lib`
- `cargo check --locked --workspace --all-targets`
- `scripts/validate-modularity-policy.sh check`
