# Fluxheim 1.7.10 Release Notes

Fluxheim 1.7.10 is the stabilization and release-gate hardening release for
the 1.7 WebAssembly policy line. It turns the documented migration examples
into explicit operator-selectable and release-gated acceptance evidence while
keeping the typed policy ABI constrained.

## Added

- Expose focused `scripts/test_starter.py` entries for F5 iRules-style,
  nginx Lua/OpenResty-style, HAProxy Lua/SPOE-style, and VCL-like Wasm policy
  examples.
- Keep focused and aggregate Wasm policy checks on one implementation path,
  and validate that the deep release gate requires the complete Wasm smoke.
- Audit every guest-controlled symbolic ID decoder for total, panic-free
  behavior over arbitrary integer inputs.
- Make the in-process native host-callback contract explicit: finite symbolic
  operations only, with blocking I/O and third-party callback code requiring a
  future killable subprocess boundary.
- Add opt-in response-hardening profiles and typed modern browser policy fields
  without changing the default response behavior.
- Add validated request-aware CORS, local preflight handling, correct dynamic
  `Vary`, and live listener evidence that preflights do not reach the origin.
- Add bounded `Retry-After` guidance to generated capacity-limit responses.

## Compatibility Boundary

- Fluxheim provides bounded capability mappings, not source-syntax or runtime
  compatibility with iRules, Lua/OpenResty, SPOE, or VCL.
- New host capabilities that require blocking I/O or third-party native
  callback code remain out of process until a killable, bounded IPC runner is
  designed and proven.

## Fixed

- Strip the historical `Proxy-Connection` hop-by-hop header on native HTTP/1
  and HTTP/2 upstream paths through one shared header policy.
- Strip Envoy, original-forwarding, Azure, Fly, proxy-user, and forwarded client
  certificate identity headers before trusted replacements are generated.
- Treat the first `Set-Cookie` segment only as the cookie name/value pair, so
  cookies named `Domain` or `Path` are not mistaken for attributes.
- Preserve closing quotes and trailing syntax while rewriting quoted exact-
  origin `Refresh` URLs.
- Enforce CORS method allowlists on actual responses and serialize bounded
  Reporting-Endpoints dictionaries with strict keys and HTTPS collectors.

## Security

- Strip the distinct spoofable `Client-IP` identity header, including in
  privacy-mode request sanitization.
- Reject repeated, embedded, and unbalanced quotes plus bracketed IPv4 in
  trusted `X-Forwarded-For` chains instead of normalizing malformed hops.
- Make `Forwarded` construction fallible, use a typed HTTP/HTTPS protocol, and
  reject invalid host values before producing an upstream header.
- Add a compile-gated fuzz target for trusted forwarding parsing, `Forwarded`
  construction, hop-by-hop policy, `Refresh`, and `Set-Cookie` rewrites.
