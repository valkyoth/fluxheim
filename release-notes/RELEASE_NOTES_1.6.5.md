# Fluxheim 1.6.5

Fluxheim 1.6.5 continues the Pingora-exit line with the first dedicated
header-policy crate boundary. Runtime behavior is intended to remain unchanged:
the root proxy module still applies Pingora request/response headers, while
pure header rewrite and forwarded-client-IP helpers now live in
`fluxheim-headers`.

## Changed

- Added the internal `fluxheim-headers` crate for header-policy helpers that do
  not need Pingora session or header types.
- Moved response `Location`, `Refresh`, and `Set-Cookie` rewrite algorithms
  into `fluxheim-headers`.
- Moved spoofable client-IP header constants, default server header policy,
  trusted `X-Forwarded-For` client-IP restoration, and `Forwarded` header value
  construction into `fluxheim-headers`.
- Kept the root `headers` module as the Pingora request/response adapter for
  now, so proxy runtime behavior and public configuration stay unchanged.
- Moved stream downstream PROXY protocol v1/v2 byte parsers and size constants
  into `fluxheim-protocol`. The stream crate now keeps only trusted-peer
  checks, timed reads, and runtime error conversion around those pure parsers.
- Added a release-gated Pingora HTTP/error boundary policy that blocks new
  direct `pingora::http`, `pingora::Error`, and `pingora::ErrorType` usage
  outside documented adapter files.

## Validation

- Added direct `fluxheim-headers` unit coverage for header-prefix rewrites,
  refresh URL rewrites, cookie Domain/Path rewrites, forwarded-header parsing,
  trusted client-IP restoration, and `Forwarded` header construction.
- Added direct `fluxheim-protocol` unit coverage for downstream PROXY protocol
  v1/v2 parsing while preserving the existing stream crate parser tests through
  the new boundary.
- Preserved the existing root proxy header-policy tests across the new crate
  boundary.
- Added `scripts/validate-pingora-boundary-policy.sh` and
  `docs/pingora-http-error-boundary-exceptions.tsv` to keep the remaining
  Pingora HTTP/error bridge surface explicit during the `1.6.x` removal line.
