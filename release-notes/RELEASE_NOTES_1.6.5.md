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

## Validation

- Added direct `fluxheim-headers` unit coverage for header-prefix rewrites,
  refresh URL rewrites, cookie Domain/Path rewrites, forwarded-header parsing,
  trusted client-IP restoration, and `Forwarded` header construction.
- Preserved the existing root proxy header-policy tests across the new crate
  boundary.

