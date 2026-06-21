# Fluxheim 1.6.27 Release Notes

Fluxheim 1.6.27 continues the Pingora-exit work by moving route-level static
web serving onto the native HTTP/1 route adapter.

## Highlights

- Native HTTP/1 route static-web adapter backed by the `fluxheim-web` crate.
- Native static file responses support ETags, conditional requests, byte
  ranges, `HEAD`, cache-control metadata, and directory listings.
- Route-level native request-header mutation overlays now apply before matched
  proxy routes are forwarded upstream.
- Multiple configured static upstreams now round-robin successful native HTTP/1
  proxy requests, with safe-method failover still available when an upstream
  fails.
- Static `proxy.upstream_weights` now drive native weighted round-robin without
  requiring the compatibility load-balancer runtime.
- Route-level response rewrite rules for `Location`, `Refresh`, and
  `Set-Cookie` now execute in the native route proxy through the shared
  `fluxheim-headers` rewrite helpers.
- The server crate now depends directly on `fluxheim-web` for pure web response
  planning instead of using the root compatibility adapter.
- Static-web, header policy, response rewrite, and weighted-upstream route
  tests run through real local native HTTP/1 listeners.

## Security Notes

- Native static-web path resolution rejects decoded dot segments, NUL bytes,
  backslashes, denied dotfiles, and symlink escapes.
- Static response body reads use rooted component-by-component `openat` with
  no-symlink opens for every directory component and the final file, closing the
  symlink-swap window between metadata checks and body reads.
- Native route static-web handling now rejects methods other than `GET` and
  `HEAD` with `405 Method Not Allowed`, even when the route method list matches
  all methods.
- Native redirect `Location` path validation now reuses the bounded multi-pass
  forward-path safety check, rejecting single- and double-encoded dot-segment
  or slash expansions from `{query}`, `{path}`, or `{uri}` templates.
- Buffered native static responses are capped at 64 MiB until the final native
  streaming body path is completed.
- Forwarded-client-IP shortcut ownership remains a compatibility-path blocker;
  only explicit request-header unset/set/append mutations are marked native
  ready in this release.
- Advanced load-balancer behavior such as health state, persistence, dynamic
  discovery, priority groups, backup/drain state, and hash-based selection
  remains on the compatibility path; this release moves static upstream
  round-robin and static weights native.

## Compatibility

The remaining rich proxy integrations, including cache lookup/fill/stale
handling, PHP-FPM routing, auth-request, traffic mirror, compression, and
advanced load-balancer policy selection, remain on the compatibility path until
their native parity tests land.
