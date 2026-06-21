# Fluxheim 1.6.28 Release Notes

Fluxheim 1.6.28 continues the Pingora-exit work by moving two more rich proxy
features onto the native HTTP/1 route/proxy adapters.

## Highlights

- Route-level response compression now works in the native HTTP/1 route proxy
  through the `fluxheim-compression` crate.
- Native compression feature mapping now reaches `fluxheim-server` for gzip,
  zstd, and brotli builds.
- Native route compression preserves the existing eligibility checks: `GET`
  only, `200 OK`, compressible content type, bounded input/output size,
  `Accept-Encoding` negotiation, no active `Content-Encoding`, no `Range`
  response, no `Set-Cookie`, and no request `Authorization` or `Cookie`.
- Native route compression now ranks enabled codecs by the client's
  `Accept-Encoding` q-values before falling back to Fluxheim's tie-break order.
- `proxy.error_pages` now builds on the native HTTP/1 proxy for static 502/504
  fallback pages backed by `fluxheim-web`.
- Native custom proxy error pages preserve the proxy failure status while using
  the configured static error page body and headers.
- Live native HTTP/1 listener tests now prove gzip route compression and custom
  proxy error-page responses end to end.

## Security Notes

- Native compression removes origin `ETag` and `Content-Length` before sending
  the compressed body, appends `Vary: accept-encoding`, and lets the native
  response writer own the final compressed length.
- Compression is skipped rather than forced if the encoder exceeds configured
  output bounds or cannot initialize.
- Custom proxy error pages only serve files resolved by the native static-web
  resolver; directory listings, missing files, forbidden paths, and oversized
  bodies fall back to the standard 502/504 response.
- Custom proxy error-page responses now close the downstream connection after
  the upstream failure, matching the built-in 502/504 failure responses.
- Native error-page serving uses the same symlink-safe `fluxheim-web` path
  validation and rooted file-open behavior as native static routes.

## Compatibility

This release does not remove Pingora from normal builds yet. The remaining
compatibility-path blockers are inherited global/vhost compression, cache
lookup/fill/stale behavior, PHP-FPM routing, auth-request, traffic mirror,
forwarded-client-IP ownership shortcuts, dynamic discovery, health-aware
load-balancing, persistence, priority/backup/drain state, and hash-based
load-balancer selection.
