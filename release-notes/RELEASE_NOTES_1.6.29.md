# Fluxheim 1.6.29 Release Notes

Fluxheim 1.6.29 continues the Pingora-exit work by moving inherited
compression and header-policy behavior into the native HTTP/1 proxy path.

## Highlights

- Native HTTP/1 plain proxy responses can now use inherited global/vhost
  compression policy when gzip, brotli, or zstd support is compiled.
- Native HTTP/1 route proxy responses now inherit global/vhost compression
  when a route does not override compression locally.
- Native route proxy construction now merges root/vhost header policy with the
  route overlay before building native request and response header policies.
- Root and vhost header mutation policy no longer blocks native HTTP/1 proxy
  cutover when it only uses supported header set/remove/append behavior.
- Root and vhost compression no longer blocks native HTTP/1 proxy cutover when
  a matching compression backend feature is compiled.
- Live native listener tests now prove plain-proxy gzip compression, inherited
  route gzip compression, inherited request-header mutation, inherited
  response-header mutation, and standard response security headers.

## Security Notes

- Inherited native compression keeps the same guarded behavior as route-level
  compression: bounded input/output size, negotiated `Accept-Encoding`, safe
  method/status checks, and privacy-sensitive header exclusions.
- Native compression strips origin `ETag` and `Content-Length`, appends
  `Vary: accept-encoding`, and lets native response framing compute the final
  compressed length.
- Native route request headers are removed or overwritten before the upstream
  request is sent, matching the compatibility-path policy order for the
  supported mutation subset.
- Native route responses now apply inherited standard security headers such as
  `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, CSP, and HSTS
  where configured.

## Compatibility

This release does not remove Pingora from normal builds yet. The remaining
compatibility blockers are forwarded-client-IP ownership overrides,
auth-request subrequests, traffic mirroring, access/rate/concurrency policy,
vhost redirects, ACME-challenge routing, route rewrite templates, per-proxy
downstream timeout/min-send-rate policy, advanced upstream transport knobs,
cache lookup/fill/stale behavior, PHP-FPM routing, dynamic discovery,
health-aware load balancing, persistence, priority/backup/drain state, and
hash-based load-balancer selection.
