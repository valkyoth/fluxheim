# Fluxheim 1.5.20 Release Notes

Fluxheim 1.5.20 starts the web, PHP-FPM, and cache boundary-preparation line
and carries forward the post-1.5.19 trusted-proxy validation fix.

## Changed

- Started the `fluxheim-cache` crate boundary by moving shared cache-header
  request/response directive parsing into `crates/fluxheim-cache`. The root
  crate keeps `crate::cache_headers` as a compatibility re-export, so runtime
  behavior and call sites are unchanged.

## Fixed

- Allowed real provider IPv6 trusted-proxy ranges such as Cloudflare's
  `2a06:98c0::/29`. The `1.5.19` config-crate split preserved runtime IPv6
  CIDR support but made config validation too strict by rejecting trusted proxy
  IPv6 prefixes broader than `/32`.
