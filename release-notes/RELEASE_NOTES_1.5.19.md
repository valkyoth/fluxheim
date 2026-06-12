# Fluxheim 1.5.19 Release Notes

Fluxheim 1.5.19 moves the Fluxheim-owned load-balancer core into the internal
`fluxheim-load-balancer` workspace crate and includes security hardening found
during the v1.5.19 review cycle.

## Security Fixes

- Fixed fallback proxy cache auth ordering so cache fallback handling cannot
  run before the configured authorization decision.
- Applied decoded route matching to edge policy checks, closing mismatches
  between encoded request paths and policy enforcement.
- Preserved private cache-control directives for status-specific TTL handling
  so restrictive origin cache headers are not weakened by cache policy.
- Hardened PHP-FPM path handling by denying scripts after resolved-path
  normalization and covering directory-index resolution under denied PHP path
  prefixes.
- Fixed proxy-only route decode feature wiring so shared path safety remains
  available in proxy builds without cache.
- Isolated upstream CA bundle material in peer reuse keys to avoid reusing
  upstream TLS peers across distinct trust material.
- Added a default stream proxy connection cap to avoid unbounded accepted TCP
  stream connections.
- Detached self-healing probes from public proxy traffic paths.
- Preserved restrictive PHP cache headers when PHP-FPM responses are converted
  into Fluxheim responses.
- Rejected PHP-FPM `PHP_VALUE` and `PHP_ADMIN_VALUE` style ini-control
  parameters so configured PHP params cannot rewrite php-fpm runtime policy.
- Cleaned pending PHP request-body spool files on retry/error paths.
- Added `php.max_in_flight`, defaulting to `8`, to cap concurrent PHP-FPM
  requests before request body buffering and FastCGI dispatch.
- Added `proxy.load_balance.passive_health.min_healthy_backends`, defaulting to
  `1`, so passive outlier ejection cannot fail-closed an entire load-balanced
  pool by default. Operators can set it to `0` to retain strict fail-closed
  passive-health behavior.
- Hardened managed-cookie load-balancer persistence so missing or invalid
  affinity cookies no longer create server-side persistence-table entries or
  trigger least-session table scans until the signed cookie is returned by the
  client.
- Rejected verified HTTP proxy upstream TLS configs that target an IP-addressed
  upstream without explicit `upstream_sni`, preventing the Pingora connector
  from falling into empty-SNI certificate-verification bypass behavior.
- Hardened HTTP load-balancer discovery so private, loopback, link-local,
  metadata, multicast, reserved, and documentation IP-literal backends are
  rejected by default unless the operator explicitly enables
  `proxy.upstreams_http_allow_private_backends`.
- Added `proxy.downstream_read_timeout_secs`, defaulting to 60 seconds, and
  wired it into vendored Pingora HTTP/2 downstream request-body reads so
  slow-body clients cannot hold proxy forwarding tasks indefinitely while
  withholding DATA frames or END_STREAM.
- Applied the downstream read timeout before PHP-FPM request-body collection and
  drain paths, covering PHP routes that read the body before FastCGI execution
  begins.
- Hardened downstream HTTP/2 flow-control defaults by capping per-stream send
  buffering at 256 KiB, keeping DATA frames at 16 KiB, fixing the receive
  window at 64 KiB, and reducing pending-accept reset-stream pressure.
- Removed encrypted filesystem disk-cache fill heap amplification for the local
  provider by committing streamed cache bodies through bounded AEAD chunks, and
  bounded the OpenBao Transit whole-object fallback heap budget.
- Hardened DNS-refreshed upstream discovery against DNS rebinding pivots by
  rejecting private, loopback, link-local, multicast, reserved, documentation,
  metadata, and unspecified resolved addresses unless
  `proxy.upstream_dns_allow_private_backends = true` is set.
- Hardened split-config trusted-proxy handling by extending
  `server.trusted_proxies` fragments instead of replacing the main list, and by
  rejecting catch-all or near-global trusted-proxy ranges such as `0.0.0.0/0`
  and `::/0`.
- Hardened split-config proxy handling by applying field-level `[proxy]`
  fragment merges so a later timeout-only proxy fragment cannot silently clear
  upstream TLS verification, auth request, mirror, or load-balancer policy.
- Hardened split-config handling for `[compression]`, `[cache]`,
  `[cache_purger]`, `[web]`, and `[stream]` so partial fragments cannot
  silently drop previously configured compression limits, cache encryption,
  static-file safety policy, or stream routes.
- Hardened split-config admin handling by applying field-level `[admin]`
  fragment merges so a later ops-socket or health-only admin fragment cannot
  silently disable the admin API or clear token and snapshot-store settings.
- Hardened cache peer-fill request construction so client-controlled `Host`
  headers and absolute-form URI authorities are not forwarded as the peer
  request `Host`.

## What Changed

- Added `crates/fluxheim-load-balancer` as the internal owner of load-balancer
  backend snapshots, discovery adapters, active health checks, selection
  algorithms, runtime policy overrides, persistence, queue policy, state files,
  background task glue, and tests.
- Kept root `crate::load_balancer` as a compatibility shim so admin, proxy,
  runtime, status endpoints, release profiles, RPM/container packaging, and
  operator config syntax remain unchanged.
- Preserved the existing `profile-load-balancer-edge` image/profile and the
  full build's load-balancer support.
- Added narrow integration hooks for root-owned metrics recording and
  compliance HMAC signing, avoiding a dependency from the load-balancer crate
  back into proxy, admin, cache, web, or PHP internals.
- Kept the load-balancer crate's tests with the code they review, including
  selection, passive health, discovery, runtime mutation, persistence, and
  database/protocol health-check coverage.

## Compatibility

- Existing config files remain valid.
- Existing admin load-balancer status and mutation APIs remain unchanged.
- Existing feature profiles and release artifact names are unchanged.
- Existing RPM and container production feature sets are unchanged.
- `fluxheim-load-balancer` is an internal workspace crate and is not published
  to crates.io.

## Not Included

- No new load-balancer features in this release.
- No removal of `pingora-load-balancing` yet.
- No removal of `pingora-cache` yet.
- No cache, web, PHP, or HTTP proxy orchestrator crate extraction in this
  release.
- No production UDP/GSLB promotion, HTTP/3/QUIC, WAF, VPN/firewall appliance
  behavior, Wasm/iRules/Lua runtime, or full Pingora HTTP proxy replacement in
  this release.

## Packaging Notes

- Release assets continue to publish the same `full`, `cache`, `proxy`,
  `load-balancer`, `php`, and `config-tester` artifacts.
- The load-balancer image remains the focused package for HTTP/TCP
  load-balancer deployments.
