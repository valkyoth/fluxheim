# Fluxheim 1.5.0 Release Notes

Fluxheim 1.5.0 is the enterprise HTTP/TCP load-balancer control-plane release.
It promotes the focused load-balancer image profile and documents the migration
surface for F5 LTM, HAProxy, nginx, and Envoy-style pool operations.

## Added

- Focused load-balancer release profile and container image line:
  `profile-load-balancer-edge` and `v1.5.0-load-balancer-*`.
- Load-balancer runtime member controls for drain, disable, force-down, normal,
  and manual-resume state.
- Load-balancer-only admin status endpoint and persistence-clear endpoint.
- Advanced selection coverage for weighted round-robin, least connections,
  weighted/ratio least connections, least sessions, least-time EWMA,
  power-of-two, hash, consistent hash, bounded-load consistent hash, static-pool
  Maglev, priority groups, locality preference, backups, and per-member caps.
- Local persistence modes for source IP, request header, and application or
  upstream-issued request cookie.
- Passive health, ejection/circuit status, slow start, retry budgets, bounded
  queueing, all-down status policy, and load-balancer audit visibility.
- Validated enterprise migration fixture:
  `examples/load-balancer-enterprise.toml`.
- Load-balancer module split into focused `src/load_balancer/*` files for
  health checks, backend state, persistence, selection, policy/status,
  discovery, and orchestration.

## Hardened

- Bounded backend runtime state maps for high-churn DNS/file discovery pools.
- Pruned passive-health state for stale backend keys while preserving active
  ejections.
- Feature-profile tests now distinguish load-balancer, default, and
  privacy-mode validation paths.
- Documentation now states the 1.5.0 load-balancer boundaries explicitly for
  operators and migration reviewers.

## Boundaries

The following are intentional 1.5.0 boundaries, not hidden shipped behavior:

- Fluxheim does not yet insert or sign managed affinity cookies.
- Load-balancer persistence and runtime overrides are in-memory and local to one
  process.
- Runtime weight changes and runtime add/remove-member are future work.
- Active-active cross-instance load-balancer state sync is future work.
- UDP, GSLB/DNS load balancing, WAF, VPN/firewall appliance behavior, and
  iRules/Lua/Wasm scripting are separate future roadmap tracks.

## Upgrade Notes

- Existing 1.4.x proxy, cache, PHP, stream, GeoIP, and compression
  configuration remains compatible.
- Use `docs/load-balancer-migration.md` and
  `examples/load-balancer-enterprise.toml` as the starting point for
  load-balancer migrations.
- The full profile includes the load-balancer module; the focused
  load-balancer image omits cache, static web serving, PHP-FPM, GeoIP, stream
  proxying, and traffic mirroring unless a custom build enables them.
