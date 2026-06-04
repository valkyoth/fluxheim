# Load Balancer Migration Notes

Fluxheim `1.5.x` focuses on HTTP/TCP edge load-balancer operations that map
cleanly from HAProxy, nginx, Envoy, and F5 LTM-style pools. The validated
starting fixture is `examples/load-balancer-enterprise.toml`.

This is a migration guide for pool behavior, not a claim that Fluxheim clones
every product module. UDP, GSLB/DNS steering, WAF policy, VPN/firewall
appliance behavior, and iRules/Lua/Wasm scripting are tracked as separate
roadmap lines.

For active-active managed-cookie and persistence-state boundaries, see
[Load Balancer HA Design Notes](load-balancer-ha.md).

## nginx Upstream

Typical nginx upstreams:

```nginx
upstream app {
    least_conn;
    server 10.0.0.10:8080 weight=4;
    server 10.0.0.11:8080 weight=4;
    server 10.0.1.10:8080 backup;
}
```

Fluxheim equivalent:

```toml
[proxy]
upstreams = ["10.0.0.10:8080", "10.0.0.11:8080", "10.0.1.10:8080"]
upstream_weights = [4, 4, 1]
backup_upstreams = ["10.0.1.10:8080"]

[proxy.load_balance]
selection = "least-connections"
```

Use `upstream_priority_groups` when nginx configs express preferred regions or
manual failover tiers rather than simple backup-only behavior.

## HAProxy Backend

Typical HAProxy backend:

```haproxy
backend app
  balance leastconn
  server app-a 10.0.0.10:8080 weight 4 check maxconn 500
  server app-b 10.0.0.11:8080 weight 4 check maxconn 500
  server app-dr 10.0.1.10:8080 backup check
```

Fluxheim equivalent:

```toml
[proxy]
upstreams = ["10.0.0.10:8080", "10.0.0.11:8080", "10.0.1.10:8080"]
upstream_aliases = ["app-a", "app-b", "app-dr"]
upstream_weights = [4, 4, 1]
upstream_max_in_flight = [500, 500, 100]
backup_upstreams = ["10.0.1.10:8080"]

[proxy.load_balance]
selection = "least-connections"
all_down_status = 503

[proxy.load_balance.health_check]
enabled = true
protocol = "tcp"
interval_secs = 2
consecutive_success = 2
consecutive_failure = 3
```

HAProxy stick-table patterns map only to Fluxheim's bounded local persistence
tables in the current `1.5.x` line. Multi-counter stick-table expressions
remain future advanced ACL/stick-table work.

## F5 LTM Pool

F5 pools often combine monitors, priority-group activation, node/member
administrative state, persistence, and manual drain/resume workflows.

Fluxheim maps those pieces as follows:

| F5 / BIG-IP concept | Fluxheim `1.5.x` mapping |
| --- | --- |
| Pool members | `proxy.upstreams` |
| Member names | `proxy.upstream_aliases` |
| Member metadata / labels | `proxy.upstream_tags` |
| Ratio / weight | `proxy.upstream_weights` |
| Maglev hash persistence | `proxy.load_balance.selection = "maglev"` for static pools |
| Bounded-load consistent hash | `proxy.load_balance.selection = "bounded-load-consistent-uri-hash"` plus optional `bounded_load_factor_per_mille` |
| Priority group activation | `proxy.upstream_priority_groups` plus `upstream_priority_group_min_active` |
| Member connection limit | `proxy.upstream_max_in_flight` |
| Monitors | `proxy.load_balance.health_check` |
| Passive outlier ejection | `proxy.load_balance.passive_health` |
| Slow ramp after recovery | `proxy.load_balance.slow_start` |
| Source-address persistence | `proxy.load_balance.persistence` with `mode = "source-ip"` |
| Manual drain/disable/force-down/resume | `POST /_fluxheim/load-balancer/member-state` |
| Runtime member weight shift | `POST /_fluxheim/load-balancer/member-weight` for round-robin and least-* selectors |
| Saturation queue | `proxy.load_balance.queue` |
| Pool all-down response | `proxy.load_balance.all_down_status` |

Example priority and locality policy:

```toml
[proxy]
upstreams = ["10.0.0.10:8080", "10.0.0.11:8080", "10.0.1.10:8080"]
upstream_aliases = ["app-a", "app-b", "app-dr"]
upstream_tags = [["blue", "primary"], ["blue", "primary"], ["dr"]]
upstream_priority_groups = [100, 100, 10]
upstream_priority_group_min_active = 1
upstream_localities = ["site-a", "site-a", "site-b"]
preferred_upstream_localities = ["site-a"]
```

Priority groups express preferred/fallback tiers. Locality preference expresses
same-zone or same-site preference with automatic fallback when no preferred
locality is selectable.

## Runtime Operations

Configured members can be moved in and out of selection without a config reload:

```bash
curl -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:8081/_fluxheim/load-balancer/member-state?vhost=app&member=app-a&state=drain"
```

Supported states are `normal`, `drain`, `disable`, `forced_down`, and
`manual_resume`. Runtime mutations are intentionally in-memory in the current
`1.5.x` line; they survive neither process restart nor runtime rebuild.

Configured member weights can be shifted at runtime for canary or traffic-ramp
workflows when the pool uses `round-robin`, `least-connections`,
`least-sessions`, or `least-time`:

```bash
curl -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:8081/_fluxheim/load-balancer/member-weight?vhost=app&member=app-a&weight=25"
```

Use `weight=default`, `reset`, `clear`, or `configured` to clear the override.
Hash, consistent-hash, bounded-load consistent, Maglev, and power-of-two
selectors reject runtime weights in the current release because their
ring/table or weighted-sampling semantics need a separate design.

The load-balancer-only status view is available without parsing the full admin
status body:

```bash
curl -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:8081/_fluxheim/load-balancer/status"
```

Persistence tables can be cleared without a reload:

```bash
curl -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:8081/_fluxheim/load-balancer/persistence/clear?vhost=app"
```

## Known Migration Boundaries

The following are intentional current `1.5.x` boundaries. They are not defects
in the shipped load-balancer behavior; they are architectural gaps tracked for
later `1.5.x` or future module lines.

- Runtime add/remove-member operations are future control-plane work.
- The remaining Pingora load-balancing substrate is planned to be replaced by a
  Fluxheim-native backend set and health/discovery loop in the `1.5.x` line.
  Pingora remains the HTTP proxy transport while the load-balancer core becomes
  Fluxheim-owned.
- Runtime weight changes are available for round-robin and least-* selectors.
  Hash/ring selectors need future table-rebuild semantics before runtime
  weights are accepted there.
- Load-balancer-managed cookie insertion is available through
  `mode = "managed-cookie"` in the `1.5.3` line. It is signed/opaque and local
  to one Fluxheim process, with daily local signing-key rotation and current or
  previous generation verification. Restart-persistent managed-cookie state,
  shared signing keys, and active-active cookie mirroring remain future HA work.
- HA persistence/cookie mirroring is future cluster-state work. Persistence
  tables, passive health, retry budgets, queue counters, and runtime overrides
  are local to one Fluxheim process in the current `1.5.x` line; active-active
  deployments must either accept independent local state or place another HA
  layer in front.
- In dynamic DNS/file discovery pools, stale runtime `drain` overrides may be
  reclaimed when a member leaves the live discovery set. Runtime `disable` and
  `forced_down` overrides are preserved across discovery churn until explicit
  admin resume/normal action.
- Maglev hashing is available for static `proxy.upstreams` pools. File-refreshed
  and DNS-refreshed pools reject Maglev in the current `1.5.x` line until
  dynamic table rebuild behavior is specified and observable.
- Bounded-load consistent hashing is local to one Fluxheim process. It avoids
  selecting an over-bound hash target when another eligible ring candidate is
  available, but it does not coordinate load across multiple Fluxheim nodes.
- Runtime state is local and in-memory in the current `1.5.x` line.
- UDP, GSLB/DNS steering, WAF, VPN/firewall appliance behavior, and scripted
  iRules/Lua/Wasm behavior are intentionally separate roadmap lines.
- `proxy.load_balance.queue` is opt-in. Defaults keep fail-fast behavior when
  no backend is selectable.
