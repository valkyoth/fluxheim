# Load Balancer Migration Notes

Fluxheim `1.5.x` focuses on HTTP/TCP edge load-balancer operations that map
cleanly from HAProxy, nginx, Envoy, and F5 LTM-style pools. The validated
starting fixture is `examples/load-balancer-enterprise.toml`.
For pull-based control-plane upstream lists, use
`examples/load-balancer-http-discovery.toml`.
For local command-based monitors, use
`examples/load-balancer-exec-health.toml`.
Exec monitor command paths and arguments are normal configuration data, so do
not put credentials in argv; let the local helper read protected local secrets
it owns. Runtime status and health-check backend summaries expose only the
protocol, not the exec command path or arguments.

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
tables in the current load-balancer implementation. Multi-counter stick-table
expressions remain future advanced ACL/stick-table work.

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
| Runtime static-pool member add/remove/update | `POST /_fluxheim/load-balancer/member-add`, `member-remove`, `member-update` |
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
`manual_resume`. Runtime mutations are intentionally local to one Fluxheim
process; they survive process restart only when
`proxy.load_balance.runtime_state_file` is configured, and they do not sync
across active-active nodes.

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

Static upstream pools can add, remove, or update members at runtime:

```bash
curl -X POST \
  -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:8081/_fluxheim/load-balancer/member-add?vhost=app&member=10.0.0.12:8080&weight=2"
```

Use `member-update` with `weight` to change the configured runtime weight, or
with `address`/`new_member` to retarget a non-aliased member. Aliased members
can be weight-updated but need a config reload for address changes because the
alias is part of the static backend identity. Use `member-remove` after the
member has drained to zero in-flight requests. These backend-set mutations are
local in-memory changes in the current release. Runtime backend sets are capped
at 256 members, and the zero in-flight check is a best-effort mutation-time
gate; Fluxheim warns if a narrow race leaves a request completing against a
removed or retargeted address. Runtime-added or retargeted members carry
address and configured weight only; aliases, tags, backup membership, priority
groups, locality metadata, and per-upstream caps remain static-config fields.
DNS/file-discovery pools and Maglev selectors reject runtime backend-set
mutation.

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

The following are intentional current load-balancer boundaries. They are not
defects in the shipped load-balancer behavior; they are architectural gaps
tracked for future module lines.

- Runtime add/remove/update-member operations are available for static upstream
  pools only. DNS/file/HTTP-discovery pools reject them because discovery
  refresh owns the live member set.
- The load-balancer core is Fluxheim-owned, including backend-set snapshots,
  runtime mutation, health/discovery loops, and selection policy. Pingora still
  remains the HTTP proxy transport boundary until the `1.6.x` native HTTP
  runtime cutover completes.
- Runtime weight changes are available for round-robin and least-* selectors.
  Hash/ring selectors need future table-rebuild semantics before runtime
  weights are accepted there.
- Load-balancer-managed cookie insertion is available through
  `mode = "managed-cookie"` in the `1.5.3` line. It is signed/opaque and local
  to one Fluxheim process, with daily local signing-key rotation and current or
  previous generation verification. Restart-persistent managed-cookie state,
  shared signing keys, and active-active cookie mirroring remain future HA work.
- HA persistence/cookie mirroring is future cluster-state work. Persistence
  tables and runtime member/weight overrides can be restart-persisted locally
  with `proxy.load_balance.runtime_state_file`, but passive health, retry
  budgets, queue counters, and managed-cookie signing keys remain local to one
  Fluxheim process in the current load-balancer implementation. Active-active
  deployments must either accept independent local state or place another HA
  layer in front until cross-node synchronization lands.
- In dynamic DNS/file/HTTP-discovery pools, stale runtime `drain` overrides may
  be reclaimed when a member leaves the live discovery set. Runtime `disable`
  and `forced_down` overrides are preserved across discovery churn until
  explicit admin resume/normal action.
- Maglev hashing is available for static `proxy.upstreams` pools. File-refreshed
  DNS-refreshed, and HTTP-discovered pools reject Maglev until dynamic table
  rebuild behavior is specified and observable.
- Bounded-load consistent hashing is local to one Fluxheim process. It avoids
  selecting an over-bound hash target when another eligible ring candidate is
  available, but it does not coordinate load across multiple Fluxheim nodes.
- Runtime state is local to one Fluxheim process. Runtime member-state
  overrides, runtime weight overrides, and persistence tables can be
  restart-persisted with `proxy.load_balance.runtime_state_file`, but mutated
  backend sets, passive health, retry budgets, queue counters, and
  managed-cookie signing keys are not cluster-synced.
- UDP, GSLB/DNS steering, WAF, VPN/firewall appliance behavior, and scripted
  iRules/Lua/Wasm behavior are intentionally separate roadmap lines.
- `proxy.load_balance.queue` is opt-in. Defaults keep fail-fast behavior when
  no backend is selectable.
