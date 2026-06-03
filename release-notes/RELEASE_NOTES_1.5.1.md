# Fluxheim 1.5.1 Release Notes

Fluxheim 1.5.1 is an enterprise load-balancer stabilization release. It keeps
the 1.5.0 feature surface intact and focuses on metrics clarity, dynamic-pool
cleanup, persistence-table correctness, release smoke coverage, and operator
documentation.

## Changed

- Load-balancer persistence-clear metrics now use dedicated bounded events:
  `persistence_clear`, `persistence_clear_invalid`, and
  `persistence_clear_not_found`. They no longer share member-state mutation
  labels.
- Dynamic DNS/file discovery pools now prune stale runtime member-state
  overrides when removed backends disappear from the live pool.
- Local persistence tables now prune entries pinned to removed dynamic-discovery
  backends before runtime status and least-sessions counts are computed.
- README and configuration documentation now describe the current 1.5.x
  load-balancer boundaries instead of tying the local persistence/runtime
  override limits only to 1.5.0.

## Test Coverage

- Admin tests cover invalid and not-found load-balancer persistence-clear
  metrics separately from member-state metrics.
- The local load-balancer smoke now exercises route-scoped header persistence,
  authenticated persistence-table clear, and the `persistence_clear` metrics
  event.

## Boundaries

The 1.5.1 release does not add new large control-plane surfaces. These remain
future 1.5.x or later roadmap items:

- managed load-balancer affinity cookie insertion;
- restart-persistent load-balancer runtime state;
- runtime upstream weight mutation;
- runtime add/remove-member operations;
- active-active cross-node load-balancer state synchronization;
- UDP, GSLB/DNS load balancing, WAF, VPN/firewall appliance behavior, and
  iRules/Lua/Wasm scripting.

## Upgrade Notes

- Existing 1.5.0 load-balancer configuration remains compatible.
- Operators using load-balancer metrics should update dashboards if they were
  grouping persistence clear operations together with member-state mutation
  events.
