# Fluxheim 1.5.9 Release Notes

Fluxheim 1.5.9 starts the restart-persistent load-balancer state line.

## Planned Scope

- Versioned local state files for selected runtime load-balancer member
  overrides.
- Size-limited, bounded persistence table snapshots for local affinity state.
- Atomic writes with safe filesystem handling and auditable load/save events.
- Fail-closed recovery semantics: corrupt, oversized, or incompatible state is
  ignored and rebuilt instead of poisoning a runtime pool.

## Added

- A versioned load-balancer runtime state snapshot API for runtime member
  overrides and local persistence tables.
- Restore validation for snapshot version, entry limits, duplicate keys,
  persistent runtime states, runtime weights, persistence key sizes, TTLs, and
  live backend membership before current runtime state is replaced.
- Optional `proxy.load_balance.runtime_state_file` local restart persistence.
  Fluxheim loads the file best-effort at pool construction and writes it
  atomically after runtime member-state, runtime weight, persistence-table, and
  persistence-clear changes.

## Stop Line

This release does not add cross-node state sync, runtime add/remove-member,
dynamic discovery control planes, UDP/GSLB, WAF, VPN/firewall features, or
Wasm/iRules/Lua scripting.
