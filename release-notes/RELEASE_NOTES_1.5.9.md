# Fluxheim 1.5.9 Release Notes

Fluxheim 1.5.9 starts the restart-persistent load-balancer state line.

## Planned Scope

- Versioned local state files for selected runtime load-balancer member
  overrides.
- Size-limited, bounded persistence table snapshots for local affinity state.
- Atomic writes with safe filesystem handling and auditable load/save events.
- Fail-closed recovery semantics: corrupt, oversized, or incompatible state is
  ignored and rebuilt instead of poisoning a runtime pool.

## Stop Line

This release does not add cross-node state sync, runtime add/remove-member,
dynamic discovery control planes, UDP/GSLB, WAF, VPN/firewall features, or
Wasm/iRules/Lua scripting.
