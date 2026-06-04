# Fluxheim 1.5.2 Release Notes

Fluxheim 1.5.2 is the runtime load-balancer weight-control release. It starts
from the stabilized 1.5.1 load-balancer surface and focuses on authenticated
runtime weight overrides for already configured members.

## Changed

- Add `POST /_fluxheim/load-balancer/member-weight` for authenticated runtime
  weight overrides on already configured members.
- Runtime weights are supported for `round-robin`, `least-connections`,
  `least-sessions`, and `least-time` pools.
- Use `weight=default`, `reset`, `clear`, or `configured` to remove the runtime
  override and return to the configured upstream weight.
- Load-balancer backend status now reports configured `weight`,
  `effective_weight`, `runtime_weight_override`, and
  `runtime_weight_changed_at_unix_secs`.
- Runtime member-weight operations emit bounded audit/metrics events:
  `member_weight`, `member_weight_invalid`, and `member_weight_not_found`.

## Test Coverage

- Unit tests cover runtime weight selection behavior, unsupported hash-selector
  rejection, runtime status fields, stale dynamic-backend cleanup, and the
  authenticated admin endpoint.

## Boundaries

The 1.5.2 release should not add managed affinity-cookie insertion,
restart-persistent load-balancer state, cross-node state synchronization,
runtime add/remove-member operations, UDP/GSLB, WAF, VPN/firewall appliance
behavior, or iRules/Lua/Wasm scripting.
