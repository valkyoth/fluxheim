# Fluxheim 1.5.10 Release Notes

Fluxheim 1.5.10 starts the runtime backend-set mutation line.

## Planned Scope

- Authenticated add, remove, and update operations for configured
  load-balancer pool members.
- Atomic backend-set swaps so runtime pool changes publish as one coherent
  backend/readiness snapshot.
- Validation, audit events, status and metrics visibility, drain behavior, and
  clear selector limitations for hash, ring, Maglev, and power-of-two policies.

## Added

- Authenticated admin endpoints for static load-balancer pools:
  `POST /_fluxheim/load-balancer/member-add`,
  `POST /_fluxheim/load-balancer/member-remove`, and
  `POST /_fluxheim/load-balancer/member-update`.
- Fluxheim-owned runtime backend-set mutation primitives that publish backend
  and readiness state together as one atomic snapshot.
- Conservative removal behavior: members with active in-flight requests must be
  drained before they can be removed or retargeted to a new address.
- Explicit selector/discovery limits: runtime backend-set mutation is rejected
  for DNS/file-discovery pools and for Maglev selectors in this release.

## Notes

Backend-set additions, removals, and configured-weight updates are in-memory
control-plane actions and return `"persistent": false`. The local
`proxy.load_balance.runtime_state_file` currently persists runtime member-state
overrides, runtime weight overrides, and local persistence tables, not mutated
backend membership.

## Stop Line

This release does not add xDS/Kubernetes/Consul discovery, UDP/GSLB,
WAF, VPN/firewall appliance behavior, or Wasm/iRules/Lua scripting.
