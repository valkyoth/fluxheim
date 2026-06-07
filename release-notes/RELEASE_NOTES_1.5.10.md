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
- Privacy-mode mutation responses, logs, and metrics avoid raw backend member
  addresses; they use configured aliases when available and `redacted` for
  response/log member fields otherwise.
- Explicit remove and address-retarget operations clear stale per-backend
  runtime overrides and passive-health state for the old backend key.
- Retargeted backend addresses start with fresh readiness state rather than
  inheriting health-check state from the previous address.
- Runtime backend-set mutations enforce the "at least one backend remains"
  invariant under the mutation lock, cap runtime backend sets at 256 members,
  save runtime state through the background save path, and warn if a narrow
  post-check race leaves a request completing against a removed or retargeted
  address.

## Notes

Backend-set additions, removals, and configured-weight updates are in-memory
control-plane actions and return `"persistent": false`. The local
`proxy.load_balance.runtime_state_file` currently persists runtime member-state
overrides, runtime weight overrides, and local persistence tables, not mutated
backend membership.

Runtime-added or retargeted members carry address and configured weight only.
Aliases, tags, backup membership, priority groups, locality metadata, and
per-upstream caps remain static-config fields and need a reload.

Mutation response `member` fields use the resolved backend address consistently;
configured aliases remain available through the separate `alias` field when
present.

## Stop Line

This release does not add xDS/Kubernetes/Consul discovery, UDP/GSLB,
WAF, VPN/firewall appliance behavior, or Wasm/iRules/Lua scripting.
