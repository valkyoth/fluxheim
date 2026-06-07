# Fluxheim 1.5.10 Release Notes

Fluxheim 1.5.10 starts the runtime backend-set mutation line.

## Planned Scope

- Authenticated add, remove, and update operations for configured
  load-balancer pool members.
- Atomic backend-set swaps so runtime pool changes publish as one coherent
  backend/readiness snapshot.
- Validation, audit events, status and metrics visibility, drain behavior, and
  clear selector limitations for hash, ring, Maglev, and power-of-two policies.

## Stop Line

This release does not add xDS/Kubernetes/Consul discovery, UDP/GSLB,
WAF, VPN/firewall appliance behavior, or Wasm/iRules/Lua scripting.
