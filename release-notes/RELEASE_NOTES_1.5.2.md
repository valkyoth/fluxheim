# Fluxheim 1.5.2 Release Notes

Fluxheim 1.5.2 is the runtime load-balancer weight-control release. It starts
from the stabilized 1.5.1 load-balancer surface and focuses on authenticated
runtime weight overrides for already configured members.

## Planned Scope

- Runtime weight overrides for configured load-balancer members.
- Status, metrics, and audit visibility for runtime weight changes.
- Migration documentation for canary and traffic-shift workflows.
- Focused load-balancer smoke coverage for runtime weight mutation.

## Boundaries

The 1.5.2 release should not add managed affinity-cookie insertion,
restart-persistent load-balancer state, cross-node state synchronization,
runtime add/remove-member operations, UDP/GSLB, WAF, VPN/firewall appliance
behavior, or iRules/Lua/Wasm scripting.
