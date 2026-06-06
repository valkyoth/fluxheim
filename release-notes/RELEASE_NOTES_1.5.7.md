# Fluxheim 1.5.7 Release Notes

Fluxheim 1.5.7 starts the Fluxheim-native load-balancer core line. The goal is
to replace `pingora-load-balancing` as Fluxheim's load-balancer substrate while
preserving the current proxy/load-balancer configuration, admin API, status
shape, metrics, privacy-mode behavior, managed-cookie behavior, and selection
results as far as possible.

## Changed

- Add a Fluxheim-owned backend/backend-set model for load-balancer upstream
  construction.
- Route static upstream pools, file-refreshed upstream discovery, and
  DNS-refreshed upstream discovery through the Fluxheim backend model before
  adapting to the remaining Pingora selector boundary.
- Move backend keying, passive health, slow start, connection counters,
  latency scoring, and backend policy evaluation onto a Fluxheim-owned backend
  identity abstraction.
- Build Maglev lookup tables from Fluxheim backend identities so Maglev
  construction no longer depends on Pingora's concrete backend type.
- Move file-refreshed and DNS-refreshed backend discovery behind a
  Fluxheim-owned discovery trait, with Pingora service discovery retained only
  as an adapter.
- Route runtime backend stats, bounded-load weight accounting, and disabled
  upstream parsing through the Fluxheim backend identity/adapter layer.
- Move slow-start state regression coverage onto Fluxheim backend identities,
  keeping Pingora backend construction only in runtime-selection tests.
- Replace Pingora's FNV weighted-hash selector for source, URI, header, and
  cookie hash modes with Fluxheim-owned weighted-first FNV selection over the
  current backend container.
- Replace Pingora's random selector dependency for power-of-two choices with a
  Fluxheim-owned weighted random first pick and unique backend fallback scan.
- Replace Pingora's consistent-hash selector dependency with Fluxheim-owned
  rendezvous candidate ordering for consistent and bounded-load consistent
  hash modes. Dynamic file/DNS discovery remains supported through the current
  backend container.
- Collapse load-balancer factory, stats, and priority-check helpers onto a
  concrete readiness container now that Fluxheim owns all shipped selection
  algorithms.
- Centralize the remaining Pingora backend container operations behind
  Fluxheim-owned adapter helpers so readiness checks, backend enumeration, and
  health-check metadata have one migration boundary.
- Route static upstream pools through the same Fluxheim-owned discovery
  adapter as file-refreshed and DNS-refreshed pools, removing Pingora's static
  discovery wrapper from load-balancer construction.
- Replace Pingora's generic `GenBackgroundService` wrapper for load-balancer
  pools with a Fluxheim-owned `ServiceWithDependents` implementation while
  preserving the current update and health-check loop.
- Introduce a Fluxheim backend-container trait so selector and runtime-stat
  code depend on Fluxheim's backend/readiness interface instead of the concrete
  Pingora container type.
- Centralize the remaining concrete Pingora load-balancer container type behind
  the backend adapter module, keeping orchestration and discovery on Fluxheim's
  adapter alias while the native substrate is phased in.
- Wrap the current Pingora load-balancer container in a Fluxheim runtime type
  before handing pools to selection, status, and background-service code.
- Return Fluxheim runtime-wrapped load-balancer pools from discovery so
  selection-mode construction no longer repeats Pingora container wrapping.
- Keep the selector-facing backend-container trait implemented only by the
  Fluxheim runtime wrapper, with raw Pingora container access confined inside
  that adapter.
- Preserve existing Pingora readiness and health-check adapters while the
  native backend set, selector boundary, and service wrapper are introduced,
  keeping this first 1.5.7 line behavior-preserving.

## Boundaries

1.5.7 is the load-balancer substrate replacement line. It may replace backend
types, backend readiness storage, discovery adapters, health-check scheduling,
background update lifecycle, and remaining load-balancer factory errors with
Fluxheim-owned equivalents.

1.5.7 does not add restart-persistent load-balancer state, active-active
cross-node state sync, runtime add/remove-member, xDS/Kubernetes/Consul
discovery, UDP/GSLB, WAF, VPN/firewall appliance behavior, HTTP/3/QUIC, or
Wasm/iRules/Lua scripting.
