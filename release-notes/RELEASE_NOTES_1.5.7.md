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
- Preserve existing Pingora selector/background-service adapters while the
  native backend set and identity boundary are introduced, keeping this first
  1.5.7 slice behavior-preserving.

## Boundaries

1.5.7 is the load-balancer substrate replacement line. It may replace backend
types, backend readiness storage, discovery adapters, health-check scheduling,
background update lifecycle, and remaining load-balancer factory errors with
Fluxheim-owned equivalents.

1.5.7 does not add restart-persistent load-balancer state, active-active
cross-node state sync, runtime add/remove-member, xDS/Kubernetes/Consul
discovery, UDP/GSLB, WAF, VPN/firewall appliance behavior, HTTP/3/QUIC, or
Wasm/iRules/Lua scripting.
