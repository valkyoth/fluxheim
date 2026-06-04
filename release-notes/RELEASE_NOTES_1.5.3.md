# Fluxheim 1.5.3 Release Notes

Fluxheim 1.5.3 is the managed affinity-cookie load-balancer release. It starts
from the stabilized 1.5.2 runtime weight-control surface and adds a
Fluxheim-owned sticky-cookie option for HTTP load-balanced routes.

## Changed

- Add `proxy.load_balance.persistence.mode = "managed-cookie"`.
- Managed-cookie mode emits a signed/opaque `Set-Cookie` value on eligible
  2xx/3xx backend responses and validates that cookie on later requests.
- Managed cookie values map to the existing bounded local persistence table and
  do not expose backend addresses, aliases, or weights to clients.
- Rotate local managed-cookie signing keys daily and verify cookies against the
  current or previous key generation.
- Add configurable managed-cookie attributes:
  `managed_cookie_domain`, `managed_cookie_path`, `managed_cookie_secure`,
  `managed_cookie_http_only`, `managed_cookie_same_site`, and
  `managed_cookie_max_age_secs`.
- Keep load-balancer persistence rejected in `privacy-mode` builds.
- Number the remaining `1.5.x` roadmap through restart-persistent state,
  runtime backend-set mutation, service discovery/control-plane integration,
  and scoped UDP/GSLB exploration.

## Boundaries

Managed-cookie state and signing keys remain process-local in 1.5.3.
Restart-persistent persistence state is planned for 1.5.4, runtime backend-set
mutation for 1.5.5, service discovery/control-plane integration for 1.5.6, and
UDP/GSLB exploration for 1.5.7.

1.5.3 does not add cross-node cookie mirroring, active-active state sync,
runtime add/remove-member, WAF, VPN/firewall appliance behavior, or Wasm/iRules
scripting.
