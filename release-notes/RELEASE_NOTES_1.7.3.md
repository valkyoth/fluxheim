# Fluxheim 1.7.3 Release Notes

Fluxheim 1.7.3 starts the HAProxy-Lua/SPOE-style routing-policy part of the
optional WebAssembly extensibility line. The first live `route-decision` hook is
intentionally constrained: plugins can continue, deny, or select a symbolic
configured route branch, but they cannot invent upstream addresses, bypass
route matching, or override built-in Fluxheim access policy.

## Highlights

- Add live native HTTP/1 `route-decision` Wasm hook execution for vhost and
  route attachments.
- Add a bounded `fluxheim_route_decision() -> i32` preview ABI under the
  existing `fluxheim_policy_v1` host-call namespace.
- Add symbolic request context for route decisions, including the existing path
  class and a bounded `x-canary: 1` signal for the first canary routing example.
- Add configured-route branch selection for the `canary` branch. Fluxheim
  accepts the decision only when a configured route named `canary` also matches
  the current request method and path.
- Add live listener tests with two local origins proving a Wasm route decision
  can move a request from the standard route to the configured canary route.
- Add fail-closed coverage for a plugin that selects an unavailable branch.

## Security Notes

- `route-decision` hooks cannot create destinations or bypass route matchers.
  A selected branch must map to an existing configured route with a matching
  method and path.
- Built-in vhost and route ACLs, rate limits, concurrency limits, body limits,
  redirect policy, and request/response header policy still apply after the
  Wasm decision selects a route.
- If a plugin selects an unavailable branch, Fluxheim returns `503` rather than
  falling back silently.
- The `wasm` feature remains optional and is still rejected with
  `privacy-mode`.

## Operator Notes

- Plugins that use `route-decision` export
  `fluxheim_route_decision() -> i32`.
- The initial preview return values are:
  - `0`: continue with normal route selection;
  - `1`: select the configured matching route named `canary`;
  - `2`: deny with `403`.
- Broader pool choice, persistence-key choice, and mirror/shadow decisions
  remain staged for later `1.7.x` slices.
