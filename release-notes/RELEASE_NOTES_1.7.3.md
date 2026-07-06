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
  class plus bounded `x-canary: 1` and `x-mirror: 1` signals for the first
  configured-branch routing examples.
- Add configured-route branch selection for the `canary` and `mirror` branches.
  Fluxheim accepts the decision only when a configured route with that name also
  matches the current request method and path.
- Add live listener tests with two local origins proving a Wasm route decision
  can move a request from the standard route to the configured canary route.
- Add live native load-balancer route coverage proving a Wasm-selected route
  still delegates backend choice to the configured Fluxheim load-balancer
  policy.
- Add live managed-cookie persistence coverage proving a Wasm-selected
  load-balanced route still pins the backend through Fluxheim's configured
  persistence policy.
- Add live traffic-mirror listener coverage proving a Wasm route decision can
  select an already configured `mirror` route without giving plugins dynamic
  shadow-target access.
- Add fail-closed coverage for a plugin that selects an unavailable branch.

## Security Notes

- `route-decision` hooks cannot create destinations or bypass route matchers.
  A selected branch must map to an existing configured route with a matching
  method and path.
- Built-in vhost ACLs, vhost rate limits, and vhost concurrency limits run
  before `route-decision` execution, so denied or shaped clients cannot spend
  the process-wide Wasm admission budget first.
- Built-in preselected/decoded route ACLs run before `route-decision`
  execution, while selected-route ACLs and route-specific rate/concurrency
  limits run after the final route decision. A plugin-selected route cannot
  bypass its own configured route policy.
- Selected-route body limits, redirect policy, and request/response header
  policy still apply after the Wasm decision selects a route.
- If a plugin selects an unavailable branch, Fluxheim returns `503` rather than
  falling back silently.
- Wasm module compilation now waits for a bounded compile slot with a condition
  variable inside the configured compile timeout instead of polling in 1 ms
  sleeps under startup/reload contention.
- The `wasm` feature remains optional and is still rejected with
  `privacy-mode`.

## Operator Notes

- Plugins that use `route-decision` export
  `fluxheim_route_decision() -> i32`.
- The initial preview return values are:
  - `0`: continue with normal route selection;
  - `1`: select the configured matching route named `canary`;
  - `2`: deny with `403`;
  - `3`: select the configured matching route named `mirror`.
- Direct backend pool/member choice, plugin-provided persistence-key choice,
  and dynamic mirror/shadow target decisions remain staged for later `1.7.x`
  slices.
- Refresh dependency pins for `aws-lc-rs`, `bytes`, `maxminddb`, `zeroize`,
  `getrandom`, `arc-swap`, and `env_logger`; `base64-ng`, `sanitization`,
  cargo security tools, smoke images, and GitHub Actions pins were checked and
  already current.
