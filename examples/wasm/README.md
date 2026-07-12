## Fluxheim Wasm Examples

These examples are source-level policy examples. Build the `.wat` files to
`.wasm`, place the compiled module under one of the configured
`wasm.plugin_roots`, and pin the module SHA-256 in config before enabling it in
production.

`irules-access-policy.wat` and `irules-access-policy.toml` demonstrate the
F5 iRules-style access-policy mapping. Fluxheim first classifies the request
through configured vhosts, routes, methods, trusted-client ACLs, and TLS
policy. The example plugin is attached only to the bounded `admin` route and
returns the typed deny decision, producing a small fixed 403 response before
origin dispatch. Requests outside that attachment continue normally. A trap,
timeout, invalid result, or admission failure follows `fail_mode =
"fail-closed"` and cannot silently bypass the policy.

This is capability parity, not Tcl syntax compatibility. The access-decision
module receives no raw headers, body, filesystem, network, admin-token, or TLS
secret capability. Use native route and access configuration for classification
instead of attempting arbitrary parsing inside the plugin.

`openresty-header-policy.wat` and `openresty-header-policy.toml` demonstrate
the nginx Lua/OpenResty-style header-policy mapping. On the configured `/gold/`
route, the module reads only Fluxheim's bounded path-class ID, adds the
allow-listed `x-policy-tier: gold` request header, removes the allow-listed
upstream `x-powered-by` response header, and adds
`x-fluxheim-policy-branch: gold` to the client response.

The guest cannot read raw `Authorization`, `Cookie`, or `Set-Cookie` values and
cannot create arbitrary names or values. Unknown IDs, duplicate/oversized
mutations, traps, timeouts, and admission failures follow the configured fail
mode; security-sensitive examples use `fail-closed`.

`haproxy-spoe-routing-policy.wat` and
`haproxy-spoe-routing-policy.toml` demonstrate the HAProxy Lua/SPOE-style
routing mapping. The guest receives only bounded `x-canary: 1` and
`x-mirror: 1` signals. It may continue normal selection or choose an existing
matching route named `canary` or `mirror`; it cannot name an arbitrary pool,
backend, URL, persistence key, or TLS policy.

The selected route still passes its own ACL, rate-limit, concurrency,
load-balancer, health, persistence, retry, and traffic-mirror controls. If the
symbolic branch is not configured and still valid for the request, selection
fails closed instead of falling back to an attacker-chosen destination.

`cache-lookup-policy.wat` and `cache-store-policy.wat` demonstrate the bounded
1.7.5 cache-policy ABI:

- split cache keys by Fluxheim's symbolic mobile/desktop device class;
- apply a bounded short TTL;
- add the fixed `wasm-policy` cache tag;
- add the fixed stored response header `x-fluxheim-cache-policy: wasm`.
- apply those store mutations only when Fluxheim reports the response
  content-type as the symbolic image class.

The example intentionally uses separate modules for lookup and store phases
because Fluxheim links only the host calls valid for the current phase. It also
uses fixed Fluxheim host-call IDs. Plugins cannot emit arbitrary cache-key
bytes, TTLs, tags, response headers, upstream targets, or filesystem paths
through this ABI.

Together, these files are the VCL-like cache-policy migration example. The
live example smoke proves cache pass versus MISS/HIT behavior, bounded
mobile/desktop key variants, image-only TTL/tag/header mutation, expiry,
non-image isolation, tag-based purge through normal Fluxheim tooling, and
fail-closed rejection of unknown or duplicate mutation IDs. Fluxheim does not
embed VCL and the guest never receives raw cache objects.

`wasi-random-policy.wat` and `wasi-random-policy.toml` demonstrate the opt-in
`1.7.8` WASI Preview 1 boundary. The module imports only `random_get`, and the
config grants only randomness. Clocks require their own explicit grant.
Environment, arguments, inherited stdio, filesystem, sockets/network, and
process-exit imports remain unavailable and are rejected before instantiation.
